"""Small, read-only endpoint audit and explicit JSON configuration drift checker."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
from state_guard_json import decode, render
from state_guard_storage import (
    atomic_update, bounded_read, create_private, local_path, open_regular,
    operation_lock, snapshot, sync_directory,
)

__version__ = "0.2.0"


def format_check(check):
    label = json.dumps(check["check"], ensure_ascii=False)
    text = f"{check['status'].upper():7} {label}"
    if "expected_type" in check and check["expected_type"] != check["observed_type"]:
        text += f" (expected {check['expected_type']}; observed {check['observed_type']})"
    if "detail" in check:
        text += " — " + check["detail"]
    return text


def command(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise ValueError("collector failed; check permissions and command availability")
    return result.stdout.strip()


def endpoint_checks():
    system = platform.system()
    checks = []
    if system == "Windows":
        collectors = [
            ("Firewall profiles enabled", "@(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) | ConvertTo-Json -Compress", lambda x: bool(x) and all(x if isinstance(x, list) else [x])),
            ("Defender real-time protection", "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled | ConvertTo-Json -Compress", lambda x: x is True),
        ]
        for name, script, passes in collectors:
            try:
                value = json.loads(command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; " + script]))
                checks.append({"check": name, "status": "pass" if passes(value) else "drift", "observed": value})
            except (OSError, ValueError, subprocess.TimeoutExpired):
                checks.append({"check": name, "status": "unknown", "detail": "Unable to collect; check permissions or installed components."})
    elif system == "Linux":
        for name, path, expected in [
            ("ASLR fully enabled", "/proc/sys/kernel/randomize_va_space", "2"),
            ("Kernel pointer addresses restricted", "/proc/sys/kernel/kptr_restrict", ("1", "2")),
        ]:
            try:
                value = Path(path).read_text().strip()
                passed = value in expected if isinstance(expected, tuple) else value == expected
                checks.append({"check": name, "status": "pass" if passed else "drift", "observed": value})
            except OSError:
                checks.append({"check": name, "status": "unknown", "detail": "Unable to read kernel setting."})
    else:
        checks.append({"check": "Supported platform", "status": "unknown", "detail": "Use Windows or Linux."})
    return checks


def load_policy(path):
    with open_regular(path) as handle:
        policy = decode(bounded_read(handle))
    if not isinstance(policy, dict) or set(policy) != {"version", "settings"} or type(policy["version"]) is not int or policy["version"] != 1:
        raise ValueError("policy must contain version: 1 and settings")
    settings = policy["settings"]
    if not isinstance(settings, dict) or not settings or any(not isinstance(k, str) or not k for k in settings):
        raise ValueError("settings must be a nonempty object with nonempty keys")
    if any(type(v) not in (str, int, bool) for v in settings.values()):
        raise ValueError("expected settings must be strings, integers, or booleans")
    return settings


def inspect_config(path, settings):
    with open_regular(path) as handle:
        raw = bounded_read(handle)
    config = decode(raw)
    if not isinstance(config, dict):
        raise ValueError("config must be a JSON object")
    checks = []
    for key, desired in settings.items():
        matches = key in config and type(config[key]) is type(desired) and config[key] == desired
        checks.append({"check": key, "status": "pass" if matches else "drift", "expected_type": type(desired).__name__, "observed_type": type(config[key]).__name__ if key in config else "missing"})
    return raw, config, checks


def recovery_paths(target):
    return (target.with_name(target.name + ".state-guard.bak"),
            target.with_name(target.name + ".state-guard.recovery.json"))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def remediate(path, settings, apply=False, allow_reformat=False):
    raw, config, checks = inspect_config(path, settings)
    if all(c["status"] == "pass" for c in checks):
        return checks
    render(raw, config, settings, allow_reformat)  # validate preview before any side effects
    if not apply:
        return checks
    with operation_lock(path) as target, snapshot(target) as (raw, info):
        config = decode(raw)
        if not isinstance(config, dict):
            raise ValueError("config must be a JSON object")
        updated = render(raw, config, settings, allow_reformat)
        if updated == raw:
            return inspect_config(path, settings)[2]
        backup, manifest = recovery_paths(target)
        if manifest.exists() or manifest.is_symlink():
            raise FileExistsError("Recovery manifest already exists; review previous recovery files")
        create_private(backup, raw)
        with open_regular(backup, private=True) as handle:
            if bounded_read(handle) != raw:
                raise ValueError("Recovery copy verification failed; replacement refused")
        metadata = {"version": 1, "original_sha256": digest(raw), "applied_sha256": digest(updated)}
        create_private(manifest, json.dumps(metadata).encode("utf-8"))
        sync_directory(target.parent)
        atomic_update(target, raw, updated, info)
        _, _, verified = inspect_config(path, settings)
        if any(c["status"] != "pass" for c in verified):
            raise ValueError("verification failed; inspect config and recovery copy")
        return verified


def rollback(path, apply=False):
    """Restore exact bytes only when current content matches the recorded state."""
    target = local_path(path).resolve(strict=True)
    def prepare(raw):
        backup, manifest = recovery_paths(target)
        with open_regular(backup, private=True) as handle:
            original = bounded_read(handle)
        with open_regular(manifest, private=True) as handle:
            metadata = decode(bounded_read(handle))
        if not isinstance(metadata, dict) or set(metadata) != {"version", "original_sha256", "applied_sha256"} or type(metadata["version"]) is not int or metadata["version"] != 1:
            raise ValueError("Invalid recovery manifest")
        if metadata["original_sha256"] != digest(original):
            raise ValueError("Recovery copy hash mismatch; rollback refused")
        if digest(raw) not in (metadata["original_sha256"], metadata["applied_sha256"]):
            raise ValueError("Config has newer or unrecognized changes; rollback refused")
        return original
    if not apply:
        with open_regular(target) as handle:
            raw = bounded_read(handle)
        original = prepare(raw)
    else:
        with operation_lock(target), snapshot(target) as (raw, info):
            original = prepare(raw)
            if original != raw:
                atomic_update(target, raw, original, info)
    return [{"check": "Recovery to original bytes", "status": "pass" if apply or original == raw else "drift"}]


def main(argv=None):
    parser = argparse.ArgumentParser(description="State Guard: small endpoint audits and explicit configuration drift checks.")
    parser.add_argument("action", nargs="?", default="audit", choices=["audit", "remediate", "rollback"])
    parser.add_argument("--version", action="version", version="State Guard " + __version__)
    parser.add_argument("--policy", help="version 1 JSON desired-state policy")
    parser.add_argument("--config", help="JSON application configuration to compare")
    parser.add_argument("--apply", action="store_true", help="apply policy to config after creating a recovery copy")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--allow-reformat", action="store_true", help="explicitly permit full JSON normalization and adding missing keys")
    args = parser.parse_args(argv)
    if args.action != "rollback" and bool(args.policy) != bool(args.config):
        parser.error("--policy and --config must be supplied together")
    if args.apply and args.action not in ("remediate", "rollback"):
        parser.error("--apply requires remediate or rollback")
    if args.action == "rollback" and (not args.config or args.policy):
        parser.error("rollback requires --config and does not accept --policy")
    if args.allow_reformat and args.action != "remediate":
        parser.error("--allow-reformat requires remediate")
    if args.action == "remediate" and not args.policy:
        parser.error("remediate requires --policy and --config")
    try:
        if args.action == "rollback":
            checks = rollback(args.config, args.apply)
        elif args.policy:
            settings = load_policy(args.policy)
            checks = remediate(args.config, settings, args.apply, args.allow_reformat) if args.action == "remediate" else inspect_config(args.config, settings)[2]
        else:
            checks = endpoint_checks()
        report = {"platform": platform.system(), "action": args.action, "version": __version__, "mode": "apply" if args.apply else "preview" if args.action in ("remediate", "rollback") else "audit", "checks": checks}
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("State Guard | " + report["platform"] + " | " + report["mode"])
            for check in checks:
                print(format_check(check))
            if args.action in ("remediate", "rollback") and not args.apply:
                print("Preview only. Review the proposed operation, then use --apply to change the config.")
        return 2 if any(c["status"] == "unknown" for c in checks) else 1 if any(c["status"] == "drift" for c in checks) else 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}))
        else:
            print("State Guard error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
