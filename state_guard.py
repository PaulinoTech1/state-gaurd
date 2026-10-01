"""Small, read-only endpoint audit and explicit JSON configuration drift checker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from typing import Any, Callable, Sequence
from state_guard_json import decode, render
from state_guard_storage import (
    atomic_update, bounded_read, create_private, local_path, open_regular,
    operation_lock, snapshot, sync_directory,
)

__version__ = "0.2.0"
Check = dict[str, Any]
Settings = dict[str, str | int | bool]
PathLike = str | os.PathLike[str]


def format_check(check: Check) -> str:
    """Format one check without exposing its observed configuration value."""
    label = json.dumps(check["check"], ensure_ascii=False)
    text = f"{check['status'].upper():7} {label}"
    if "expected_type" in check and check["expected_type"] != check["observed_type"]:
        text += f" (expected {check['expected_type']}; observed {check['observed_type']})"
    if "detail" in check:
        text += " — " + check["detail"]
    return text


def command(args: Sequence[str]) -> str:
    """Run a fixed collector command and return trimmed stdout."""
    result = subprocess.run(args, capture_output=True, text=True, timeout=20)
    if result.returncode:
        detail = (result.stderr or "").strip().replace("\n", " ")
        if len(detail) > 200:
            detail = detail[:200] + "..."
        suffix = f": {detail}" if detail else ""
        raise ValueError(f"collector failed (exit {result.returncode}); check permissions and command availability{suffix}")
    return result.stdout.strip()


def endpoint_checks() -> list[Check]:
    """Collect the small, read-only endpoint check set for this platform."""
    system = platform.system()
    checks = []
    if system == "Windows":
        collectors: list[tuple[str, str, Callable[[Any], bool]]] = [
            ("Firewall profiles enabled", "@(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) | ConvertTo-Json -Compress", lambda x: bool(x) and all(x if isinstance(x, list) else [x])),
            ("Defender real-time protection", "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled | ConvertTo-Json -Compress", lambda x: x is True),
            ("Defender tamper protection", "Get-MpComputerStatus | Select-Object -ExpandProperty IsTamperProtected | ConvertTo-Json -Compress", lambda x: x is True),
            ("Defender cloud-delivered protection", "Get-MpPreference | Select-Object -ExpandProperty MAPSReporting | ConvertTo-Json -Compress", lambda x: type(x) is int and x in (1, 2)),
        ]
        for name, script, passes in collectors:
            try:
                value = json.loads(command(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; " + script]))
                if value is None:
                    checks.append({"check": name, "status": "unknown", "detail": "Collector returned no data; check installed components."})
                else:
                    checks.append({"check": name, "status": "pass" if passes(value) else "drift", "observed": value})
            except ValueError as exc:
                checks.append({"check": name, "status": "unknown", "detail": str(exc)})
            except subprocess.TimeoutExpired:
                checks.append({"check": name, "status": "unknown", "detail": "Collector timed out after 20 seconds; retry, then check PowerShell and security-product responsiveness."})
            except OSError:
                checks.append({"check": name, "status": "unknown", "detail": "Collector could not start; check that PowerShell is installed and permitted to run."})
    elif system == "Linux":
        for name, path, expected in [
            ("ASLR fully enabled", "/proc/sys/kernel/randomize_va_space", "2"),
            ("Kernel pointer addresses restricted", "/proc/sys/kernel/kptr_restrict", ("1", "2")),
            ("Kernel messages restricted", "/proc/sys/kernel/dmesg_restrict", "1"),
        ]:
            try:
                value = Path(path).read_text().strip()
                passed = value in expected if isinstance(expected, tuple) else value == expected
                checks.append({"check": name, "status": "pass" if passed else "drift", "observed": value})
            except OSError:
                checks.append({"check": name, "status": "unknown", "detail": "Kernel setting could not be read; check procfs availability and read permissions."})
    else:
        checks.append({"check": "Supported platform", "status": "unknown", "detail": "Use Windows or Linux."})
    return checks


def load_policy(path: PathLike) -> Settings:
    """Load and validate a version 1 desired-state policy."""
    with open_regular(path) as handle:
        policy = decode(bounded_read(handle))
    if not isinstance(policy, dict) or set(policy) != {"version", "settings"} or type(policy["version"]) is not int or policy["version"] != 1:
        raise ValueError("Policy must contain exactly 'version': 1 and 'settings'; review the policy structure.")
    settings = policy["settings"]
    if not isinstance(settings, dict) or not settings or any(not isinstance(k, str) or not k for k in settings):
        raise ValueError("Policy 'settings' must be a nonempty object with nonempty string keys.")
    if any(type(v) not in (str, int, bool) for v in settings.values()):
        raise ValueError("Policy values must be strings, integers, or booleans; remove unsupported value types.")
    return settings


def inspect_config(path: PathLike, settings: Settings) -> tuple[bytes, dict[str, Any], list[Check]]:
    """Read a JSON config and compare its top-level values with a policy."""
    with open_regular(path) as handle:
        raw = bounded_read(handle)
    config = decode(raw)
    if not isinstance(config, dict):
        raise ValueError("Config must contain one top-level JSON object; arrays and scalar values are unsupported.")
    checks = []
    for key, desired in settings.items():
        matches = key in config and type(config[key]) is type(desired) and config[key] == desired
        checks.append({"check": key, "status": "pass" if matches else "drift", "expected_type": type(desired).__name__, "observed_type": type(config[key]).__name__ if key in config else "missing"})
    return raw, config, checks


def recovery_paths(target: Path) -> tuple[Path, Path]:
    """Return the recovery-copy and recovery-manifest paths for a config."""
    return (target.with_name(target.name + ".state-guard.bak"),
            target.with_name(target.name + ".state-guard.recovery.json"))


def digest(raw: bytes) -> str:
    """Return the SHA-256 digest used to bind recovery state."""
    return hashlib.sha256(raw).hexdigest()


def validate_recovery(target: Path, raw: bytes) -> bytes:
    """Validate recovery metadata against its backup and the current config."""
    backup, manifest = recovery_paths(target)
    with open_regular(backup, private=True) as handle:
        original = bounded_read(handle)
    with open_regular(manifest, private=True) as handle:
        metadata = decode(bounded_read(handle))
    if not isinstance(metadata, dict) or set(metadata) != {"version", "original_sha256", "applied_sha256"} or type(metadata["version"]) is not int or metadata["version"] != 1:
        raise ValueError("Recovery manifest is invalid; inspect it and the recovery copy before retrying.")
    if metadata["original_sha256"] != digest(original):
        raise ValueError("Recovery copy hash mismatch; operation refused. Restore only from a separately verified backup.")
    if digest(raw) not in (metadata["original_sha256"], metadata["applied_sha256"]):
        raise ValueError("Config has newer or unrecognized changes; preserve those changes and review them before continuing.")
    return original


def remediate(
    path: PathLike,
    settings: Settings,
    apply: bool = False,
    allow_reformat: bool = False,
) -> list[Check]:
    """Preview or apply policy values with verified recovery material."""
    raw, config, checks = inspect_config(path, settings)
    if all(c["status"] == "pass" for c in checks):
        return checks
    render(raw, config, settings, allow_reformat)  # validate preview before any side effects
    if not apply:
        return checks
    with operation_lock(path) as target, snapshot(target) as (raw, info):
        config = decode(raw)
        if not isinstance(config, dict):
            raise ValueError("Config must contain one top-level JSON object; arrays and scalar values are unsupported.")
        updated = render(raw, config, settings, allow_reformat)
        if updated == raw:
            return inspect_config(path, settings)[2]
        backup, manifest = recovery_paths(target)
        if manifest.exists() or manifest.is_symlink():
            raise FileExistsError("Recovery manifest already exists; inspect or archive both recovery files before applying again.")
        create_private(backup, raw)
        with open_regular(backup, private=True) as handle:
            if bounded_read(handle) != raw:
                raise ValueError("Recovery copy verification failed; leave the config unchanged and check storage health and permissions.")
        metadata = {"version": 1, "original_sha256": digest(raw), "applied_sha256": digest(updated)}
        create_private(manifest, json.dumps(metadata).encode("utf-8"))
        sync_directory(target.parent)
        atomic_update(target, raw, updated, info)
        _, _, verified = inspect_config(path, settings)
        if any(c["status"] != "pass" for c in verified):
            raise ValueError("Applied config did not match the policy; stop the owning application and inspect the config and recovery files.")
        return verified


def rollback(path: PathLike, apply: bool = False) -> list[Check]:
    """Restore exact bytes only when current content matches the recorded state."""
    target = local_path(path).resolve(strict=True)
    if not apply:
        with open_regular(target) as handle:
            raw = bounded_read(handle)
        original = validate_recovery(target, raw)
    else:
        with operation_lock(target), snapshot(target) as (raw, info):
            original = validate_recovery(target, raw)
            if original != raw:
                atomic_update(target, raw, original, info)
    return [{"check": "Recovery to original bytes", "status": "pass" if apply or original == raw else "drift"}]


def clean_recovery(path: PathLike, settings: Settings, apply: bool = False) -> list[Check]:
    """Verify and optionally remove recovery files for a policy-compliant config."""
    target = local_path(path).resolve(strict=True)

    def prepare(raw: bytes) -> None:
        """Require current policy compliance and internally consistent recovery state."""
        config = decode(raw)
        if not isinstance(config, dict):
            raise ValueError("Config must contain one top-level JSON object; arrays and scalar values are unsupported.")
        checks = []
        for key, desired in settings.items():
            matches = key in config and type(config[key]) is type(desired) and config[key] == desired
            checks.append(matches)
        if not all(checks):
            raise ValueError("Recovery cleanup requires the current config to pass policy; resolve drift before retrying.")
        validate_recovery(target, raw)

    if not apply:
        with open_regular(target) as handle:
            prepare(bounded_read(handle))
    else:
        with operation_lock(target), snapshot(target) as (raw, _):
            prepare(raw)
            backup, manifest = recovery_paths(target)
            backup.unlink()
            sync_directory(target.parent)
            manifest.unlink()
            sync_directory(target.parent)
    return [{"check": "Recovery cleanup", "status": "pass" if apply else "drift"}]


def main(argv: Sequence[str] | None = None) -> int:
    """Parse CLI arguments, run the requested action, and return an exit code."""
    parser = argparse.ArgumentParser(description="State Guard: small endpoint audits and explicit configuration drift checks.")
    parser.add_argument("action", nargs="?", default="audit", choices=["audit", "remediate", "rollback", "recover"])
    parser.add_argument("--version", action="version", version="State Guard " + __version__)
    parser.add_argument("--policy", help="version 1 JSON desired-state policy")
    parser.add_argument("--config", help="JSON application configuration to compare")
    parser.add_argument("--apply", action="store_true", help="apply policy to config after creating a recovery copy")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--allow-reformat", action="store_true", help="explicitly permit full JSON normalization and adding missing keys")
    parser.add_argument("--clean", action="store_true", help="verify and remove recovery files")
    args = parser.parse_args(argv)
    if args.action not in ("rollback", "recover") and bool(args.policy) != bool(args.config):
        parser.error("--policy and --config must be supplied together")
    if args.apply and args.action not in ("remediate", "rollback", "recover"):
        parser.error("--apply requires remediate, rollback, or recover")
    if args.action == "rollback" and (not args.config or args.policy):
        parser.error("rollback requires --config and does not accept --policy")
    if args.action == "recover" and (not args.clean or not args.policy or not args.config):
        parser.error("recover requires --clean, --policy, and --config")
    if args.clean and args.action != "recover":
        parser.error("--clean requires recover")
    if args.allow_reformat and args.action != "remediate":
        parser.error("--allow-reformat requires remediate")
    if args.action == "remediate" and not args.policy:
        parser.error("remediate requires --policy and --config")
    try:
        if args.action == "rollback":
            checks = rollback(args.config, args.apply)
        elif args.action == "recover":
            checks = clean_recovery(args.config, load_policy(args.policy), args.apply)
        elif args.policy:
            settings = load_policy(args.policy)
            checks = remediate(args.config, settings, args.apply, args.allow_reformat) if args.action == "remediate" else inspect_config(args.config, settings)[2]
        else:
            checks = endpoint_checks()
        report = {"platform": platform.system(), "action": args.action, "version": __version__, "mode": "apply" if args.apply else "preview" if args.action in ("remediate", "rollback", "recover") else "audit", "checks": checks}
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("State Guard | " + report["platform"] + " | " + report["mode"])
            for check in checks:
                print(format_check(check))
            if args.action in ("remediate", "rollback", "recover") and not args.apply:
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
