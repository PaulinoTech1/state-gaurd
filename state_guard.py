"""Small, read-only endpoint audit and explicit JSON configuration drift checker."""
import argparse
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


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
    policy = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(policy, dict) or set(policy) != {"version", "settings"} or policy["version"] != 1:
        raise ValueError("policy must contain version: 1 and settings")
    settings = policy["settings"]
    if not isinstance(settings, dict) or not settings or any(not isinstance(k, str) or not k for k in settings):
        raise ValueError("settings must be a nonempty object with nonempty keys")
    if any(type(v) not in (str, int, bool) for v in settings.values()):
        raise ValueError("expected settings must be strings, integers, or booleans")
    return settings


def inspect_config(path, settings):
    target = Path(path)
    if target.is_symlink() or not target.is_file() or target.stat().st_nlink != 1:
        raise ValueError("config must be an existing regular file without symbolic or hard links")
    raw = target.read_bytes()
    config = json.loads(raw)
    if not isinstance(config, dict):
        raise ValueError("config must be a JSON object")
    checks = []
    for key, desired in settings.items():
        matches = key in config and type(config[key]) is type(desired) and config[key] == desired
        checks.append({"check": key, "status": "pass" if matches else "drift"})
    return raw, config, checks


def remediate(path, settings, apply=False):
    raw, config, checks = inspect_config(path, settings)
    if not apply or all(c["status"] == "pass" for c in checks):
        return checks
    target = Path(path)
    backup = target.with_name(target.name + ".state-guard.bak")
    # Exclusive creation prevents overwriting a previous recovery copy.
    with backup.open("xb") as handle:
        if os.name != "nt":
            os.chmod(backup, 0o600)
        handle.write(raw)
    # Refuse changes detected since collection. This is not a transactional lock.
    if target.is_symlink() or target.stat().st_nlink != 1 or target.read_bytes() != raw:
        raise ValueError("config changed during preparation; no changes applied")
    config.update(settings)
    updated = (json.dumps(config, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    with target.open("r+b") as handle:
        if handle.read() != raw:
            raise ValueError("config changed before write; no changes applied")
        handle.seek(0)
        handle.write(updated)
        handle.truncate()
        handle.flush()
        os.fsync(handle.fileno())
    _, _, verified = inspect_config(path, settings)
    if any(c["status"] != "pass" for c in verified):
        raise ValueError("verification failed; inspect config and recovery copy")
    return verified


def main(argv=None):
    parser = argparse.ArgumentParser(description="State Guard: small endpoint audits and explicit configuration drift checks.")
    parser.add_argument("action", nargs="?", default="audit", choices=["audit", "remediate"])
    parser.add_argument("--policy", help="version 1 JSON desired-state policy")
    parser.add_argument("--config", help="JSON application configuration to compare")
    parser.add_argument("--apply", action="store_true", help="apply policy to config after creating a recovery copy")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    if bool(args.policy) != bool(args.config):
        parser.error("--policy and --config must be supplied together")
    if args.apply and args.action != "remediate":
        parser.error("--apply requires remediate")
    if args.action == "remediate" and not args.policy:
        parser.error("remediate requires --policy and --config")
    try:
        if args.policy:
            settings = load_policy(args.policy)
            checks = remediate(args.config, settings, args.apply) if args.action == "remediate" else inspect_config(args.config, settings)[2]
        else:
            checks = endpoint_checks()
        report = {"platform": platform.system(), "mode": "apply" if args.apply else "preview" if args.action == "remediate" else "audit", "checks": checks}
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print("State Guard | " + report["platform"] + " | " + report["mode"])
            for check in checks:
                print(f"{check['status'].upper():7} {check['check']}" + (" — " + check["detail"] if "detail" in check else ""))
            if args.action == "remediate" and not args.apply:
                print("Preview only. Review the policy, then use --apply to change the config.")
        return 2 if any(c["status"] == "unknown" for c in checks) else 1 if any(c["status"] == "drift" for c in checks) else 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}))
        else:
            print("State Guard error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
