# State Guard

Lightweight Windows and Linux endpoint audits, configuration drift detection,
and guarded remediation, with a CLI and desktop interface. Python 3.10+ only;
no third-party Python dependencies, background agent, server, or network calls.

**Early prototype:** native security checks are read-only. Remediation currently
covers explicitly selected JSON application settings, not operating system settings.

## Run it

Download this repository and open a terminal in its directory.

| Task | Windows | Linux |
| --- | --- | --- |
| Desktop interface | `py state_guard_gui.py` | `python3 state_guard_gui.py` |
| Endpoint audit | `py state_guard.py` | `python3 state_guard.py` |
| Help | `py state_guard.py --help` | `python3 state_guard.py --help` |

The desktop interface uses Tkinter, included in standard Windows Python installers.
Linux may require the distribution's `python3-tk` package and a graphical desktop.
The CLI does not require Tkinter. Start without administrator/root privileges.
Unavailable collectors report UNKNOWN, never a successful check.

Windows checks firewall profiles and Defender real-time protection. Linux checks
full address space randomization (ASLR) and kernel pointer restrictions. These are
limited indicators, not a complete security assessment. Defender may be unavailable
on endpoints using another protection product.

## Try drift detection and remediation

Use a copy of the demonstration config:

```powershell
Copy-Item examples/config.json demo-config.json
py state_guard.py audit --policy examples/policy.json --config demo-config.json
py state_guard.py remediate --policy examples/policy.json --config demo-config.json
py state_guard.py remediate --policy examples/policy.json --config demo-config.json --apply
```

On Linux use `cp examples/config.json demo-config.json` and replace `py` with
`python3`. In the desktop interface, select the policy and config, choose
**Check drift**, then **Preview**, and finally **Apply…** after reviewing the policy.

A policy specifies exact top-level JSON values and types:

```json
{"version": 1, "settings": {"debug": false, "require_authentication": true}}
```

Choose settings your application recognizes. The example keys do not configure
Windows or Linux. Unlisted keys stay intact; writing normalizes JSON formatting.
Reports show key names and statuses without disclosing configuration values.

Remediation previews by default. Applying creates an exclusive
`<config>.state-guard.bak` recovery copy, refuses existing backups and linked files,
checks for intervening changes, and verifies the resulting settings. When there is
no drift, it writes nothing.

Stop the application that owns the config before applying. There is no transactional
locking or crash-atomic write guarantee: concurrent writers or interrupted writes
can still damage a file. Recovery copies may contain secrets; keep the config
directory private. Windows backups inherit directory access controls; Linux backups
use mode 0600. To recover, stop the owning application and copy the backup over the
config. Review and remove the backup before a later remediation. This prototype is
not ready for unattended or production remediation.

## Distinct from Lynis

[Lynis](https://cisofy.com/products/) provides broad Unix, macOS, and Linux security
auditing. State Guard focuses on a small Windows/Linux workflow: endpoint indicators,
explicit desired-state policies for application settings, visible drift, and a desktop
interface with preview and recovery copies. It complements a comprehensive auditor
such as Lynis; it does not match its coverage.

## Automation and verification

Add `--json` for machine-readable output. Exit codes: **0** all checks pass,
**1** drift detected (including preview), **2** error or unknown results.

```powershell
python -m unittest discover -s tests -v
```

The included CI workflow targets Windows and Linux with Python 3.10 and 3.13.
Native collectors and desktop interactions still need acceptance testing on
representative endpoints. Tests do not establish that an endpoint is secure.
