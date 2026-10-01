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
Windows or Linux. Exact types are intentional: `1`, `true`, and `"1"` differ.
Reports include type names without disclosing configuration values. Existing-key edits
preserve every byte outside changed values: whitespace, unrelated key order, number
spellings, string escapes, UTF-8 BOM and line endings. UTF-8 JSON only; duplicate keys,
nonstandard constants and files larger than 4 MiB are refused.

Missing keys require `--allow-reformat`, which explicitly permits full JSON
normalization (indentation, escaping, BOM, line endings and number spellings may
change). The GUI has the same opt-in checkbox. This flag does not enable coercion.
Reformatting is refused if a floating-point number would lose its numeric value;
the opt-in permits formatting changes, not silent precision loss.

Remediation previews by default. Applying writes private recovery files before
staging a complete replacement; the config is never truncated in place. A stable
OS lock serializes State Guard operations. POSIX additionally takes an advisory
config lock; Windows denies ordinary writers while holding the read snapshot.
Stop the owning application: uncooperative POSIX writers, external renames and
writes after replacement can still conflict. Use a trusted local directory.

Recovery files are `<config>.state-guard.bak` and
`<config>.state-guard.recovery.json`. Both are exclusively created and kept private:
POSIX mode 0600 from creation; Windows protected user/SYSTEM DACLs. Config access
controls are retained separately. An existing recovery copy or manifest blocks
another change; no-drift apply remains a no-op. The `.state-guard.lock` sidecar
stays on disk to avoid split locks; do not remove it during use.

Preview or apply exact-byte recovery:

```powershell
py state_guard.py rollback --config demo-config.json
py state_guard.py rollback --config demo-config.json --apply
```

The GUI also has **Preview rollback** and **Rollback?**. Rollback checks recovery
hashes and refuses newer/unrecognized config edits or corrupt backups. It retains
recovery files. Review and archive/remove both before a new remediation. Legacy
backups without the new private manifest require manual inspection.

Windows remediation requires a local fixed NTFS volume and Windows support for
FileRenameInfoEx (modern Windows 10/11). Unsupported APIs/ACLs fail closed. Linux
requires a local filesystem and a trusted directory chain; group/other-writable
ancestors without sticky-bit protection are refused. Network filesystems are
unsupported. File flushing and replacement reduce interruption risk but do not
guarantee universal power-loss durability. A killed process can leave staging or
recovery files for inspection. There is no unattended crash-recovery service or
operating-system remediation. See [security limits](SECURITY.md).
Windows read-only, compressed or encrypted files and files containing alternate
data streams are refused rather than silently dropping those attributes or streams.

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
Actions are pinned to commit hashes. Native collectors and desktop interactions
still need acceptance testing on representative endpoints. Tests do not establish
that an endpoint is secure.

[Dependency/release status](DEPENDENCIES.md) records external runtimes and the
unsigned commit history. Licensed under the [MIT License](LICENSE); see
[licensing](LICENSING.md). The display name is State Guard; the existing GitHub slug
`state-gaurd` is retained. The prototype does not claim safe OS remediation.

A [source-only SPDX inventory](sbom.spdx.json) records file hashes and the absence
of third-party Python packages. It does not inventory installed Python/Tcl/Tk/OS
binaries or certify vulnerability status. Regenerate after source changes:

```powershell
python scripts/generate_sbom.py
python scripts/generate_sbom.py --check
```
