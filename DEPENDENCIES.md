# Dependency and release inventory

Application third-party Python packages: **none**. No pip installation or lockfile
is required. Python standard-library modules and Windows native APIs are used.
Tkinter additionally depends on the Python distribution's Tcl/Tk runtime. Python,
Tcl/Tk, PowerShell, Windows/Linux, and hosted CI runner images are externally
supplied dependencies; they are not pinned or bundled by this source repository.
Keep those components supported and patched independently.

`sbom.spdx.json` is a source-only SPDX 2.3 inventory with per-file hashes, regenerated
by `python scripts/generate_sbom.py`. CI rejects a stale inventory. It does not
enumerate installed runtime binaries, prove their integrity, or scan vulnerabilities.
The inventory reports licensing as MIT.

GitHub Actions dependencies are pinned to commit hashes. The Windows/Linux runner
images and requested Python minor versions are mutable; pinning actions does not
make the complete build environment reproducible.

The existing commit history is unsigned. No signing key or trusted release identity
has been configured or verified by this change. Do not label commits or artifacts
as signed. Configure the owner's signing identity and verify signatures before
making that claim. This change does not rewrite history or create a signing key.

The display name is State Guard. The GitHub slug remains `state-gaurd` so existing
clone URLs keep working. Renaming the repository is a separate administration
operation. Suggested honest repository description:

> Prototype Windows/Linux endpoint checks and JSON configuration drift detection,
> with preview, guarded file remediation, rollback, CLI and desktop interface.
