"""Generate/check a source-only SPDX inventory without third-party dependencies."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from state_guard import __version__


def build(created):
    names = ["README.md", "LICENSING.md", "SECURITY.md", "DEPENDENCIES.md", ".gitignore", ".gitattributes"]
    names += [p.name for p in ROOT.glob("state_guard*.py")]
    if (ROOT / "LICENSE").is_file():
        names.append("LICENSE")
    for directory in ("tests", "scripts", "examples", ".github/workflows"):
        names += [p.relative_to(ROOT).as_posix() for p in (ROOT / directory).rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts and p.suffix in (".py", ".json", ".yml")]
    files = []
    for index, name in enumerate(sorted(names)):
        raw = (ROOT / name).read_bytes()
        files.append({"SPDXID": f"SPDXRef-File-{index}", "fileName": "./" + name,
                      "checksums": [{"algorithm": "SHA1", "checksumValue": hashlib.sha1(raw).hexdigest()},
                                    {"algorithm": "SHA256", "checksumValue": hashlib.sha256(raw).hexdigest()}],
                      "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"],
                      "copyrightText": "NOASSERTION"})
    verification = hashlib.sha1("".join(sorted(f["checksums"][0]["checksumValue"] for f in files)).encode("ascii")).hexdigest()
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "State Guard source inventory",
            "documentNamespace": "https://github.com/PaulinoTech1/state-gaurd/spdx/" + __version__ + "-" + verification,
            "creationInfo": {"creators": ["Tool: State Guard source inventory generator"], "created": created},
            "comment": "Source-only inventory. No third-party Python packages. Python, optional Tcl/Tk, operating-system components and CI runner images are externally supplied and not inventoried here. This is not a vulnerability scan or binary/runtime SBOM. Licensing is unasserted pending owner selection.",
            "packages": [{"name": "State Guard", "SPDXID": "SPDXRef-StateGuard", "versionInfo": __version__,
                          "downloadLocation": "https://github.com/PaulinoTech1/state-gaurd",
                          "filesAnalyzed": True, "packageVerificationCode": {"packageVerificationCodeValue": verification},
                          "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION"}],
            "files": files,
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-StateGuard"}] +
                             [{"spdxElementId": "SPDXRef-StateGuard", "relationshipType": "CONTAINS", "relatedSpdxElement": f["SPDXID"]} for f in files]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the tracked inventory matches current source bytes")
    args = parser.parse_args()
    path = ROOT / "sbom.spdx.json"
    if args.check and path.exists():
        try:
            created = json.loads(path.read_bytes())["creationInfo"]["created"]
            datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, KeyError, TypeError):
            print("Invalid source inventory metadata", file=sys.stderr)
            return 1
    else:
        created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expected = (json.dumps(build(created), indent=2) + "\n").encode("utf-8")
    if args.check:
        if not path.exists() or path.read_bytes() != expected:
            print("Source inventory is stale; run python scripts/generate_sbom.py", file=sys.stderr)
            return 1
        print("Source inventory matches current files")
    else:
        path.write_bytes(expected)
        print("Generated source-only inventory: sbom.spdx.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
