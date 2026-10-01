# Security scope and remaining limits

This is an early prototype, not a comprehensive endpoint auditor, compliance
certification, or an unattended operating-system hardening service. Native checks
are read-only. Apply and rollback affect only explicitly selected local JSON files.

## Write boundary

Assume a trusted, stable directory namespace and a stopped owning application.
Do not run as administrator/root merely to bypass an error. Same-user attackers,
administrators/root, and hostile writable directories are outside the protection
provided by these file operations. Path and file-handle checks reject observed
links, hard links, reparse points and identity changes; they do not prove immunity
to every rename race in an attacker-controlled namespace.

Apply and rollback use a persistent sidecar OS lock to serialize cooperating State
Guard processes. Do not delete or rename the lock file while any operation runs.
POSIX also takes an advisory lock on the original config. Applications that ignore
locks can still race or overwrite the new inode. Windows holds a read snapshot
denying ordinary write sharing; external rename/delete or later writes are still
possible. Locks do not provide a distributed transaction.

The config is never truncated in place. A complete, flushed, verified staging file
is placed beside it before a rename/replacement. POSIX uses os.replace; Windows
uses handle-based FileRenameInfoEx and requires a local fixed NTFS volume and a
Windows release supporting that API. Unsupported APIs or ACL preservation fail
closed, without falling back to in-place writes. Network filesystems are unsupported.
Windows read-only, compressed/encrypted files and alternate data streams are refused.
Files and POSIX directory entries are flushed; this is not a universal power-loss,
storage-controller, filesystem-corruption or multi-file transaction guarantee.

Recovery data and its hash manifest are exclusively created before replacement.
POSIX creates them with mode 0600 from the outset. Windows creates protected DACLs
allowing the current user and SYSTEM instead of inheriting broad directory ACLs.
Access-control failures stop remediation; there is no public-backup fallback.
Config access controls are retained separately. Recovery hashes detect mismatches;
they are not signatures and cannot defend against the owner modifying both files.

## Recovery and serialization

Rollback verifies the original-byte hash and accepts only current bytes matching
the recorded original or intended applied state. It refuses newer edits instead of
overwriting them. Recovery files remain after rollback; archive or remove them only
after review and before another application of policy. Old prototype backups with
no private manifest are not automatically trusted. A crash can leave a staged file
or incomplete recovery preparation requiring inspection. Rollback is a command,
not a background crash-recovery agent.

Default edits preserve bytes outside replaced top-level JSON values, including
whitespace, encoding BOM, unrelated number/string spellings, and key order. Missing
keys require explicit full-format opt-in. UTF-8 only (optional BOM), maximum 4 MiB.
Duplicate keys, nonstandard constants and non-finite numbers are refused. Exact type
matching intentionally distinguishes bool/int/string; there is no silent coercion.
Full reformat also refuses numeric precision loss instead of changing unmanaged
numeric values. There is no format-independent proof of compatibility with every
application parser.

## Evidence and reporting

Regression tests cover staging/rename failures, private recovery permissions, lock
contention, a process killed before rename, unmanaged-byte preservation, exact-byte
rollback and refusal of newer/corrupt recovery states. They do not establish broad
security, all filesystem crash modes, or Windows/Linux coverage on every endpoint.
Report platform-specific skips and unavailable checks explicitly. Commit signatures,
license selection and runtime vulnerability coverage are separate concerns.

For suspected vulnerabilities, use a private channel available through the repository
owner's GitHub profile. No monitored disclosure mailbox or response SLA is asserted.
