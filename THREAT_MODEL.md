# State Guard threat model

## Scope and assets

State Guard reads a small set of Windows or Linux security indicators and compares
explicitly selected local JSON files with a user-supplied policy. Its write surface is
limited to guarded JSON replacement, private recovery files, recovery cleanup, and
rollback. The protected assets are the selected config's bytes and metadata, recovery
material, and the accuracy of audit and drift results.

## Trust boundaries

- The operator, policy, executable, Python runtime, operating system, and local
  administrator/root are trusted.
- The selected config and its owning application may be malformed, unavailable, or
  changing, but the application should be stopped before a write operation.
- The config directory must be local and trusted. A same-user attacker or hostile
  writable directory is outside the protection boundary.
- PowerShell, procfs, filesystem APIs, and kernel-reported state are platform trust
  boundaries. Collector failures produce UNKNOWN rather than PASS.
- Policy settings and config values are sensitive. Reports expose names and types but
  do not print values.

## Attacker capabilities considered

State Guard considers accidental interruption, malformed JSON or policy input,
ordinary concurrent writers, links and reparse points, stale recovery material,
corrupt recovery bytes, and attempts to replace a config between validation and
replacement. It also considers unprivileged users trying to read recovery files.

## Controls and guarantees

- Exclusive recovery creation, private permissions, hashes, and content rechecks bind
  rollback and cleanup to the recorded original and applied states.
- Persistent sidecar locks serialize cooperating State Guard processes. POSIX advisory
  locking and Windows sharing restrictions also detect ordinary writers.
- Complete staging, flushing, identity checks, and atomic replacement avoid in-place
  truncation and reduce interruption and TOCTOU risk.
- Symlinks, hard links, Windows reparse points and alternate data streams are rejected.
- Cleanup requires valid recovery hashes, a recognized current config hash, current
  policy compliance, and an explicit `--apply` confirmation.
- Strict JSON parsing, exact types, size limits, and byte-preserving rendering fail
  closed on ambiguous or unsupported inputs.

## Limits and residual risks

State Guard does not defend against administrator/root, kernel compromise, a modified
Python runtime or program, storage corruption, power-loss behavior outside filesystem
guarantees, or an attacker who controls the operator's account. Hashes detect mismatch;
they are not signatures against the file owner. An owning application can ignore POSIX
advisory locks, write after replacement, or continuously revert the desired state.
Windows external rename/delete races and hostile directory namespaces remain outside
the supported boundary. Recovery cleanup removes two files sequentially, so interruption
can leave partial recovery state requiring manual inspection. Endpoint checks are
limited indicators and do not establish compliance or endpoint security.

## Validation expectations

CI exercises Windows and Linux on supported Python versions. Regression tests cover
write interruption, concurrent operations, corrupt and stale recovery data, cleanup
preconditions, byte preservation, platform collector failures, and Windows ACL behavior.
Representative endpoint testing remains necessary for OS and security-product variants.
