# State Guard

**Status: placeholder / work in progress.** This repository does not currently
contain an implementation. It is not ready for evaluation or production use.

## Intended scope

The intended project is an endpoint security auditing tool that compares
endpoint configuration with an explicitly supplied desired-state policy and
reports configuration drift. Supported operating systems, policy format,
collection methods, and deployment model have not yet been selected.

Remediation is not implemented or specified. Do not rely on this repository to
secure, configure, or repair an endpoint.

## Security status

There is no implementation to inspect, threat model, privilege design, audit
logging, test suite, CI, dependency manifest, release process, or SBOM. In
particular, this project makes no claims about safe remediation, rollback,
concurrent changes, or failure handling. These need to be designed and
independently verified before any remediation feature is considered usable.

Until then, treat this repository as an unverified project placeholder, not as
security software or a trusted source of endpoint configuration changes.