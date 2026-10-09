# Validation evidence

Status is recorded as tests finish. This document distinguishes actual execution from deployment guidance.

| Area | Current evidence |
| --- | --- |
| Automated API/security regressions | 28 passing tests: tenant isolation, key revocation/scope, CSRF, roles, private packages/reports, immutable versions, runner leases/capacity/labels/disable/cancellation, rejected host-access Compose fields, safe report paths, webhook signatures/installation/forks/replay, encrypted integrations, native findings deduplication, AI opt-in, rate limiting, restricted OPA |
| Container build | Local ARM64 controller image built; OPA binary checksum verified |
| PostgreSQL Compose | Validation in progress |
| Browser workflows | Validation in progress |
| Unraid deployment and runner | Validation in progress |
| VM installer | Validation in progress |
| Kubernetes | Validation in progress |
| AWS EC2 / ECS / EKS | Reference instructions; live testing depends on authorized account access |
| DefectDojo | API bridge implemented; comprehensive live parser coverage not yet validated |
| OIDC / LDAPS / Ollama | Implemented; external-provider end-to-end validation not yet completed |
| Organization mirror | Private securelyprogramming mirror created; hook/CI evidence recorded after publication |
| Donation account | Buy Me a Coffee selected; verification/onboarding pending |

No zero-finding, comprehensive scanner-coverage, production-readiness, or third-party certification claim is implied by these checks. Tests and reports never include real credentials or private operational data in the public repository.
