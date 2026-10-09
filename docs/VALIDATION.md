# Validation evidence

Validation completed on October 9, 2026. This matrix distinguishes executed tests from reference deployment guidance.

| Area | Executed evidence |
| --- | --- |
| Automated API/security regressions | 29 tests passed: tenant isolation, key scope/revocation, CSRF, roles, private packages/reports, immutable versions, community review/withdrawal, runner leases/capacity/labels/disable/cancellation, safe Compose/report contracts, webhook signatures/installation/forks/replay, encrypted integrations, finding deduplication, AI opt-in, rate limits and restricted OPA |
| Live LDAPS and access levels | 5 additional tests passed against an isolated LLDAP v0.6.3 directory with a short-lived CA. Valid sign-in, separate identities, wrong password, escaped filters, untrusted-certificate rejection and plaintext-LDAP rejection; owner/admin/operator/viewer permissions and cross-workspace/report denial. Directory administrator privileges do not grant site administration |
| Container builds | ARM64 local image and AMD64 GitHub image builds passed; OPA binary checksum verified |
| PostgreSQL Compose | Healthy app/database; real concurrent polls enforce runner capacity; real OPA evaluation passed |
| Browser workflows | Signup, login, runner enrollment, scan queue, API-key creation, policy preview/save, community source review/approval/withdrawal, and 390px layout passed; no browser JS errors |
| Hosted community registry | Verified HTTPS, administrator login, review queue, public package listing, donation link and mobile layout; PostgreSQL/state bound to the Coolify host's verified external drive; app/database CPU and memory limits applied. Controller image pinned by digest |
| Unraid host Compose | Controller and PostgreSQL ran directly on Unraid with dedicated bind-mounted storage, loopback app access, resource limits and a successful health check |
| VM installer | One-line installation on a fresh Unraid-hosted Ubuntu VM passed. The first test exposed a restrictive-umask source-permission bug; the corrected non-root image passed the retest |
| Real scanner execution | Outbound VM runner completed Gitleaks, Trivy configuration and Semgrep starter scans of the public repository; each produced a downloadable report. Semgrep's writable HOME fix was published as a new immutable package version |
| Local Kubernetes | K3s v1.37.1+k3s1 on the disposable Unraid VM: controller and PostgreSQL deployment rollouts and controller health passed |
| AWS EC2 | Ubuntu 24.04 Compose installer passed on a dedicated encrypted-volume EC2 instance; SSM and controller health checks passed |
| AWS ECS | Fargate container deployment and HTTP health passed with an explicitly disposable SQLite database. This smoke test does not validate RDS, ALB, durable storage or a production ECS architecture |
| AWS EKS | Managed EKS v1.36.4 worker, controller/PostgreSQL rollouts, namespace quota/network-policy resources and controller health passed. The database was a disposable test fixture; RDS, ingress and enforced CNI network-policy behavior were not independently validated |
| DefectDojo | API discovery/import bridge implemented; comprehensive live parser coverage has not been validated |
| OIDC / Ollama | Implemented; external-provider/model end-to-end validation remains outstanding |
| Organization mirror | Private securelyprogramming/CheckMayo-internal CI, live LDAPS/access checks and real Gitleaks scanning passed on push. PR/cron triggers configured; organization-wide GitHub App rollout is not implied |
| Developer support | Maintainer's public Buy Me a Coffee creator profile verified; README, GitHub funding and site links configured. No payment/payout transaction performed |
| Secret checks | Known operational credential comparison and full eligible-file Gitleaks scan before staging; staged scan and pre-commit hook before each commit; public/private CI and history scans passed |
| Cleanup | Temporary EC2/ECS/EKS infrastructure, dedicated IAM roles, VPC/network resources, Unraid VM/overlay, Unraid test containers/storage, local test stack and live-directory fixtures removed. The live Coolify registry, its persistent database and production DNS are retained |

## Reproduce identity checks

With Docker running and development dependencies installed:

```bash
CHECKMAYO_TEST_LDAP=1 pytest tests/test_ldap_live.py -q --tb=short
```

The test generates disposable credentials and certificates outside the repository, binds only loopback ports, and removes the directory container and generated files in its finalizer. Both repository CI configurations execute these live checks.

| Capability in a shared workspace | Owner | Admin | Operator | Viewer |
| --- | --- | --- | --- | --- |
| Read scans, findings and private reports | Yes | Yes | Yes | Yes |
| Publish packages, queue scans and triage findings | Yes | Yes | Yes | No |
| Manage settings, runners, API keys and members | Yes | Yes | No | No |
| Access an unrelated workspace or its reports | No | No | No | No |
| Approve community packages without separate site-admin permission | No | No | No | No |

No zero-finding, comprehensive scanner-coverage, production-readiness, or third-party certification claim is implied by these checks. Operational credentials, test reports and private deployment details are excluded from the public repository.
