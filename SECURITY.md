# Security policy

This is a preview release. Report vulnerabilities privately using GitHub's private vulnerability reporting on the upstream repository, or contact the maintainer through https://www.quentinmayo.com/. Do not upload real secrets or private scan reports into public issues.

## Execution boundaries

The controller stores metadata and reports and never holds a Docker socket. The hosted community registry disables runner enrollment, scanning, schedules, remote integrations, and policy execution. Self-hosted controllers can configure administrator-owned internal endpoints.

Only explicitly trusted package digests execute on a runner. Package validation rejects privileged mode, host networking, additional capabilities, host paths, Docker sockets, build contexts, environment files, interpolation in image names, and unsafe report paths. Images run as non-root, with no network, a read-only root, dropped capabilities, and bounded CPU, memory, scratch space and process count. Container isolation is not a complete boundary against kernel vulnerabilities: use disposable dedicated VMs.

Runners possess workspace-scoped credentials and lease tokens. The server checks workspace, runner, lease expiry and job state for heartbeats and completion. Cancellation rejects completion and terminates execution on the next runner heartbeat. Credentials and integration material do not enter scanner subprocess environments. Scanner stdout/stderr are suppressed because they may contain secrets; reports are private and may still contain sensitive information. Gitleaks packages use redaction.

Cookie-authenticated mutations require an exact configured Origin. Sessions are HTTP-only and HTTPS-secure when PUBLIC_URL uses HTTPS; API keys are hashed, revocable, scoped, and expiring. OIDC uses state/nonce validation and verified email; new identities never link to existing local accounts based only on email. LDAP requires certificate-verified LDAPS. Signups and authentication attempts have database-backed rate limits.

Rego execution excludes network, runtime/environment inspection, and wall-clock builtins; output and CPU use are bounded. Policy failure never means a scan is safe. Optional AI sends only explicitly submitted text to the workspace's Ollama service and requires human review.

## Operational requirements

Use TLS, PostgreSQL TLS for remote databases, encrypted backups, strong generated bootstrap credentials, and a durable encryption key. Back up that key with the database; losing it makes stored integrations unreadable. Do not expose PostgreSQL, Docker, LDAP service credentials, or the runner agent to the public internet.

Preview limits: no email-verification or password-reset flow, no signed scanner supply-chain attestations, no automated retention worker, no database upgrade migrations, no full enterprise group synchronization, no complete scanner egress broker. Review the roadmap and validation matrix before adopting this release for sensitive production workloads.
