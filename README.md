# CheckMayo

**Your scanners. Your infrastructure. Your call.**

CheckMayo is an Apache 2.0 security orchestration platform for solo developers and teams. Publish scanners as Docker Compose packages, run them on your own machines, and keep security reports in your own database.

[Community registry](https://checkmayo.programmingsecurely.com) · [Deployment guide](docs/DEPLOYMENT.md) · [Scanner contract](docs/SCANNERS.md) · [API and integrations](docs/INTEGRATIONS.md) · [Roadmap](docs/ROADMAP.md)

> **v0.1 preview:** a working foundation with explicit security boundaries. This release is not a complete replacement for Checkmarx or DefectDojo. See [compatibility](docs/COMPATIBILITY.md) and [validation](docs/VALIDATION.md) for what is implemented and what has actually been tested.

## What you can do

- Create personal or organization workspaces with owner, administrator, operator, and viewer roles.
- Search and download community scanners; publish immutable versions in your private registry or submit them for administrator review.
- Connect dedicated Linux VMs as outbound runners. Select locations with labels; enforce concurrency and job leases; disable runners from the platform.
- Queue scans manually, on signed GitHub App pull-request events, or on UTC cron schedules.
- Normalize Gitleaks, Semgrep, Trivy, and SARIF reports into deduplicated findings; record triage decisions and audit events.
- Import reports into your own DefectDojo instance using its discovered scan types. Its parser coverage is available through this bridge; those parsers are not bundled into CheckMayo.
- Configure your image mirror or Nexus proxy prefix, HTTP proxy, and encrypted integrations per workspace.
- Preview and save Rego triage policies with restricted OPA execution. AI summaries are off by default and use your own Ollama endpoint when explicitly enabled.
- Use Swagger at `/docs` or `/openapi.json`, and create revocable workspace API keys with 90-day expiry.
- Sign in with local accounts, an administrator-configured OIDC provider, or LDAPS.

## Quick start

Install Docker Engine with Compose v2.24+, Git, and Python 3 on a Linux host. The installer **requires you to choose where data is stored**, generates credentials, and keeps them in a mode-600 `.env` file.

```bash
curl -fsSLo /tmp/checkmayo-install.sh https://raw.githubusercontent.com/quentinmayo/CheckMayo/main/scripts/install.sh && CHECKMAYO_DATABASE_MODE=local bash /tmp/checkmayo-install.sh
```

For a controlled production install, download the script from a reviewed commit or release, inspect it, and pin `CHECKMAYO_GIT_REF` to that ref. This preview uses `main` in the convenience command; it does not provide a signed-release trust chain yet.

Open `http://localhost:8000`. Read the generated administrator credentials locally from `~/checkmayo/.env`. Set `PUBLIC_URL` and configure an HTTPS reverse proxy before exposing the platform outside localhost. The default Compose file binds only loopback.

To use a remote database:

```bash
export CHECKMAYO_DATABASE_MODE=remote
# Set CHECKMAYO_DATABASE_URL privately to a postgresql+psycopg:// URL.
# Use sslmode=verify-full and the database's trusted CA for remote TLS.
bash /tmp/checkmayo-install.sh
```

PostgreSQL is the supported deployment database. SQLite is available for local development. MySQL is not supported in this release.

## Docker Compose

```bash
git clone https://github.com/quentinmayo/CheckMayo.git
cd CheckMayo
cp .env.example .env
# Set administrator and PostgreSQL passwords and a Fernet encryption key.
# Generate a key with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
docker compose up --build -d --wait
```

See [deployment instructions](docs/DEPLOYMENT.md) for Unraid storage, Coolify, Kubernetes, EC2, ECS, and EKS. Cloud instructions distinguish reference architecture from tested deployment paths.

## Bring a runner

A scanner host needs Linux, Docker Compose, Git, and Python 3.12. Enroll it in **Workspace → Runners**, save the returned credential in a mode-600 file, and explicitly trust each reviewed package digest. Follow [the runner guide](docs/RUNNERS.md).

Scanner packages are executable code. Runners belong on disposable VMs, with no unrelated applications or credentials. CheckMayo does not mount a Docker socket into its controller. The preview scanner contract allows one service, a read-only source mount, a report mount, no network, and fixed CPU/memory/process limits. Multi-service packages, uploaded ZIP bundles, unrestricted DAST, and arbitrary host-access scanners need a separate reviewed execution profile; they are not silently enabled.

## Community and internal validation

The public upstream lives at **[quentinmayo/CheckMayo](https://github.com/quentinmayo/CheckMayo)**. A private integration mirror in the **securelyprogramming** organization is used for development and scanner validation. GitHub requires public forks to stay public, so this is a private mirror rather than a GitHub fork. It is not publicly browsable.

The same secret-check hooks and CI configuration can be used by a solo developer or an organization. See [validation evidence](docs/VALIDATION.md) before interpreting this as broad organization-wide scanning coverage.

## Want managed security tooling?

Explore **[MayoASPM](https://mayoaspm.com/)** for additional managed security tooling. CheckMayo remains free to self-host.

## Support the developers ☕

If CheckMayo helps you, consider supporting its maintainers. [Developer support](docs/SUPPORT.md) documents the Buy Me a Coffee setup status. We will publish the donation link after the creator account is verified and activated; no unverified payment destination is advertised.

Built by [Quentin Mayo](https://www.quentinmayo.com/), whose work spans application security, cloud infrastructure, and automation.

## Development

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
git config core.hooksPath .githooks
pytest -q
ruff check app runner tests
# Install gitleaks 8.30.1+ first.
bash scripts/check-secrets.sh all
bash scripts/safe-commit.sh "Describe your change"
```

Every staging operation for this project must be preceded by a secret scan, and every commit scans the staged snapshot. CI repeats the scan. Do not put infrastructure credentials, reports, tester accounts, private repositories, or operational backups in a public build context.

[Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Apache 2.0 license](LICENSE)

CheckMayo is independent of Checkmarx, DefectDojo, and the individual scanner vendors. Scanner licenses and services' terms still apply.
