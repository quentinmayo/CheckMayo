# Deployment guide

Use PostgreSQL 16+ for deployments. Choose local or remote storage during installation; keep the encryption key durable and back it up with the database. No database port is published by the default Compose stack.

## Linux VM and Docker Compose

The Bash installer checks prerequisites, requires an explicit database choice, generates administrator/database credentials and a Fernet key, and preserves existing `.env` and database volumes. It does not install Docker, modify firewalls, or perform unattended upgrades. `CHECKMAYO_INSTALL_DIR` changes the install directory; `CHECKMAYO_GIT_REF` pins a reviewed branch, tag or release.

Compose builds the controller image and starts PostgreSQL with health checks. The app runs as UID/GID 10001, with a read-only filesystem and a bounded `/tmp`; state is mounted at `/data`. App limits: 1 CPU, 768 MiB. Database limits: 0.5 CPU, 512 MiB.

The default HTTP listener is `127.0.0.1:8000`. Put an HTTPS reverse proxy in front of it. Set PUBLIC_URL to its exact public origin; secure cookies and browser mutation checks depend on this value.

For a remote database use [`deploy/compose.external-db.yaml`](https://github.com/quentinmayo/CheckMayo/blob/main/deploy/compose.external-db.yaml) and a privately configured DATABASE_URL. The URL must use the `postgresql+psycopg` SQLAlchemy driver. URL-encode reserved password characters. Configure verified TLS when connecting across hosts.

## Unraid

Create a dedicated directory under your selected app-data or external drive. Set CHECKMAYO_DATA_ROOT in your private deployment environment. Initialize its `state` directory with UID/GID 10001; PostgreSQL owns its own data directory.

```bash
docker compose -f compose.yaml -f deploy/compose.unraid.yaml up --build -d --wait
```

Keep this path exclusive to CheckMayo. Never reuse another project's database directory. The override mounts `state` and `postgres` beneath your selected directory. Back up the mounted database and encryption key; avoid a share configured to move active database files between storage tiers while the database is running.

Run scanners on a separate dedicated VM. Do not grant an untrusted scanner access to the Unraid Docker daemon containing your other services.

## Coolify

Create a CheckMayo project/environment. Deploy PostgreSQL as a dedicated resource or Compose service, limit it to 0.5 CPU/512 MiB, and bind its data directory to a new dedicated directory on the external drive. Verify the mount exists on the **connected Coolify server**, which may be a VM rather than the Unraid host.

Create a public Git application using the upstream repository and Dockerfile. Expose container port 8000 with `/health` as the health check. Configure runtime PUBLIC_URL, DATABASE_URL, administrator credentials, durable CHECKMAYO_ENCRYPTION_KEY and optional donation URL. Keep secrets as runtime variables, not Docker build arguments. Set memory to 768 MiB and CPU to 1.0. Do not publish the database or mount a Docker socket.

For the public scanner registry, set CHECKMAYO_MODE=registry. This intentionally disables execution, schedules, integration callbacks and network connectors. Deploy a separate private controller for organization scanning. Review source commits before redeployment.

Configure the chosen domain at Coolify and create a Route 53 A/AAAA/CNAME record to your existing trusted ingress. Avoid assuming an existing wildcard covers the new hostname: verify DNS and HTTPS independently.

## Kubernetes (including EKS)

The manifest in [`deploy/kubernetes/checkmayo.yaml`](https://github.com/quentinmayo/CheckMayo/blob/main/deploy/kubernetes/checkmayo.yaml) deploys the controller, Service, resource quota and network policy. It expects a separately provisioned PostgreSQL database and a Secret named `checkmayo-runtime`. The controller has no service-account token or Docker socket.

```bash
kubectl apply -f deploy/kubernetes/checkmayo.yaml --selector=''
# Supply a mode-600 runtime.env containing PUBLIC_URL, DATABASE_URL,
# CHECKMAYO_ENCRYPTION_KEY and CHECKMAYO_ADMIN_EMAIL/PASSWORD.
kubectl -n checkmayo create secret generic checkmayo-runtime --from-env-file=/private/runtime.env
kubectl -n checkmayo rollout status deployment/checkmayo
kubectl -n checkmayo port-forward service/checkmayo 8000:80
```

The temporary `/data` emptyDir is safe only when the Fernet key is supplied by the Secret; integrations must not depend on a generated ephemeral key. The image reference to `main` is a preview convenience; pin a reviewed image digest for production. Configure an ingress/TLS certificate and PUBLIC_URL. The network policy allows DNS and PostgreSQL; add narrowly scoped egress rules for the integrations you enable. A CNI implementing NetworkPolicy is required.

Use a single controller replica in the preview. Runners are dedicated VMs; the Compose runner is not a Kubernetes-native scanner pod orchestrator. EKS uses the same controller manifest with RDS, private networking and your standard ingress. EKS cloud provisioning is a separate infrastructure operation; see the current validation matrix.

## EC2

Use a dedicated Linux instance with Docker Compose, an encrypted root/data volume, a minimal instance profile and only HTTPS through your ingress. Install the reviewed release using scripts/install.sh. Store the database on durable EBS or use RDS PostgreSQL with verified TLS. Keep scanner runners separate; their instance profiles should not hold administrator permissions.

Budget before scaling. Tag temporary experiments with the project and test ID, record every created resource, and delete test instances, volumes, addresses, security groups and associated databases after verification.

## ECS

ECS Fargate can host the **controller**, using a published controller image and RDS PostgreSQL. See deploy/aws/ecs-task.json. Supply credentials via Secrets Manager or SSM references; do not include plaintext secrets in a task definition. Use an ALB health check at `/health`, private tasks, verified database TLS and no database ingress from the public internet.

Fargate does not provide the Docker daemon needed by the current Compose runner. Use dedicated EC2 scanner runners that connect outbound to the controller. Native ECS scanner jobs are roadmap work.

## Backups, upgrade and removal

Use pg_dump/pg_restore or your PostgreSQL provider's backup workflow, and separately back up the Fernet key. Test restoration before relying on backups. This initial release creates tables at startup; it has no upgrade migration tooling yet. Review schema changes before upgrading a populated installation.

`docker compose down` preserves data volumes. Use `down --volumes` only for explicitly disposable test stacks; it removes database data. Kubernetes test cleanup deletes the dedicated namespace and any separately created test PVC/database. Do not delete other projects' resources.

Continue with [getting started](https://github.com/quentinmayo/CheckMayo/wiki/Getting-Started), [authentication and roles](https://github.com/quentinmayo/CheckMayo/wiki/Authentication-and-Roles), or [compatibility and testing](https://github.com/quentinmayo/CheckMayo/wiki/Compatibility-and-Testing).
