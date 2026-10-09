## 1. Choose where your data lives

CheckMayo's deployment database is PostgreSQL 16+. Use a local database in the Compose stack or your own remote PostgreSQL instance. SQLite is available for local development; MySQL is not supported in the preview.

Choose a dedicated Linux controller host with Docker Engine, Compose v2.24+, Git, and Python 3. Keep scanning on separate dedicated runner VMs. The installer does not install Docker or alter your firewall.

## 2. Install the controller

```bash
curl -fsSLo /tmp/checkmayo-install.sh https://raw.githubusercontent.com/quentinmayo/CheckMayo/main/scripts/install.sh
CHECKMAYO_DATABASE_MODE=local bash /tmp/checkmayo-install.sh
```

Review the script first. For a controlled production install, download it from a reviewed commit and set `CHECKMAYO_GIT_REF` to that commit. The convenience command follows `main`; signed releases are not available in this preview.

The installer generates credentials and a durable encryption key in `~/checkmayo/.env`, with mode 600. It preserves an existing configuration and data volumes. `CHECKMAYO_INSTALL_DIR` selects a different installation directory.

For a remote database, set `CHECKMAYO_DATABASE_MODE=remote` and privately supply `CHECKMAYO_DATABASE_URL` using `postgresql+psycopg://`. Use verified TLS with `sslmode=verify-full` and your database's trusted CA. Keep the database URL out of screenshots, repository files, and shell transcripts.

## 3. Open your workspace

Open `http://localhost:8000` on the controller host, or use a local SSH tunnel. The default listener binds loopback. Read the generated administrator credentials locally from the private `.env` and sign in.

Set `PUBLIC_URL` to your exact HTTPS origin and configure an HTTPS reverse proxy before exposing the controller. See [deployments](https://github.com/quentinmayo/CheckMayo/wiki/Deployments) for Compose, Unraid, Coolify, Kubernetes, and AWS.

Create a personal or organization workspace with **+ Workspace**. Workspaces isolate packages, runners, reports, settings, and permissions. Registered users can be added through **Settings & connections → Add member**.

## 4. Review a scanner and connect a runner

1. Find a starter scanner in the registry, download its Compose file, and review its image, command, mounts, and report format.
2. Choose **Details** to copy the package's SHA-256.
3. In **Workspace → Runners**, enroll a dedicated Linux VM and save its one-time credential to a mode-600 file.
4. Add the reviewed package digest to that runner's local trust file.
5. Start the outbound runner following the [runner guide](https://github.com/quentinmayo/CheckMayo/wiki/Runners).

The initial agent runs one job at a time. Labels route work among your machines. Docker access controls the host, so keep the runner on an isolated VM with no unrelated workloads or administrator cloud credentials.

## 5. Queue a scan

In **Scans & schedules → Queue scan**, choose a package, GitHub repository, ref, and optional runner label. A matching enabled runner polls for the job. Completed jobs provide **Download report**; supported report formats also populate **Findings**.

Start with your own reviewed public repository. Private repositories require a configured GitHub App integration. A completed job means a report was produced; review its findings before treating the repository as safe.

Continue with [PR and scheduled scans](https://github.com/quentinmayo/CheckMayo/wiki/PR-and-Scheduled-Scans), [authentication and roles](https://github.com/quentinmayo/CheckMayo/wiki/Authentication-and-Roles), and the [screenshot tour](https://github.com/quentinmayo/CheckMayo/wiki/Screenshots).
