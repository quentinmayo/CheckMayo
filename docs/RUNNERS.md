# Dedicated Linux runners

Enroll a runner in the UI or `POST /api/workspaces/{id}/runners`. Save the returned token once in `/etc/checkmayo/runner-token` with mode 600. The token is hashed on the server. A disabled runner cannot poll or complete jobs; re-enabling it restores access. Rotation currently means creating a new runner and disabling the old one.

Install Git, Python 3.12, Docker Engine, and Compose. Clone the reviewed CheckMayo version and install `requirements.txt` in a virtual environment. Review the package's Compose file and image, then copy its registry SHA-256 into a trust file, one digest per line.

```bash
python -m runner.agent \
  --url https://checkmayo.your-domain.example \
  --token-file /etc/checkmayo/runner-token \
  --trust-file /etc/checkmayo/trusted-scanners \
  --workdir /var/lib/checkmayo-runner
```

Run this as a dedicated operator account with access only to that VM's Docker daemon. Docker access grants control of the host, so use an isolated disposable VM. Do not co-locate the runner with databases, customer apps, your controller, or cloud administrator credentials. Do not mount its token file or Docker configuration into scanner containers.

The agent polls outbound, verifies the package hash against the local trust list, clones a GitHub repository without hooks/submodules/LFS execution, checks out the requested ref, and runs the reviewed package with enforced limits. Private-repository installation tokens are obtained only for the configured repository and active lease; they are not embedded in Git URLs or scanner environments.

The runner renews leases every 20 seconds; the lease lasts 120 seconds. Scan execution times out after 15 minutes. Disabling, cancelling, or losing a lease stops execution on the next heartbeat. `docker compose down --volumes --remove-orphans` cleans up each job, and source/report scratch directories are removed.

Concurrency is an upper bound enforced by the server. This preview agent runs one job at a time; use separate dedicated agents/hosts for parallelism, or contribute a reviewed local worker pool. Labels let you route work among AWS, homelab, datacenter and other locations.

Daemon-level network ACLs, rootless Docker or an equivalent hardened execution environment, read-only image cache, scanner image digests and disposable-VM recycling are recommended before sensitive production use. The agent does not claim kernel-level sandbox guarantees.
