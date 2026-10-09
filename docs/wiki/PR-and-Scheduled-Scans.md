## Manual scans

Open **Workspace → Scans & schedules → Queue scan**. Select a visible scanner package, a GitHub repository URL, a ref such as `main`, and an optional runner label. Only matching enabled runners in that workspace can claim the job. Private packages stay workspace-scoped.

The controller stores jobs and reports in your database. You can cancel a queued or running job; a running agent stops when its next lease heartbeat detects cancellation. Disabled runners cannot poll or complete jobs.

## UTC cron schedules

Choose **+ Schedule** and provide the same package, repository, ref, and label plus a five-field cron expression. For example, `0 2 * * *` queues a scan daily at **02:00 UTC**. The table may display next-run timestamps in your browser's local time zone; the cron expression always uses UTC.

Use **Pause** or **Resume** to control a schedule. A schedule queues work; an enabled matching runner and a locally trusted package digest are still required for execution. The preview controller should run as a single replica.

## GitHub App pull-request events

1. Create a GitHub App on your personal account or organization.
2. Set its webhook URL to `https://your-controller/api/hooks/github/WORKSPACE_ID`.
3. Subscribe to pull-request events and grant repository **Contents: read**.
4. Install it only on the repositories you intend to scan.
5. In **Settings & connections → github**, provide the app ID, installation ID, PEM private key, webhook secret, `owner/repo`, package ID, and runner label.

Use a randomly generated webhook secret of at least 32 characters. Integration credentials are encrypted at rest and status responses do not return them. Keep the durable encryption key with your database backup.

CheckMayo validates webhook signatures, installation/repository identity, and delivery IDs. It queues immutable commit SHAs for supported same-repository pull requests. Cross-repository fork events are ignored; manually queue a reviewed fork when appropriate.

The current release does not publish GitHub PR checks or finding details. It does not need **Checks: write**. Private-repository installation tokens are limited to repository Contents: read and issued only for an active runner lease. See [API and integrations](https://github.com/quentinmayo/CheckMayo/wiki/API-and-Integrations).

## Job states and reports

| State | Meaning |
| --- | --- |
| Queued | Waiting for an enabled matching runner with capacity |
| Running | Claimed by a runner with an active lease |
| Completed | A report was produced; findings may still require action |
| Failed | Execution failed; inspect the isolated runner locally |
| Cancelled | An operator cancelled the job |

The runner renews its lease every 20 seconds. Leases last 120 seconds; expired jobs can be requeued. Execution has a 15-minute timeout. Reports must be regular UTF-8 files, up to 5 MB, in the allowed report mount.

![Scans and UTC schedules with sample data](https://raw.githubusercontent.com/quentinmayo/CheckMayo/main/docs/assets/screenshots/scans-and-schedules.png)

*The screenshot uses disposable demo jobs and synthetic reports; it is an interface example. Actual deployment and scanner test evidence is recorded in [compatibility and testing](https://github.com/quentinmayo/CheckMayo/wiki/Compatibility-and-Testing).*
