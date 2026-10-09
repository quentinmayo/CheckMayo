## Read and triage findings

Supported Gitleaks, Semgrep, Trivy, and SARIF reports are normalized into **Workspace → Findings**. CheckMayo deduplicates findings within the workspace using repository, scanner, rule, path, and line. The original report remains downloadable from the scan.

Use **Triage** to record `open`, `accepted_risk`, `false_positive`, or `resolved`. Triage changes create audit events. Operators, administrators, and owners can triage; viewers can read workspace findings and reports.

Unknown or malformed reports are retained for download and are not evidence that a scan found no vulnerabilities. Other formats can be imported into a separately deployed DefectDojo through the [integration bridge](https://github.com/quentinmayo/CheckMayo/wiki/API-and-Integrations).

![Findings with sample data](https://raw.githubusercontent.com/quentinmayo/CheckMayo/main/docs/assets/screenshots/findings.png)

*Example findings are synthetic and are not a security assessment of the repository.*

## Preview and save OPA policies

An owner or administrator opens **Settings & connections → OPA triage policy**. Policies use `package checkmayo.triage` and expose `result`. The bundled [example policy](https://github.com/quentinmayo/CheckMayo/blob/main/policies/triage.rego) prioritizes a critical finding on an internet-facing asset:

```rego
package checkmayo.triage
import rego.v1

default result := {"priority": "normal", "action": "review"}

result := {"priority": "urgent", "action": "block"} if {
    input.finding.severity == "Critical"
    input.asset.internet_facing == true
}
```

Preview it with:

```json
{"finding": {"severity": "Critical"}, "asset": {"internet_facing": true}}
```

Select **Save this policy after a successful preview** to persist it. The enabled checkbox controls whether it is available for finding evaluation. **Risk policy** on a finding uses that finding's normalized fields; the API also accepts asset context through `POST /api/workspaces/WORKSPACE_ID/findings/FINDING_ID/policy`.

OPA runs with restricted capabilities and bounded resources. Network and environment builtins are denied. These results support human risk decisions; the preview does not automatically block PRs or mark findings safe. An `action: block` value is a policy recommendation.

![A real OPA policy preview with example input](https://raw.githubusercontent.com/quentinmayo/CheckMayo/main/docs/assets/screenshots/risk-policy-preview.png)

## Optional ticket summaries

AI is disabled by default. Configure your Ollama URL and model in **Settings & connections → ollama**, then enable optional AI summaries. **Summarize ticket** sends only the ticket text you explicitly submit to that endpoint.

The default stack does not run Ollama or download models. Review generated summaries before use. External Ollama model validation remains outstanding; see [compatibility and testing](https://github.com/quentinmayo/CheckMayo/wiki/Compatibility-and-Testing).
