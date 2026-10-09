package checkmayo.triage
import rego.v1

default result := {"priority": "normal", "action": "review", "reason": "Human review required"}

result := {"priority": "urgent", "action": "block", "reason": "Critical finding on an internet-facing asset"} if {
    input.finding.severity == "Critical"
    input.asset.internet_facing == true
}
