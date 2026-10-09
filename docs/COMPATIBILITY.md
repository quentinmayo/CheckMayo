# Scanner and integration compatibility

CheckMayo separates scanner execution from report ingestion.

| Layer | Release behavior | Coverage limit |
| --- | --- | --- |
| Scanner packages | Reviewed single-service Docker Compose YAML | Offline tools under the documented execution contract |
| Native findings | Gitleaks JSON, Semgrep JSON, Trivy JSON, SARIF | Bounded normalization and deduplication; original report retained |
| DefectDojo bridge | Discovers `/api/v2/test_types/`; sends reports to `/api/v2/import-scan/` | Uses parsers installed in your DefectDojo instance |
| GitHub App | Signed PR events, installation/repository binding, replay guard, repository-scoped installation tokens | Same-repository PRs; fork PRs require explicit manual queueing |
| OIDC and LDAPS | Optional administrator-configured sign-in providers | No SAML or automatic enterprise group synchronization |
| AI | Explicit ticket summarization via your Ollama service | Disabled by default; no automatic remediation |

## DefectDojo support

The bridge accepts any scan-type name exposed by the configured DefectDojo instance and delegates parsing to it. CheckMayo does not claim that all DefectDojo tools can execute in its runner, or that every parser has been independently tested.

Use the Swagger route `GET /api/workspaces/{id}/defectdojo/scan-types` to inspect authoritative coverage for your installation. Import with `POST /api/workspaces/{id}/defectdojo/import?scan_type=...` and a multipart `report` file. Scanner engines and native connectors that require credentials, outbound internet, a browser, target access, or multiple services need reviewed execution extensions.

Upstream references: [DefectDojo repository](https://github.com/DefectDojo/django-DefectDojo), [API documentation](https://docs.defectdojo.com/automation/api/api-v2-docs/). DefectDojo remains a separately deployed, separately licensed service.

## ZIP packages

Compose YAML is sufficient for the initial registry. Arbitrary ZIP uploads are disabled. A future package-bundle format should include a manifest, Compose document, vendored rules, license metadata, per-file SHA-256 values, expansion limits, and traversal/symlink checks. It must not enable uploading secrets or unreviewed Docker build contexts.
