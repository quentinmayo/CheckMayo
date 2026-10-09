# API and integrations

Swagger UI is at `/docs`, OpenAPI at `/openapi.json`. Browser sessions use secure HTTP-only cookies; mutations require Origin equal to PUBLIC_URL. API clients use `Authorization: Bearer <workspace-key>`. Keys expire after 90 days and can be revoked in the UI.

Roles: owners/admins manage keys, runners, members, integrations and settings; operators publish packages, queue scans and triage findings; viewers read workspace resources. Only site administrator browser sessions approve community packages. API keys remain workspace-scoped even if their issuing user belongs to several workspaces.

## GitHub App

Create a GitHub App on your personal account or organization. Set its webhook URL to `https://your-controller/api/hooks/github/{workspace_id}`. Generate a random webhook secret of at least 32 characters. Subscribe to pull requests. Grant repository **Contents: read**, and install it only on repositories you intend to scan. Checks: write will be needed for future PR check publication; this release does not request it or publish public finding details.

Configure the encrypted `github` integration in Workspace → Settings & connections with app ID, installation ID, PEM private key, webhook secret, `owner/repo`, package ID and runner label. The controller binds every event to that installation and repository, rejects invalid signatures, deduplicates delivery IDs, and queues immutable commit SHAs. Cross-repository fork events are ignored; operators can manually queue a reviewed public fork on their own runner.

The runner can request a short-lived installation token only for its active job, and the controller restricts that token to repository Contents: read. Private reports stay in your controller rather than public GitHub Actions logs or publicly visible checks. Public repository security can have public logs/metadata; always review platform visibility settings.

## DefectDojo

Configure `defectdojo` with `url`, API `token` and numeric `engagement`. Scan-type discovery and multipart import are in Swagger. Secrets are encrypted; status endpoints do not expose them. Remote calls refuse redirects so credentials cannot be forwarded to another host. Self-hosted administrators may configure internal service endpoints; the hosted registry disables all such connectors.

## OPA triage

Policies must use `package checkmayo.triage` and expose `result`. Preview a policy at `/api/workspaces/{id}/policies/evaluate`, save it with `PUT /api/workspaces/{id}/policy`, and evaluate a finding with `POST /api/workspaces/{id}/findings/{finding_id}/policy` plus `{ "asset": { "internet_facing": true } }`.

This is risk decision support. Policy results are suggestions; the preview does not automatically block PRs or mark findings safe. Network and runtime/environment builtins are denied; policy output, elapsed time and CPU use are bounded. An unavailable evaluator returns an explicit error.

## Optional Ollama

Configure `ollama` with `url` and `model`, then enable AI in workspace settings. `/api/workspaces/{id}/ai/summarize` sends only explicitly submitted ticket text. Review output before use. The default Compose stack does not start Ollama or download models; point to your existing service or deploy one locally under its own resource budget.

## SSO

Set OIDC discovery URL, client ID and client secret in your controller's environment. Register `PUBLIC_URL/api/auth/oidc/callback` at the provider. Authorization-code flow validates state/nonce and requires verified email. Identities are bound to issuer+subject; they do not silently take over a local account by matching email.

For LDAP, set `LDAP_URL=ldaps://...`, service bind DN/password, base DN, optional filter and CA path. LDAPS certificates are verified. UI login offers directory sign-in when configured. These are deployment-administrator settings in this release; credential rotation, group sync and managed identity-provider UI are roadmap work.

The Compose stack forwards OIDC and LDAP variables from its private `.env`. For a private directory CA, mount its public CA file read-only with a local override and set `LDAP_CA_FILE=/run/checkmayo/directory-ca.crt`:

```yaml
services:
  app:
    volumes:
      - /private/directory-ca.crt:/run/checkmayo/directory-ca.crt:ro
```

Keep bind passwords in private configuration. A directory user starts with a personal workspace and receives organization permissions only when that workspace's owner or administrator adds them. Directory administrator status does not grant CheckMayo site administrator status.

Run reproducible live LDAPS tests with Docker and the development dependencies:

```bash
CHECKMAYO_TEST_LDAP=1 .venv/bin/pytest tests/test_ldap_live.py -q
```

The test creates an isolated LLDAP directory, short-lived private CA, loopback-only ports and disposable users. It verifies certificate checks, bad credentials, escaped filters, identity separation, and the owner/admin/operator/viewer permission matrix; its finalizer removes the directory container and generated credentials.
