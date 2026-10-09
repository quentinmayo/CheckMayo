## Local accounts and workspaces

Local accounts use hashed passwords and HTTP-only browser sessions. Sessions last 12 hours. Your deployment can enable or disable signup with `CHECKMAYO_SIGNUP`. Set the exact HTTPS `PUBLIC_URL` so secure cookies and mutation-origin checks match your ingress.

Users can create personal and organization workspaces. A person must register before an owner or administrator adds them through **Settings & connections → Add member**. A new directory user receives a personal workspace; organization membership is explicit.

| Permission | Owner | Admin | Operator | Viewer |
| --- | --- | --- | --- | --- |
| Read workspace scans, findings, packages, and private reports | Yes | Yes | Yes | Yes |
| Publish packages, queue scans, and triage findings | Yes | Yes | Yes | No |
| Manage settings, runners, API keys, and members | Yes | Yes | No | No |
| Access another unrelated workspace or its reports | No | No | No | No |

Community package approval is a separate **site administrator** browser-session permission. Being a workspace owner or directory administrator does not grant it. Workspace API keys remain scoped to one workspace and cannot approve community submissions.

## OIDC single sign-on

The deployment administrator supplies these private runtime variables:

```text
OIDC_DISCOVERY_URL=https://identity.example.com/.well-known/openid-configuration
OIDC_CLIENT_ID=<your-client-id>
OIDC_CLIENT_SECRET=<your-client-secret>
```

Register `PUBLIC_URL/api/auth/oidc/callback` as the redirect URI at your provider, then use **Single sign-on** on the login form. The authorization-code flow checks state and nonce and requires verified email. External identities bind to issuer and subject; an email match does not silently take over an existing local account.

OIDC is implemented, but a live external-provider end-to-end test remains outstanding. SAML and automatic enterprise group synchronization are not available in the preview.

## Verified LDAPS

Configure the controller's private runtime environment:

```text
LDAP_URL=ldaps://directory.example.com:636
LDAP_BIND_DN=cn=checkmayo,ou=service-accounts,dc=example,dc=com
LDAP_BIND_PASSWORD=<your-service-bind-password>
LDAP_BASE_DN=ou=people,dc=example,dc=com
LDAP_USER_FILTER=(uid={username})
LDAP_CA_FILE=/run/checkmayo/directory-ca.crt
```

Mount your private directory's **public CA certificate** read-only at `LDAP_CA_FILE`. The bind password stays in private deployment configuration. Compose forwards these variables from `.env`; its [example environment](https://github.com/quentinmayo/CheckMayo/blob/main/.env.example) documents the names.

```yaml
services:
  app:
    volumes:
      - /private/directory-ca.crt:/run/checkmayo/directory-ca.crt:ro
```

Use **Directory login** when enabled. LDAPS certificates are verified, plaintext LDAP is rejected, and usernames are escaped in directory search filters. Directory administrator privileges do not grant CheckMayo site administration. Add the user to an organization workspace separately with the intended role.

## Reproduce the access checks

With Docker and the development dependencies installed:

```bash
CHECKMAYO_TEST_LDAP=1 .venv/bin/pytest tests/test_ldap_live.py -q --tb=short
```

The tests create an isolated LLDAP directory, short-lived CA, loopback ports, and disposable users. They verify valid login, bad credentials, escaped filters, identity separation, untrusted-certificate and plaintext-LDAP rejection, all four workspace roles, and denial of unrelated workspace/report access. Finalizers remove the directory container and generated credentials.

Five live-directory tests passed in the recorded preview validation. Both public and private-mirror CI execute them. Read [compatibility and testing](https://github.com/quentinmayo/CheckMayo/wiki/Compatibility-and-Testing) for the full evidence and its limits.
