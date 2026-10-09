# Scanner packages

A package is an immutable Compose document plus name, version, category, description, report filename and DefectDojo scan type. The registry calculates its SHA-256. Private packages are visible only to workspace members; community submissions require site administrator review before public download.

```yaml
services:
  scanner:
    image: your-registry.example.com/security/your-scanner:1.0.0
    user: '65532:65532'
    command: ['scan', '/src', '--output', '/reports/report.json']
    volumes:
      - '${SOURCE_DIR}:/src:ro'
      - '${REPORT_DIR}:/reports:rw'
    network_mode: none
    read_only: true
    cap_drop: [ALL]
    security_opt: ['no-new-privileges:true']
```

Only one service named `scanner` is supported. Use an explicit image tag or digest; prefer digests for your reviewed production packages. The SHA-256 identifies the Compose package, **not the content of a mutable image tag**. Local runner trust does not replace image review or image signing.

The runner enforces 1 CPU, 512 MiB RAM, 128 processes and a bounded `/tmp`. It overrides requested resource values. Only source and report mounts are allowed. Reports must be regular UTF-8 files under `/reports`, at most 5 MB. Scanner output goes to this file, not to controller logs.

A produced report means execution completed; many scanners return a nonzero status when they find vulnerabilities. Completion never means a security check passed. Do not treat unknown report formats or failed policies as clean findings.

Community starter packages:

- Gitleaks: scans source directories, redacts reported secrets.
- Semgrep: an offline Python `eval` demonstration rule, not a broad rule pack.
- Trivy: offline misconfiguration checks. Full dependency vulnerability scanning needs a reviewed image with preloaded scanner databases.

For Nexus, configure a mirror prefix that preserves the scanner's image path, e.g. `nexus.example.com:5000/mirror`. The runner prefixes that value to the package image. Configure Docker registry credentials locally on the dedicated runner using `docker login`; credentials never belong in a package. `CHECKMAYO_DOCKER_CONFIG` may select a dedicated Docker configuration directory.

The workspace HTTP proxy controls image-pull/Git process environment. Scanner containers have no network even when a proxy is set. Proxy support does not grant scanner egress. Online scanning is a future separately reviewed execution profile.

Continue with [getting started](https://github.com/quentinmayo/CheckMayo/wiki/Getting-Started), [authentication and roles](https://github.com/quentinmayo/CheckMayo/wiki/Authentication-and-Roles), or [compatibility and testing](https://github.com/quentinmayo/CheckMayo/wiki/Compatibility-and-Testing).
