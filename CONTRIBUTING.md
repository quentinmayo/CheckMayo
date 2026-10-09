# Contributing

Small, testable contributions are welcome. Discuss new scanner execution profiles and connector behavior in an issue before expanding permissions.

Install Python 3.12, development dependencies, and gitleaks 8.30.1+. Configure `git config core.hooksPath .githooks`. Run pytest, Ruff, and `scripts/check-secrets.sh all`. Use `scripts/safe-commit.sh` to validate before staging and committing.

Never commit `.env`, private keys, database files, real scan reports, cloud account details, customer repositories, or private deployment/test logs. Do not weaken secret scans with broad allowlists. Test fixtures should generate temporary credentials in memory.

Scanner packages must follow docs/SCANNERS.md. Submit version changes as new immutable versions. Document engine/rule/database coverage and license requirements; a scanner's presence in the catalog is not proof of comprehensive security coverage.

Use a dedicated branch and PR. Include the concrete behavior change, tests, and limits. Documentation must distinguish implemented, tested, and planned features.
