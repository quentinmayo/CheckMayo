# Maintaining the GitHub wiki

The public [CheckMayo wiki](https://github.com/quentinmayo/CheckMayo/wiki) provides a guided entry point to installation, deployment, scanner packaging, runner management, identity, integrations, and validation.

Its Markdown sources live in [docs/wiki](wiki/Home.md). Change these files through the main repository so documentation receives the same review and secret scans as code. Screenshot assets live in [docs/assets/screenshots](assets/screenshots); the wiki references the public upstream assets instead of copying binaries into its own Git history.

## Publish reviewed changes

Install Gitleaks 8.30.1+ and authenticate Git for `quentinmayo/CheckMayo.wiki.git`. From the repository root:

```bash
bash scripts/check-secrets.sh all
bash scripts/safe-commit.sh "Update the CheckMayo wiki sources"
git push origin main
bash scripts/publish-wiki.sh
```

The publishing script clones the separate wiki repository into a temporary directory, copies the managed Markdown pages, scans every eligible file before staging, scans the staged snapshot before committing, and pushes the wiki. It preserves unrelated wiki files and removes the temporary checkout afterward. If the sources are unchanged, it creates no commit.

GitHub must have the wiki enabled and an initial Home page before its Git repository can be cloned. The initial Home page has already been created for CheckMayo. Publishing requires repository write access; it does not change wiki access permissions.

Publish assets to the main repository before wiki pages that reference them. Keep screenshots free of credentials and private data. The current gallery records its demo-data provenance and cleanup in [SCREENSHOTS.md](SCREENSHOTS.md).

## Keep guides consistent

When changing a feature, update its wiki page and the corresponding guide in `docs/`. Match the implemented UI and API, identify preview limits, and retain the distinction between executed tests and reference deployment guidance. The compatibility/testing page mirrors the coverage and validation documents; refresh it when their evidence changes.

Use absolute upstream links for repository files and wiki pages. Keep `_Sidebar.md` and `_Footer.md` aligned with the pages you publish. The wiki belongs to the public personal-account repository; the private organization mirror receives the sources through its normal Git synchronization.
