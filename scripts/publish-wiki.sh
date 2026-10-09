#!/usr/bin/env bash
set -euo pipefail

CHECKMAYO_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v gitleaks >/dev/null || { echo 'Install gitleaks 8.30.1+ before publishing.' >&2; exit 1; }
CHECKMAYO_WIKI_TEMP="$(mktemp -d)"
trap 'rm -rf "$CHECKMAYO_WIKI_TEMP"' EXIT

git clone --quiet https://github.com/quentinmayo/CheckMayo.wiki.git "$CHECKMAYO_WIKI_TEMP/wiki"
cp "$CHECKMAYO_REPO_ROOT"/docs/wiki/*.md "$CHECKMAYO_WIKI_TEMP/wiki/"
cd "$CHECKMAYO_WIKI_TEMP/wiki"
if [[ -z "$(git status --porcelain)" ]]; then
  echo 'Wiki already matches the reviewed sources.'
  exit 0
fi

git config user.name "$(git -C "$CHECKMAYO_REPO_ROOT" config user.name)"
git config user.email "$(git -C "$CHECKMAYO_REPO_ROOT" config user.email)"
bash "$CHECKMAYO_REPO_ROOT/scripts/check-secrets.sh" all
git add --all
bash "$CHECKMAYO_REPO_ROOT/scripts/check-secrets.sh" staged
git commit -m 'Publish reviewed CheckMayo wiki guides'
git push origin HEAD
