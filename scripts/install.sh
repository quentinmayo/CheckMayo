#!/usr/bin/env bash
set -euo pipefail
umask 077
INSTALL_DIR="${CHECKMAYO_INSTALL_DIR:-$HOME/checkmayo}"
CHECKMAYO_GIT_REF="${CHECKMAYO_GIT_REF:-main}"
DB_MODE="${CHECKMAYO_DATABASE_MODE:-}"
if [[ "${1:-}" == "--help" ]]; then
  cat <<'HELP'
CheckMayo installer. Requires Docker Engine, Compose v2.24+, Git, and Python 3.
Set CHECKMAYO_INSTALL_DIR, CHECKMAYO_DATABASE_MODE=local|remote,
CHECKMAYO_DATABASE_URL (remote only), CHECKMAYO_ADMIN_EMAIL, PUBLIC_URL.
The installer preserves an existing .env and existing database volumes.
It does not install Docker or change firewall rules.
HELP
  exit 0
fi
for cmd in docker git python3; do command -v "$cmd" >/dev/null || { echo "Install $cmd first."; exit 1; }; done
docker compose version >/dev/null
if [[ -z "$DB_MODE" ]]; then
  if [[ -t 0 ]]; then
    read -r -p 'Where should findings and configuration be stored? [local/remote]: ' DB_MODE
  else
    echo 'Set CHECKMAYO_DATABASE_MODE=local or remote explicitly.' >&2; exit 1
  fi
fi
[[ "$DB_MODE" == local || "$DB_MODE" == remote ]] || { echo 'Choose local or remote.'; exit 1; }
if [[ "$DB_MODE" == remote && -z "${CHECKMAYO_DATABASE_URL:-}" ]]; then
  echo 'Set CHECKMAYO_DATABASE_URL to a PostgreSQL URL.' >&2; exit 1
fi
if [[ ! -d "$INSTALL_DIR/.git" ]]; then
  [[ ! -e "$INSTALL_DIR" || -z "$(ls -A "$INSTALL_DIR")" ]] || { echo 'Install directory must be empty.'; exit 1; }
  git clone --branch "$CHECKMAYO_GIT_REF" --depth 1 https://github.com/quentinmayo/CheckMayo.git "$INSTALL_DIR"
fi
cd "$INSTALL_DIR"
if [[ ! -f .env ]]; then
  export CHECKMAYO_INSTALL_DB_MODE="$DB_MODE"
  python3 - <<'PY'
import base64, os, secrets
from pathlib import Path
values={'PUBLIC_URL':os.getenv('PUBLIC_URL','http://localhost:8000'), 'CHECKMAYO_MODE':'controller',
'CHECKMAYO_SIGNUP':'true', 'CHECKMAYO_ADMIN_EMAIL':os.getenv('CHECKMAYO_ADMIN_EMAIL','admin@example.com'),
'CHECKMAYO_ADMIN_PASSWORD':secrets.token_urlsafe(32),'POSTGRES_PASSWORD':secrets.token_hex(24),
'CHECKMAYO_ENCRYPTION_KEY':base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()}
if os.environ['CHECKMAYO_INSTALL_DB_MODE']=='remote': values['DATABASE_URL']=os.environ['CHECKMAYO_DATABASE_URL']
for value in values.values():
 if '\n' in value or '\r' in value or "'" in value: raise SystemExit('Configuration contains unsupported characters')
Path('.env').write_text(''.join(f"{k}='{v}'\n" for k,v in values.items()))
Path('.env').chmod(0o600)
PY
fi
if [[ "$DB_MODE" == remote ]]; then
  docker compose -f compose.yaml -f deploy/compose.external-db.yaml up --build -d --wait
else
  docker compose up --build -d --wait
fi
echo "CheckMayo is ready. Administrator credentials are in $INSTALL_DIR/.env (mode 600)."
echo 'Open PUBLIC_URL. Back up the PostgreSQL database and the encryption key together.'
