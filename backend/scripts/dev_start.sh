#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

if [ ! -f ".env" ] && [ -f ".env.local.example" ]; then
  cp .env.local.example .env
  echo "Created backend/.env from .env.local.example. Review credentials before production use."
fi

alembic upgrade head
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
