Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BackendRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $BackendRoot

if (-not (Test-Path ".venv")) {
  python -m venv .venv
}

& ".\.venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip
pip install -r requirements.txt

if (-not (Test-Path ".env") -and (Test-Path ".env.local.example")) {
  Copy-Item ".env.local.example" ".env"
  Write-Host "Created backend/.env from .env.local.example. Review credentials before production use." -ForegroundColor Yellow
}

alembic upgrade head
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
