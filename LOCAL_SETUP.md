# ZeroTrustX Local Setup

This project can run in two modes:

- Docker mode: `docker compose up --build`
- Local mode: PostgreSQL, Redis, FastAPI, Celery, and Vite run directly on the host

Docker support is still the quickest full-stack path. Local mode is useful when you want faster backend/frontend iteration or direct debugger access.

## 1. Requirements

Install:

- Python 3.11+
- Node.js 20+
- npm
- PostgreSQL 15+ or another compatible PostgreSQL version
- Redis-compatible server
- Git, optional but recommended

Useful local tools:

- DBeaver or pgAdmin for PostgreSQL
- RedisInsight for Redis
- Postman or Insomnia for API checks

## 2. PostgreSQL

Create a local database. Use any secure user/password you prefer; the example uses the default local `postgres` user.

PowerShell or terminal:

```bash
createdb dashboard_v3
```

SQL alternative:

```sql
CREATE DATABASE dashboard_v3;
```

The matching local connection strings are:

```env
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/dashboard_v3
DATABASE_URL_SYNC=postgresql+psycopg2://postgres:postgres@localhost:5432/dashboard_v3
```

If your local PostgreSQL password is different, update `backend/.env`.

## 3. Redis

Linux/macOS:

```bash
redis-server
```

Windows options:

- Run Redis inside WSL: `sudo apt install redis-server && redis-server`
- Install Memurai or another Redis-compatible service
- Use Docker only for Redis if desired: `docker run -p 6379:6379 redis:7-alpine`

Local Redis/Celery URLs:

```env
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
CELERY_RESULT_BACKEND=redis://localhost:6379/1
```

## 4. Backend

Copy the local env example:

Windows PowerShell:

```powershell
Copy-Item backend\.env.local.example backend\.env
```

Linux/macOS:

```bash
cp backend/.env.local.example backend/.env
```

Create the virtual environment and install dependencies:

Windows PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
alembic upgrade head
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Linux/macOS:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Convenience scripts:

```powershell
backend\scripts\dev_start.ps1
```

```bash
bash backend/scripts/dev_start.sh
```

Run backend commands from the `backend` directory. Alembic is configured with `prepend_sys_path = .`, and the app import path is `main:app`.

## 5. Celery Worker

Start this in a second terminal after Redis is running:

Windows PowerShell:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
celery -A workers.celery_app worker --loglevel=info
```

Linux/macOS:

```bash
cd backend
source .venv/bin/activate
celery -A workers.celery_app worker --loglevel=info
```

The worker uses `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` when set, otherwise it falls back to `REDIS_URL` for Docker compatibility.

## 6. Frontend

Copy the local env example:

Windows PowerShell:

```powershell
Copy-Item frontend\.env.local.example frontend\.env.local
```

Linux/macOS:

```bash
cp frontend/.env.local.example frontend/.env.local
```

Install and run:

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The frontend supports both:

- Direct Axios calls through `VITE_API_URL=http://localhost:8000`
- Browser calls to `/api/*` through the Vite proxy, forwarded to `VITE_API_PROXY_TARGET=http://localhost:8000`

For example, `http://localhost:5173/api/auth/login` forwards to `http://localhost:8000/auth/login`.

## 7. MITRE ATT&CK Sync

After logging in as an admin, sync MITRE data from the UI or call:

```bash
curl -X POST http://localhost:8000/mitre/sync \
  -H "Authorization: Bearer <token>"
```

Health check:

```bash
curl http://localhost:8000/mitre/health \
  -H "Authorization: Bearer <token>"
```

## 8. Splunk, pfSense, and Reputation Keys

Local mode does not require Splunk or pfSense to start. Leave those values empty until you need the integrations.

Set these in `backend/.env` when available:

```env
SPLUNK_HOST=
SPLUNK_PORT=8089
SPLUNK_USERNAME=
SPLUNK_PASSWORD=
SPLUNK_HEC_TOKEN=
SPLUNK_HEC_URL=

PFSENSE_HOST=
PFSENSE_USERNAME=
PFSENSE_PASSWORD=

ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
```

Secrets are never needed in the frontend env.

## 9. Quick Local Verification

Backend:

```bash
curl http://localhost:8000/docs
```

Frontend proxy:

```bash
curl http://localhost:5173/api/docs
```

Authenticated API checks:

```bash
curl http://localhost:5173/api/mitre/health -H "Authorization: Bearer <token>"
curl http://localhost:5173/api/incidents -H "Authorization: Bearer <token>"
```

Frontend flows:

- Login
- Dashboard
- Investigation
- Incidents
- MITRE Open Mapping
- Integrations

## 10. Troubleshooting

`could not translate host name "postgres"`:

- You are using Docker env values in local mode.
- Copy `backend/.env.local.example` to `backend/.env` and use `localhost`.

`Error 111 connecting to redis:6379`:

- Redis is not running locally.
- Start Redis, WSL Redis, Memurai, or a local Redis container.

Vite `/api` requests go to `fastapi`:

- Copy `frontend/.env.local.example` to `frontend/.env.local`.
- Restart `npm run dev`.

Alembic cannot import project modules:

- Run `alembic upgrade head` from the `backend` directory.

`PowerShell cannot run Activate.ps1`:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Use Docker mode any time you want the known integrated stack:

```bash
docker compose up --build
```
