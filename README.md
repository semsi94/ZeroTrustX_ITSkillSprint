# ZeroTrustX SOC Dashboard

ZeroTrustX is a SOC analyst dashboard with a React/Vite frontend and FastAPI backend. It can run with Docker Compose or directly on the host machine.

## Docker Mode

Docker remains the fastest full-stack startup path:

```bash
docker compose up --build
```

Services:

- Frontend: http://localhost:5173
- Backend API/docs: http://localhost:8000/docs
- PostgreSQL: localhost:5432
- Redis: localhost:6379

Docker env defaults use service hostnames such as `postgres`, `redis`, and `fastapi`.

## Local Mode

Local mode runs each service directly on your machine:

- PostgreSQL on `localhost:5432`
- Redis on `localhost:6379`
- FastAPI through `uvicorn main:app`
- Celery through `celery -A workers.celery_app worker`
- Frontend through `npm run dev`

Start here:

[LOCAL_SETUP.md](LOCAL_SETUP.md)

Minimum command outline:

```bash
cp backend/.env.local.example backend/.env
cp frontend/.env.local.example frontend/.env.local

cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

In another terminal:

```bash
cd backend
source .venv/bin/activate
celery -A workers.celery_app worker --loglevel=info
```

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Windows PowerShell equivalents are documented in [LOCAL_SETUP.md](LOCAL_SETUP.md).
