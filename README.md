# ZeroTrustX SOC Dashboard

ZeroTrustX is a demonstration Security Operations Center (SOC) platform built around Zero Trust security principles. Developed as a cybersecurity showcase and learning project, it simulates key SOC workflows including threat detection, incident investigation, asset management, threat intelligence enrichment, and automated response actions.

The platform combines a React/Vite frontend with a FastAPI backend to provide a centralized environment where security analysts can monitor alerts, investigate incidents, analyze threats, and visualize security operations through a modern dashboard experience.

Key Features
SOC Dashboard & Security Monitoring
Incident Detection & Investigation Workflows
MITRE ATT&CK Mapping & Analysis
Asset Inventory Management
Threat Intelligence & IP Reputation Analysis
Firewall Response & Containment Actions
Risk Assessment & Prioritization
Role-Based Access Control (RBAC)
Splunk SIEM Integration
pfSense Firewall Integration
Docker-Based Deployment

Note: ZeroTrustX is a demonstration and educational project created to showcase SOC operations, cybersecurity workflows, and security platform development concepts. It is not intended for production deployment without additional security review, testing, and hardening.

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
