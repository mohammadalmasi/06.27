# 06.27 — Web Vulnerability Scanner (Thesis Project)

A web app that scans code for common web vulnerabilities using **custom static scanners** (regex/AST-style checks) and an **optional ML endpoint** (when ML assets are present).

## Project structure

- `backend/`: Flask API (scanners + report generation)
- `frontend/`: React (Create React App) UI
- `report/`: thesis/report artifacts (optional)

## Prerequisites

- **Python**: 3.10+ (recommended: 3.10 to match `backend/app.yaml`)
- **Node.js**: 18+ (frontend build on GCP uses Node 18; frontend runtime uses Node 20 in `frontend/app.yaml`)

## Quickstart (local development)

### 1) Clone

```bash
git clone https://github.com/mohammadalmasi/06.27.git
cd 06.27
```

### 2) Backend (Flask API)

Create a virtualenv and install pinned dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the backend (default: `http://localhost:5001`):

```bash
python backend/main.py
```

Health check:

```bash
curl http://localhost:5001/api/health
```

### 3) Frontend (React UI)

In a separate terminal:

```bash
cd frontend
npm ci
npm start
```

Open `http://localhost:3000`.

#### Configure the backend URL (optional)

By default, the frontend uses `http://localhost:5001` in development. To override:

```bash
cp frontend/.env.example frontend/.env.local
```

Then edit `frontend/.env.local`:

```bash
REACT_APP_API_BASE_URL=http://localhost:5001
```

## Backend API (main endpoints)

- `GET /api/health`
- `GET /api/scanner-config`
- `POST /api/scan-xss`
- `POST /api/scan-sql-injection`
- `POST /api/scan-command-injection`
- `POST /api/scan-csrf`
- `POST /api/generate-xss-report`
- `POST /api/generate-sql-injection-report`
- `POST /api/generate-command-injection-report`
- `POST /api/generate-csrf-report`
- `POST /api/scan-ml` (optional; requires ML analyzer/assets)

## ML endpoint note

`POST /api/scan-ml` runs an external analyzer script at `backend/ml/lib/analyze.py`.

- If the ML analyzer + model assets are **not** present in your checkout, the endpoint returns **HTTP 501** with a JSON error describing what’s missing.
- This keeps the repo reproducible even when ML assets are private / too large to ship.

## Deployment (Google App Engine)

This repo includes:

- `backend/app.yaml` (Python runtime + Gunicorn entrypoint)
- `frontend/app.yaml` (static serving for CRA build output)

### Option A) One-shot deploy script

```bash
bash deploy.sh
```

Notes:
- It deploys the backend first and then builds the frontend with `REACT_APP_API_BASE_URL` set to the deployed backend URL.
- You must have the Google Cloud CLI installed and be logged in.

### Option B) Cloud Build (`cloudbuild.yaml`)

```bash
gcloud builds submit --config cloudbuild.yaml .
```

## Reproducibility notes

- **Python dependencies** are pinned in `backend/requirements.txt` and referenced by the root `requirements.txt`.
- **Node dependencies** are locked by `frontend/package-lock.json` (use `npm ci`).
- Don’t commit local virtualenvs (`.venv/`, `backend/mlvenv/`) or `.env*` files (ignored in `.gitignore`).
