# Static Analysis vs. Machine Learning: A Study of Source Code Vulnerability Detection Models

**A Study of Source Code Vulnerability VS. Detection Models**

Repository for the thesis project **06.27**: a web app that scans Python source for common web vulnerabilities (including **SQL injection**, **XSS**, **command injection**, and **CSRF**) using **custom static scanners** (regex/AST-style checks) and **optional ML detectors** (Keras models under `backend/models/` when TensorFlow and weights are present).

## Project structure

- `backend/`: Flask API (static + ML scanners, results handling)
- `frontend/`: React (Create React App) UI

## Prerequisites

- **Python**: 3.10+ (see `backend/app.yaml` for a known-good runtime pin)
- **Node.js**: 18+ (compatible with the CRA toolchain in `frontend/`)

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
pip install -r backend/requirements.txt
```

Run the backend (default: `http://localhost:5001`):

```bash
python backend/main.py
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

Static (always available if the backend runs):

- `POST /api/static-sql-injection`
- `POST /api/static-xss`
- `POST /api/static-command-injection`
- `POST /api/static-csrf`

ML (require TensorFlow, gensim as needed, and the corresponding `.h5` / Word2Vec files under `backend/models/`):

- `POST /api/ml-sql-injection`
- `POST /api/ml-xss`
- `POST /api/ml-command-injection`
- `POST /api/ml-csrf`

## ML scanners note

Each `POST /api/ml-*` route uses the matching detector in `backend/scanners/**/ml_*_scanner.py`, which loads Keras models from `backend/models/`. If TensorFlow is not installed or expected model files are missing, scans **fail with an error** (for example missing `bidirectional_LSTM_model_sql.h5` for SQL). Omitting large model files keeps the repository smaller; add them locally when you want ML results.

## Reproducibility notes

- **Python dependencies** are pinned in `backend/requirements.txt`.
- **Node dependencies** are locked by `frontend/package-lock.json` (use `npm ci`).
- Don’t commit local virtualenvs (`.venv/`, `backend/mlvenv/`) or `.env*` files (ignored in `.gitignore`).
