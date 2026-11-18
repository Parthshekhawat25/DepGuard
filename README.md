# DepGuard

DepGuard is an evidence-first dependency risk analyzer for Python projects. It
parses `requirements.txt`, queries the OSV vulnerability database for exact
pinned versions, and keeps unresolved dependencies and lookup failures visible.

## Features

- Safe text-only `requirements.txt` parsing; uploaded packages are never
  executed or installed.
- Exact pinned-version OSV lookups for the PyPI ecosystem.
- Explicit statuses: `vulnerable`, `no_known_match`, `unresolved`, and
  `scan_error`.
- Source-backed advisory IDs, summaries, severity, affected/fixed version data,
  dates, and references when OSV provides them.
- CSV and self-contained HTML scan reports.
- React/Vite dashboard with upload, search, filtering, expandable findings, and
  report downloads.

`no_known_match` means that OSV returned no matching advisory for the exact
queried version. It is not a guarantee that the package is secure.

## Architecture

```text
frontend/                 React + Vite + Tailwind dashboard
backend/app/main.py       FastAPI application and health endpoint
backend/app/routes/       Scan and report HTTP endpoints
backend/app/services/     Parser, OSV client, analyzer, and report generators
backend/tests/            Parser, OSV, analyzer, API, and report tests
```

The scan flow is:

```text
requirements.txt upload
  -> parser
  -> exact-pin analysis
  -> OSV query
  -> normalized scan response
  -> CSV/HTML report
```

## Technology stack

- Backend: Python, FastAPI, Uvicorn, HTTPX, Packaging, Pytest
- Frontend: React, Vite, JavaScript, Tailwind CSS, Lucide React
- Vulnerability source: OSV API
- Persistence: in-memory scan store for the local prototype

## Installation

### Backend

From the repository root in PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

The existing project virtual environment can be reused. No package from an
uploaded requirements file is installed.

### Frontend

```powershell
cd frontend
npm install
```

Optionally copy `frontend/.env.example` to `frontend/.env` and set
`VITE_API_BASE_URL` if the backend is not running at its default URL.

## Running the application

Start the backend in one terminal:

```powershell
cd backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Start the frontend in another terminal:

```powershell
cd frontend
npm run dev
```

Open the Vite URL shown in the terminal, normally
`http://localhost:5173`.

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/health` | Backend health check |
| POST | `/api/v1/scans` | Upload a `.txt` requirements file using multipart field `file` |
| GET | `/api/v1/scans/{scan_id}` | Retrieve a completed scan |
| GET | `/api/v1/scans/{scan_id}/report.csv` | Download the CSV report |
| GET | `/api/v1/scans/{scan_id}/report.html` | Download the HTML report |

The upload endpoint rejects empty files, invalid UTF-8, unsupported extensions,
and files larger than 1 MB.

## Testing

Run the backend suite:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest -q
```

Build the frontend:

```powershell
cd frontend
npm run build
```

The automated OSV and API tests use mocked HTTP/client responses and do not
depend on the live OSV service.

## Known limitations

- Only Python `requirements.txt` files are supported.
- Only exact `package==version` entries can be queried. Ranges and unpinned
  packages remain `unresolved`; DepGuard does not guess installed versions.
- Scan history is stored in memory and is lost when the backend restarts.
- OSV availability and advisory coverage affect scan results.
- Reports are CSV and HTML; PDF generation is not included.
- The dashboard's total scan count is for the current browser session.
- Authentication, multi-user storage, transitive dependency resolution, and
  GitHub/LLM integrations are not implemented.
