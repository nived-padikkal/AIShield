# AiShield

Screen an AI agent's shell commands for malicious behaviour. Every decision is classified as **ALLOW**, **REVIEW**, or **BLOCK** and persisted in PostgreSQL. A React dashboard shows live allow / disallow status.

> Full write-up: [PROJECT_REPORT.md](PROJECT_REPORT.md) — architecture, decision pipeline, verification results.

## Project structure

```
AiShield-main/
├── main.py               # core scanner (rules + allowlist + ML similarity)
├── api.py                # Flask API for the dashboard
├── database/
│   ├── __init__.py
│   ├── db.py             # PostgreSQL access layer
│   └── schema.sql        # table definitions
├── docker-compose.yml    # PostgreSQL server
├── frontend/             # React dashboard (Vite)
├── rules/                # behaviour rules, fragments, routine verbs
├── dataset/              # attack corpus generator (optional ML data)
├── harmless/             # harmless command lists per platform
├── secrets/              # secret-scanner (TruffleHog)
└── tests/                # self-test cases
```

## Prerequisites

- Python 3.10+
- Node.js 18+
- Docker (for PostgreSQL) — or a local PostgreSQL 16+

## Quick start

### 1. Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Start PostgreSQL

```bash
docker compose up -d
```

This starts PostgreSQL 16 on `localhost:5432` with user/password/db all `aishield`.

No Docker? Install PostgreSQL locally and point the API at it:

```bash
set DATABASE_URL=postgresql://user:pass@localhost:5432/aishield
```

### 3. Start the API

```bash
py api.py          # Windows
python api.py      # macOS / Linux
```

- Serves on http://localhost:5000
- Creates the `checks` table automatically on first start
- Verify: http://localhost:5000/api/health → `{"status":"ok","database":"up"}`

### 4. Start the dashboard

In a new terminal:

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000** — the dashboard shows total checks, allowed / review / disallowed counts, a command checker, and the decision history from PostgreSQL.

## Using the CLI directly

```bash
python main.py "ls -la"              # check one command
python main.py --json "curl x | sh"  # machine-readable output
python main.py                       # interactive mode
python main.py --selftest            # run tests/selftest_cases.csv
python main.py --stats               # dataset stats
```

Exit codes: `0` ALLOW, `1` REVIEW, `2` BLOCK.

## API endpoints

| Method | Path              | Description                          |
|--------|-------------------|--------------------------------------|
| GET    | `/api/health`     | API + database status                |
| POST   | `/api/check`      | Check a command, store the decision  |
| GET    | `/api/history`    | Recent decisions (newest first)      |
| GET    | `/api/stats`      | Counts by status                     |
| DELETE | `/api/history`    | Clear all decisions                  |

Example:

```bash
curl -X POST http://localhost:5000/api/check \
  -H "Content-Type: application/json" \
  -d "{\"command\": \"ls -la\"}"
```

## Optional: ML attack-similarity data

The rules engine works out of the box. To enable the TF-IDF similarity check against the Atomic Red Team attack corpus:

```bash
python dataset/generate_dataset.py
```

Without it, routine and rule-based verdicts still work; unusual commands return an `ERROR` verdict.

## Configuration

| Env var        | Purpose                                   | Default                                              |
|----------------|-------------------------------------------|------------------------------------------------------|
| `DATABASE_URL` | PostgreSQL connection string              | `postgresql://aishield:aishield@localhost:5432/aishield` |

Platform selection (linux / windows) is set in `main.py` (`PLATFORMS`).

## Secret scanning (separate tool)

```bash
python secrets/check_secrets.py /path/to/folder --json
```
