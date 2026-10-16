"""PostgreSQL access layer for the AiShield API.

Configuration (env vars, all optional):
    DATABASE_URL   postgresql://user:pass@host:port/dbname   (preferred)
    PGHOST, PGPORT, PGUSER, PGPASSWORD, PGNAME               (fallback)

Default: postgresql://aishield:aishield@localhost:5432/aishield
"""
import os
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Json

BASE = Path(__file__).resolve().parent
SCHEMA_SQL = BASE / "schema.sql"

DEFAULT_URL = "postgresql://aishield:aishield@localhost:5432/aishield"


def connection_url():
    return os.environ.get("DATABASE_URL") or DEFAULT_URL


def _connect():
    return psycopg.connect(connection_url(), row_factory=dict_row, connect_timeout=5)


@contextmanager
def get_conn():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create tables/indexes if they do not exist."""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(SCHEMA_SQL.read_text(encoding="utf-8"))


def ping():
    """True if the database is reachable."""
    try:
        with get_conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
        return True
    except Exception:
        return False


def insert_check(command, verdict, status, note, findings):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO checks (command, verdict, status, note, findings)
            VALUES (%s, %s, %s, %s, %s::jsonb)
            RETURNING id, command, verdict, status, note, findings, created_at
            """,
            (command, verdict, status, note or "", Json(findings or [])),
        )
        return _row_to_entry(cur.fetchone())


def list_checks(limit=100):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, command, verdict, status, note, findings, created_at
            FROM checks
            ORDER BY id DESC
            LIMIT %s
            """,
            (limit,),
        )
        return [_row_to_entry(r) for r in cur.fetchall()]


def count_by_status():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT status, COUNT(*) AS n FROM checks GROUP BY status"
        )
        counts = {"allow": 0, "review": 0, "disallow": 0, "error": 0}
        total = 0
        for row in cur.fetchall():
            counts[row["status"]] = row["n"]
            total += row["n"]
        return {"total": total, **counts}


def clear_checks():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM checks")
        return cur.rowcount


def list_domains():
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, domain, created_at FROM domains ORDER BY domain"
        )
        return [
            {
                "id": r["id"],
                "domain": r["domain"],
                "created_at": r["created_at"].isoformat(timespec="seconds") if r["created_at"] else None,
            }
            for r in cur.fetchall()
        ]


def add_domain(domain):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO domains (domain) VALUES (%s)
            ON CONFLICT (domain) DO UPDATE SET domain = EXCLUDED.domain
            RETURNING id, domain, created_at
            """,
            (domain,),
        )
        r = cur.fetchone()
        return {
            "id": r["id"],
            "domain": r["domain"],
            "created_at": r["created_at"].isoformat(timespec="seconds") if r["created_at"] else None,
        }


def remove_domain(domain):
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM domains WHERE domain = %s RETURNING id", (domain,))
        r = cur.fetchone()
        return r["id"] if r else None


def _row_to_entry(row):
    if row is None:
        return None
    return {
        "id": row["id"],
        "command": row["command"],
        "verdict": row["verdict"],
        "status": row["status"],
        "note": row["note"],
        "findings": row["findings"] or [],
        "time": row["created_at"].isoformat(timespec="seconds") if row["created_at"] else None,
    }
