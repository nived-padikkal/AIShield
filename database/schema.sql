-- AiShield PostgreSQL schema
-- Applied automatically by db.init_db() on API startup.

CREATE TABLE IF NOT EXISTS checks (
    id         BIGSERIAL PRIMARY KEY,
    command    TEXT NOT NULL,
    verdict    TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('allow', 'review', 'disallow', 'error')),
    note       TEXT NOT NULL DEFAULT '',
    findings   JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_checks_created_at ON checks (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_checks_status     ON checks (status);
