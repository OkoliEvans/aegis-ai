CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS watched_addresses (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address         TEXT NOT NULL UNIQUE,
    label           TEXT,
    owner_address   TEXT NOT NULL,
    is_poisoned     BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score      INTEGER NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_activity   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approval_records (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner               TEXT NOT NULL,
    spender             TEXT NOT NULL,
    token_denom         TEXT NOT NULL,
    amount              TEXT NOT NULL,
    granted_at_height   BIGINT NOT NULL,
    revoked             BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score          INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS risk_events (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address     TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    severity    TEXT NOT NULL,
    tx_hash     TEXT,
    payload     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tx_patterns (
    address             TEXT PRIMARY KEY,
    avg_value_uinit     BIGINT NOT NULL DEFAULT 0,
    typical_recipients  JSONB NOT NULL DEFAULT '[]'::jsonb,
    typical_hour_utc    INTEGER NOT NULL DEFAULT 12,
    sample_count        INTEGER NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS registered_users (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    address           TEXT NOT NULL UNIQUE,
    telegram_chat_id  BIGINT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_events_address ON risk_events(address);
CREATE INDEX IF NOT EXISTS idx_risk_events_created ON risk_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_owner ON approval_records(owner);
