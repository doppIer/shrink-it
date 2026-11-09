CREATE TABLE IF NOT EXISTS links (
    id                   BIGSERIAL PRIMARY KEY,
    code                 TEXT        NOT NULL UNIQUE,
    target_url           TEXT        NOT NULL,
    fallback_url         TEXT,
    rules                JSONB       NOT NULL DEFAULT '{}'::jsonb,
    safety_status        TEXT        NOT NULL DEFAULT 'unknown', -- safe | flagged | unknown
    safety_reason        TEXT,
    safety_warnings      JSONB       NOT NULL DEFAULT '[]'::jsonb,
    health_status        TEXT        NOT NULL DEFAULT 'unknown', -- healthy | broken | unknown
    last_status_code     INT,
    consecutive_failures INT         NOT NULL DEFAULT 0,
    last_checked_at      TIMESTAMPTZ,
    expires_at           TIMESTAMPTZ,
    disabled             BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS links_due_check_idx ON links (last_checked_at NULLS FIRST) WHERE NOT disabled;

CREATE TABLE IF NOT EXISTS clicks (
    id            BIGSERIAL PRIMARY KEY,
    link_id       BIGINT      NOT NULL REFERENCES links(id) ON DELETE CASCADE,
    clicked_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    device        TEXT        NOT NULL,
    country       TEXT,
    referrer_host TEXT,
    target_url    TEXT        NOT NULL,
    reason        TEXT        NOT NULL
);

CREATE INDEX IF NOT EXISTS clicks_link_time_idx ON clicks (link_id, clicked_at);
