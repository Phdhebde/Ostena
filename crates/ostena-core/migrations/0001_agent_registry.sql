-- Agent registry and enrolment tokens (ADR-0008, ADR-0011).
-- Identifiers are UUIDs; certificate fingerprints are SHA-256 (32 bytes).
-- Enrolment tokens keep only the SHA-256 of their secret, never the secret.

CREATE TABLE agent (
    id            uuid        PRIMARY KEY,
    gateway_group uuid        NOT NULL,
    enrolled_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at    timestamptz
);

CREATE INDEX agent_gateway_group ON agent (gateway_group);

CREATE TABLE agent_certificate (
    fingerprint bytea       PRIMARY KEY CHECK (length(fingerprint) = 32),
    agent_id    uuid        NOT NULL REFERENCES agent (id),
    issued_at   timestamptz NOT NULL DEFAULT now(),
    revoked_at  timestamptz
);

CREATE INDEX agent_certificate_agent ON agent_certificate (agent_id);

CREATE TABLE enrollment_token (
    id            bytea       PRIMARY KEY CHECK (length(id) = 16),
    digest        bytea       NOT NULL CHECK (length(digest) = 32),
    gateway_group uuid        NOT NULL,
    -- Unix seconds, compared with the clock of the core.
    expires_at    bigint      NOT NULL CHECK (expires_at > 0),
    used          boolean     NOT NULL DEFAULT false,
    failures      smallint    NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 3),
    burned        boolean     NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);
