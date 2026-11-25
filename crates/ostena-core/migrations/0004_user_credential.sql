-- Local credentials of a user for `ostena login` (ADR-0009, amendment of
-- 2026-11-25; ADR-0010): password digest, TOTP secret encrypted with
-- `core.login.totp_key`, anti-replay of the codes and lockout.
--
-- Times the core compares with its own clock are Unix seconds (bigint);
-- the others are timestamptz for the operators.

CREATE TABLE user_credential (
    user_id             uuid        PRIMARY KEY REFERENCES app_user (id),
    -- `$ostena-pbkdf2-sha256$i=<n>$<salt>$<digest>`, see
    -- ostena_crypto::password.
    password_hash       text        CHECK (octet_length(password_hash) BETWEEN 1 AND 256),
    password_changed_at timestamptz,
    -- AES-256-GCM: version, nonce, secret (20 or 32 bytes), tag; the
    -- associated data is the user id.
    totp_secret         bytea       CHECK (length(totp_secret) BETWEEN 49 AND 61),
    totp_algorithm      text        CHECK (totp_algorithm IN ('sha1', 'sha256')),
    -- Generated, not confirmed yet: the login is refused.
    totp_pending        boolean     NOT NULL DEFAULT false,
    totp_enrolled_at    timestamptz,
    -- Last accepted time step: a code of this step or an earlier one is
    -- refused (anti-replay).
    totp_last_step      bigint      NOT NULL DEFAULT 0 CHECK (totp_last_step >= 0),
    failed_attempts     integer     NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until        bigint      CHECK (locked_until > 0),
    last_success_at     timestamptz,
    CHECK ((password_hash IS NULL) = (password_changed_at IS NULL)),
    CHECK ((totp_secret IS NULL) = (totp_algorithm IS NULL)),
    CHECK (totp_secret IS NOT NULL OR NOT totp_pending),
    CHECK (totp_enrolled_at IS NULL OR (totp_secret IS NOT NULL AND NOT totp_pending))
);
