-- Browser sessions of the portal and roles of the users (ADR-0020).
--
-- A browser session is a login session of channel `web`, without a user
-- certificate: revoking it (logout, administrator, disabled user, idle
-- time, source change) follows the same path as for `ostena login`.

ALTER TABLE login_session
    ADD COLUMN channel text NOT NULL DEFAULT 'cli' CHECK (channel IN ('cli', 'web')),
    ALTER COLUMN certificate_sha256 DROP NOT NULL,
    ADD CONSTRAINT login_session_certificate_of_cli
        CHECK ((channel = 'cli') = (certificate_sha256 IS NOT NULL));

CREATE INDEX login_session_open ON login_session (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE web_session (
    login_session_id uuid   PRIMARY KEY REFERENCES login_session (id),
    -- SHA-256 of the cookie value (256 random bits drawn by the core); the
    -- value itself is never stored. Replaced at each authentication.
    cookie_sha256    bytea  NOT NULL UNIQUE CHECK (length(cookie_sha256) = 32),
    -- The source the session is bound to: an IPv4 address or an IPv6 /64
    -- prefix, in the canonical text form of the core.
    source           text   NOT NULL CHECK (char_length(source) BETWEEN 2 AND 45),
    -- Last authentication with both factors, Unix seconds.
    authenticated_at bigint NOT NULL CHECK (authenticated_at > 0),
    -- Last request that was not a background one, Unix seconds.
    last_activity_at bigint NOT NULL CHECK (last_activity_at >= authenticated_at)
);

CREATE TABLE user_role (
    user_id    uuid        NOT NULL REFERENCES app_user (id),
    role       text        NOT NULL CHECK (role IN ('admin')),
    granted_at timestamptz NOT NULL DEFAULT now(),
    -- Database user of the administration command.
    granted_by text        NOT NULL CHECK (char_length(granted_by) BETWEEN 1 AND 128),
    PRIMARY KEY (user_id, role)
);

-- The service (ADR-0011, roles): sessions are opened, touched and revoked,
-- never deleted; the roles are given and taken by the administration
-- commands. login_session keeps the privileges of migration 6.
GRANT SELECT, INSERT, UPDATE ON web_session TO ostena_app;
GRANT SELECT, INSERT, DELETE ON user_role TO ostena_app;
