-- SSH authorisation and minimal inventory (ADR-0014): gateway groups, users,
-- login sessions, resources, target accounts, rights, issued grants, access
-- sessions, grant signing keys and the SSH state of each agent.
--
-- Times the core compares with its own clock are Unix seconds (bigint), as
-- in enrollment_token; the others are timestamptz for the operators.
-- Names follow the rules of the tunnel messages (ADR-0008): a resource is
-- `[a-z0-9][a-z0-9.-]{0,62}`, an account 1 to 256 bytes without control
-- character nor surrounding space.
--
-- The login (PR 7) adds the credentials of a user in a table of its own and
-- creates the login sessions; nothing here needs to change for it.

-- Versions of what the core pushes (scope policy, grant key set, SSH trust):
-- one sequence, so that a version never goes back, whatever the object.
CREATE SEQUENCE push_version START 1;

CREATE TABLE gateway_group (
    id             uuid        PRIMARY KEY,
    name           text        NOT NULL UNIQUE
                               CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    -- Principals of the host certificates of its agents: the names users
    -- type after the last `@` (ssh root@srv-lab01@<name>).
    ssh_host_names text[]      NOT NULL DEFAULT '{}'
                               CHECK (cardinality(ssh_host_names) <= 16),
    -- PolicySpec in JSON, compiled in production mode before it is stored.
    policy         text        CHECK (octet_length(policy) <= 1048576),
    policy_version bigint      CHECK (policy_version > 0),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    CHECK ((policy IS NULL) = (policy_version IS NULL))
);

CREATE TABLE app_user (
    id           uuid        PRIMARY KEY,
    -- Login name; the id is the principal of the SSH user certificates.
    name         text        NOT NULL UNIQUE
                             CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    display_name text        NOT NULL
                             CHECK (char_length(display_name) BETWEEN 1 AND 128
                                    AND display_name !~ '[[:cntrl:]]'),
    state        text        NOT NULL DEFAULT 'active'
                             CHECK (state IN ('active', 'disabled')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    disabled_at  timestamptz,
    CHECK ((state = 'disabled') = (disabled_at IS NOT NULL))
);

-- An `ostena login` session: the key identifier of the user certificate.
CREATE TABLE login_session (
    id                 uuid        PRIMARY KEY,
    user_id            uuid        NOT NULL REFERENCES app_user (id),
    certificate_sha256 bytea       NOT NULL UNIQUE
                                   CHECK (length(certificate_sha256) = 32),
    started_at         bigint      NOT NULL CHECK (started_at > 0),
    -- Eight hours at most (ADR-0010).
    expires_at         bigint      NOT NULL,
    revoked_at         timestamptz,
    revoked_by         text,
    revocation_reason  text        CHECK (char_length(revocation_reason) <= 256),
    CHECK (expires_at > started_at AND expires_at <= started_at + 28800),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX login_session_user ON login_session (user_id);

CREATE TABLE resource (
    id                   uuid        PRIMARY KEY,
    name                 text        NOT NULL UNIQUE
                                     CHECK (name ~ '^[a-z0-9][a-z0-9.-]{0,62}$'),
    -- Checked again by the scope control of the agent.
    host                 text        NOT NULL
                                     CHECK (octet_length(host) BETWEEN 1 AND 253
                                            AND host !~ '[[:space:][:cntrl:]]'),
    port                 integer     NOT NULL CHECK (port BETWEEN 1 AND 65535),
    -- Pinned SSH host key of the target, uncompressed SEC1 point.
    ssh_host_p256_public bytea       CHECK (length(ssh_host_p256_public) = 65),
    gateway_group        uuid        NOT NULL REFERENCES gateway_group (id),
    created_at           timestamptz NOT NULL DEFAULT now(),
    disabled_at          timestamptz
);

CREATE INDEX resource_gateway_group ON resource (gateway_group);

CREATE TABLE target_account (
    id          uuid        PRIMARY KEY,
    resource_id uuid        NOT NULL REFERENCES resource (id),
    name        text        NOT NULL
                            CHECK (octet_length(name) BETWEEN 1 AND 256
                                   AND name !~ '[[:cntrl:]]'
                                   AND name !~ '^[[:space:]]'
                                   AND name !~ '[[:space:]]$'),
    created_at  timestamptz NOT NULL DEFAULT now(),
    disabled_at timestamptz,
    UNIQUE (resource_id, name)
);

-- User -> account (so resource) -> protocol, until a date.
CREATE TABLE access_right (
    id               uuid        PRIMARY KEY,
    user_id          uuid        NOT NULL REFERENCES app_user (id),
    account_id       uuid        NOT NULL REFERENCES target_account (id),
    protocol         text        NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'web')),
    valid_from       bigint      NOT NULL,
    -- Mandatory, 366 days at most.
    valid_until      bigint      NOT NULL,
    max_session_secs integer     NOT NULL CHECK (max_session_secs BETWEEN 60 AND 43200),
    created_by       text        NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    revoked_at       timestamptz,
    revoked_by       text,
    CHECK (valid_until > valid_from AND valid_until <= valid_from + 31622400),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX access_right_user_account ON access_right (user_id, account_id);

-- Grant signing keys, pushed to the agents as a key set (ADR-0004).
CREATE TABLE grant_key (
    kid          bytea  PRIMARY KEY CHECK (length(kid) = 8),
    p256_public  bytea  NOT NULL UNIQUE CHECK (length(p256_public) = 65),
    activated_at bigint NOT NULL,
    -- Set when another key becomes active: kept until the grants it signed
    -- have expired.
    retire_at    bigint
);

-- Version of the key set; one row.
CREATE TABLE grant_key_set (
    id      boolean PRIMARY KEY DEFAULT true CHECK (id),
    version bigint  NOT NULL CHECK (version > 0)
);

-- Every grant the core issued, by jti: what it authorises beyond its own
-- claims (account, login session), and its consumption by the core
-- (anti-replay across the agents of a group, ADR-0004).
CREATE TABLE access_grant (
    jti              bytea   PRIMARY KEY CHECK (length(jti) = 16),
    login_session_id uuid    NOT NULL REFERENCES login_session (id),
    right_id         uuid    NOT NULL REFERENCES access_right (id),
    agent_id         uuid    NOT NULL REFERENCES agent (id),
    gateway_group    uuid    NOT NULL,
    resource_id      uuid    NOT NULL REFERENCES resource (id),
    account          text    NOT NULL,
    protocol         text    NOT NULL CHECK (protocol IN ('ssh', 'rdp', 'vnc', 'web')),
    max_session_secs integer NOT NULL CHECK (max_session_secs > 0),
    issued_at        bigint  NOT NULL,
    expires_at       bigint  NOT NULL CHECK (expires_at > issued_at),
    consumed_at      bigint,
    consumed_by      uuid    REFERENCES agent (id),
    CHECK ((consumed_at IS NULL) = (consumed_by IS NULL))
);

CREATE INDEX access_grant_login_session ON access_grant (login_session_id);
CREATE INDEX access_grant_agent ON access_grant (agent_id);
CREATE INDEX access_grant_consumed_by ON access_grant (consumed_by);

-- A session opened by an agent for a consumed grant.
CREATE TABLE access_session (
    id                uuid   PRIMARY KEY,
    jti               bytea  NOT NULL UNIQUE REFERENCES access_grant (jti),
    agent_id          uuid   NOT NULL REFERENCES agent (id),
    opened_at         bigint NOT NULL,
    closed_at         bigint,
    close_reason      text   CHECK (char_length(close_reason) <= 128),
    bytes_to_target   bigint CHECK (bytes_to_target >= 0),
    bytes_from_target bigint CHECK (bytes_from_target >= 0)
);

-- What the core certified and pushed for the SSH server of an agent.
CREATE TABLE agent_ssh (
    agent_id                 uuid        PRIMARY KEY REFERENCES agent (id),
    host_p256_public         bytea       CHECK (length(host_p256_public) = 65),
    host_certificate         bytea       CHECK (length(host_certificate) <= 4096),
    certificate_issued_at    bigint,
    certificate_valid_before bigint,
    -- Last ssh_trust pushed: its version and the SHA-256 of its content, so
    -- that a change always gets a new version (TUN-E030 otherwise).
    trust_version            bigint      NOT NULL CHECK (trust_version > 0),
    trust_digest             bytea       NOT NULL CHECK (length(trust_digest) = 32),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CHECK ((host_certificate IS NULL) = (certificate_valid_before IS NULL)),
    CHECK ((host_certificate IS NULL) = (certificate_issued_at IS NULL))
);
