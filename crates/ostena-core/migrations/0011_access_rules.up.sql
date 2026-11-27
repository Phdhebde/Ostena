-- Access rules of the decision point (ADR-0022, PR 10c): groups of
-- accounts, rules on users or groups of users and on accounts or groups of
-- accounts, refusals, the roles `policy` and `audit`, and the version of
-- the policy.
--
-- The rights of ADR-0014 stay as they are: they are rules on one user and
-- one account, allowing SSH.

-- Groups of target accounts, created by the administration commands.
CREATE TABLE account_group (
    id         uuid        PRIMARY KEY,
    name       text        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    created_by text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE account_group_member (
    group_id   uuid        NOT NULL REFERENCES account_group (id),
    account_id uuid        NOT NULL REFERENCES target_account (id),
    added_by   text        NOT NULL CHECK (char_length(added_by) BETWEEN 1 AND 128),
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, account_id)
);

CREATE INDEX account_group_member_account ON account_group_member (account_id);

-- One rule: a subject (a user or a group of users), a target (an account
-- or a group of accounts), protocols, an effect and a validity window
-- [valid_from, valid_until) in Unix seconds. An allowing rule ends within
-- 366 days, like a right; a refusal may have no end (NULL).
CREATE TABLE access_rule (
    id               uuid        PRIMARY KEY,
    user_id          uuid        REFERENCES app_user (id),
    user_group_id    uuid        REFERENCES user_group (id),
    account_id       uuid        REFERENCES target_account (id),
    account_group_id uuid        REFERENCES account_group (id),
    protocols        text[]      NOT NULL
                                 CHECK (protocols <@ ARRAY['ssh', 'rdp', 'vnc', 'web']::text[]
                                        AND cardinality(protocols) BETWEEN 1 AND 4),
    effect           text        NOT NULL CHECK (effect IN ('allow', 'deny', 'deny_functions')),
    -- Allow: the functions granted; deny_functions: the functions taken
    -- away (at least one); deny: none. Same names as the rights.
    functions        text[]      NOT NULL DEFAULT '{}'
                                 CHECK (functions <@ ARRAY['transfer', 'port-forwarding',
                                                           'agent-forwarding', 'x11-forwarding']::text[]
                                        AND cardinality(functions) <= 4),
    max_session_secs integer     CHECK (max_session_secs BETWEEN 60 AND 43200),
    valid_from       bigint      NOT NULL,
    valid_until      bigint,
    created_by       text        NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at       timestamptz NOT NULL DEFAULT now(),
    revoked_at       timestamptz,
    revoked_by       text        CHECK (char_length(revoked_by) BETWEEN 1 AND 128),
    CHECK ((user_id IS NULL) <> (user_group_id IS NULL)),
    CHECK ((account_id IS NULL) <> (account_group_id IS NULL)),
    CHECK ((effect = 'allow') = (max_session_secs IS NOT NULL)),
    CHECK (effect <> 'deny' OR cardinality(functions) = 0),
    CHECK (effect <> 'deny_functions' OR cardinality(functions) >= 1),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    CHECK (effect <> 'allow'
           OR (valid_until IS NOT NULL AND valid_until <= valid_from + 31622400)),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);

CREATE INDEX access_rule_valid ON access_rule (valid_until) WHERE revoked_at IS NULL;

-- A grant names the right or the rule it was issued under.
ALTER TABLE access_grant
    ALTER COLUMN right_id DROP NOT NULL,
    ADD COLUMN rule_id uuid REFERENCES access_rule (id),
    ADD CONSTRAINT access_grant_right_or_rule CHECK ((right_id IS NULL) <> (rule_id IS NULL));

-- The separate administration roles (ADR-0022).
ALTER TABLE user_role DROP CONSTRAINT user_role_role_check;
ALTER TABLE user_role
    ADD CONSTRAINT user_role_role_check CHECK (role IN ('admin', 'policy', 'audit'));

-- Version of the access policy; one row. Every change of what the policy
-- reads raises it, in the transaction of the change: the transaction of a
-- grant reads it with FOR SHARE and compares it with the version of the
-- decision point, so a decision is never older than the rules it sees, and
-- a change waits for the grants being decided.
CREATE TABLE policy_version (
    id      boolean PRIMARY KEY DEFAULT true CHECK (id),
    version bigint  NOT NULL CHECK (version >= 1)
);

INSERT INTO policy_version (id, version) VALUES (true, 1);

CREATE FUNCTION policy_changed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE policy_version SET version = version + 1;
    -- The core reloads its policy (notice `policy` of ADR-0022).
    PERFORM pg_notify('ostena_registry', 'policy');
    RETURN NULL;
END;
$$;

CREATE TRIGGER access_right_policy AFTER INSERT OR UPDATE OR DELETE ON access_right
    FOR EACH STATEMENT EXECUTE FUNCTION policy_changed();
CREATE TRIGGER access_rule_policy AFTER INSERT OR UPDATE OR DELETE ON access_rule
    FOR EACH STATEMENT EXECUTE FUNCTION policy_changed();
CREATE TRIGGER account_group_member_policy
    AFTER INSERT OR UPDATE OR DELETE ON account_group_member
    FOR EACH STATEMENT EXECUTE FUNCTION policy_changed();
CREATE TRIGGER user_group_member_policy AFTER INSERT OR UPDATE OR DELETE ON user_group_member
    FOR EACH STATEMENT EXECUTE FUNCTION policy_changed();

-- The service (ADR-0011, roles): groups of accounts are created, never
-- changed nor deleted; memberships are added and removed; rules are
-- created and revoked, never deleted; the version is read and raised.
GRANT SELECT, INSERT ON account_group TO ostena_app;
GRANT SELECT, INSERT, DELETE ON account_group_member TO ostena_app;
GRANT SELECT, INSERT ON access_rule TO ostena_app;
GRANT UPDATE (revoked_at, revoked_by) ON access_rule TO ostena_app;
GRANT SELECT, UPDATE ON policy_version TO ostena_app;
