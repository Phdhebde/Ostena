-- Separate roles (ADR-0011, amendment of 2026-11-26): the schema belongs to
-- ostena_owner, which only `ostena core migrate` takes; the service and the
-- administration commands take ostena_app, which gets here the DML each
-- table needs and nothing else. Both roles are created by `ostena core db
-- init` (NOLOGIN group roles); this migration fails without them.
--
-- Every later migration that adds a table grants what ostena_app needs on
-- it, in the same migration; the test of the privileges (tests/roles.rs)
-- lists them all and fails on any other.
--
-- UPDATE on a table also covers its row locks (FOR UPDATE, FOR SHARE) and
-- `INSERT … ON CONFLICT DO UPDATE`; a table that is only locked, never
-- updated, gets UPDATE on one column so that FOR SHARE is allowed.

-- The schema state, read by `ostena core run` and the administration
-- commands before they do anything (CORE-E005).
GRANT SELECT ON _sqlx_migrations TO ostena_app;

-- Agent registry and enrolment (ADR-0008).
GRANT SELECT, INSERT, UPDATE ON agent, agent_certificate, enrollment_token TO ostena_app;

-- Audit chain (ADR-0012): append only. No UPDATE, DELETE nor TRUNCATE, and
-- not the owner: the service cannot disable the append-only triggers.
GRANT SELECT, INSERT ON audit_record, audit_head TO ostena_app;

-- Inventory and SSH access (ADR-0014).
GRANT SELECT, INSERT, UPDATE ON gateway_group, app_user, login_session, access_right,
    grant_key, grant_key_set, access_grant, access_session, agent_ssh TO ostena_app;
GRANT SELECT, INSERT, UPDATE (disabled_at) ON resource, target_account TO ostena_app;
GRANT USAGE ON SEQUENCE push_version TO ostena_app;

-- Credentials of `ostena login` (ADR-0010).
GRANT SELECT, INSERT, UPDATE ON user_credential TO ostena_app;

-- Session transcripts (ADR-0016).
GRANT SELECT, INSERT, UPDATE ON session_transcript TO ostena_app;
