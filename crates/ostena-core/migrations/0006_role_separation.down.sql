-- Back to the single role of M1 (ADR-0011): the privileges of ostena_app
-- are withdrawn, nothing else changes and no row is touched. The objects
-- stay owned by ostena_owner: before an M1 binary is started again, the
-- procedure of docs/exploitation/core-installation.md hands them back to
-- the service account (REASSIGN OWNED).

REVOKE ALL ON _sqlx_migrations FROM ostena_app;
REVOKE ALL ON agent, agent_certificate, enrollment_token FROM ostena_app;
REVOKE ALL ON audit_record, audit_head FROM ostena_app;
REVOKE ALL ON gateway_group, app_user, login_session, access_right, grant_key, grant_key_set,
    access_grant, access_session, agent_ssh, resource, target_account FROM ostena_app;
REVOKE ALL (disabled_at) ON resource, target_account FROM ostena_app;
REVOKE ALL ON SEQUENCE push_version FROM ostena_app;
REVOKE ALL ON user_credential FROM ostena_app;
REVOKE ALL ON session_transcript FROM ostena_app;
