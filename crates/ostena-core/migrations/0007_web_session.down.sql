-- Back to migration 6 (ADR-0011, reversible migrations). The browser
-- sessions and the roles of the portal do not exist there: their tables go,
-- and so do the login sessions of channel `web`, which have no certificate
-- and cannot be written in the schema of migration 6. The login sessions of
-- `ostena login` are kept as they are.

DROP TABLE user_role;
DROP TABLE web_session;
DELETE FROM login_session WHERE channel = 'web';
DROP INDEX login_session_open;
ALTER TABLE login_session
    DROP CONSTRAINT login_session_certificate_of_cli,
    ALTER COLUMN certificate_sha256 SET NOT NULL,
    DROP COLUMN channel;
