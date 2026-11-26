-- Back to local accounts only (ADR-0021). No row is deleted: the users of a
-- directory become disabled local accounts named `source.identifier`, so
-- that their sessions, rights and audit records keep pointing at them; the
-- group memberships, fed again by the sources after a new upgrade, are
-- dropped with their tables. If such a name is taken by a local account,
-- or is longer than the 64 characters of a local name, the migration fails
-- and changes nothing.

REVOKE ALL ON user_group_member FROM ostena_app;
REVOKE ALL ON user_group FROM ostena_app;

DROP TABLE user_group_member;
DROP TABLE user_group;

DROP INDEX app_user_external_id;

ALTER TABLE app_user
    DROP CONSTRAINT app_user_directory_check,
    DROP CONSTRAINT app_user_name_check;

UPDATE app_user
   SET name = replace(name, '/', '.'),
       state = 'disabled',
       disabled_at = coalesce(disabled_at, now())
 WHERE source <> 'local';

ALTER TABLE app_user
    DROP COLUMN synced_at,
    DROP COLUMN directory_disabled,
    DROP COLUMN directory_dn,
    DROP COLUMN external_id,
    DROP COLUMN source,
    ADD CONSTRAINT app_user_name_check CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,63}$');
