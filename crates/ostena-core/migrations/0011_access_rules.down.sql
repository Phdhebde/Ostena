-- Back to migration 10 (ADR-0011, reversible migrations). The rules, the
-- groups of accounts and the version of the policy go; the rights of
-- ADR-0014 stay. The roles `policy` and `audit` are taken away: migration
-- 10 only knows `admin`.
--
-- A grant issued under a rule cannot be written in the schema of migration
-- 10 (its right is mandatory), and its session may hold a transcript: if
-- one exists, the migration fails and changes nothing. Revoke the rules
-- and wait for their grants to be gone from the registry first.

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM access_grant WHERE rule_id IS NOT NULL) THEN
        RAISE EXCEPTION 'grants issued under an access rule exist: cannot revert to migration 10';
    END IF;
END;
$$;

REVOKE ALL ON policy_version FROM ostena_app;
REVOKE ALL ON access_rule FROM ostena_app;
REVOKE ALL ON account_group_member FROM ostena_app;
REVOKE ALL ON account_group FROM ostena_app;

DROP TRIGGER user_group_member_policy ON user_group_member;
DROP TRIGGER account_group_member_policy ON account_group_member;
DROP TRIGGER access_rule_policy ON access_rule;
DROP TRIGGER access_right_policy ON access_right;
DROP FUNCTION policy_changed();
DROP TABLE policy_version;

DELETE FROM user_role WHERE role <> 'admin';
ALTER TABLE user_role DROP CONSTRAINT user_role_role_check;
ALTER TABLE user_role ADD CONSTRAINT user_role_role_check CHECK (role IN ('admin'));

ALTER TABLE access_grant
    DROP CONSTRAINT access_grant_right_or_rule,
    DROP COLUMN rule_id,
    ALTER COLUMN right_id SET NOT NULL;

DROP TABLE access_rule;
DROP TABLE account_group_member;
DROP TABLE account_group;
