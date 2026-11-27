-- Identity sources (ADR-0021): users of LDAPS directories besides the local
-- accounts, and groups of users fed by the group rules of each source.
--
-- A user belongs to one source. A local account keeps its name; a user of a
-- directory is named `source/identifier`, so that the same identifier in two
-- sources gives two distinct users, never merged. The directory identifies
-- its entry by `external_id` (objectGUID of Active Directory in hex,
-- entryUUID of OpenLDAP, ipaUniqueID of FreeIPA): a rename in the directory
-- renames the user, a deletion disables it.
--
-- `directory_disabled` tells a disabling by the source (directory account
-- disabled, deleted, out of the allowed groups) from a disabling by an
-- administrator: only the first is lifted when the directory enables the
-- account again.

ALTER TABLE app_user DROP CONSTRAINT app_user_name_check;

ALTER TABLE app_user
    ADD COLUMN source             text    NOT NULL DEFAULT 'local'
                                          CHECK (source ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    ADD COLUMN external_id        text    CHECK (octet_length(external_id) BETWEEN 1 AND 128
                                                 AND external_id !~ '[[:cntrl:]]'),
    ADD COLUMN directory_dn       text    CHECK (octet_length(directory_dn) BETWEEN 1 AND 1024
                                                 AND directory_dn !~ '[[:cntrl:]]'),
    ADD COLUMN directory_disabled boolean NOT NULL DEFAULT false,
    -- Last time the source confirmed the account, Unix seconds.
    ADD COLUMN synced_at          bigint  CHECK (synced_at > 0),
    ADD CONSTRAINT app_user_name_check CHECK (
        (source = 'local' AND name ~ '^[a-z0-9][a-z0-9._-]{0,63}$')
        OR (source <> 'local' AND name ~ ('^' || source || '/[a-z0-9][a-z0-9._-]{0,63}$'))
    ),
    ADD CONSTRAINT app_user_directory_check CHECK (
        (source = 'local') = (external_id IS NULL)
        AND (source = 'local') = (directory_dn IS NULL)
        AND (NOT directory_disabled OR (source <> 'local' AND state = 'disabled'))
    );

CREATE UNIQUE INDEX app_user_external_id ON app_user (source, external_id)
    WHERE external_id IS NOT NULL;

-- Groups of users of the core. The access decision (PDP) refers to them;
-- the group rules of the sources create and feed them.
CREATE TABLE user_group (
    id         uuid        PRIMARY KEY,
    name       text        NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_group_member (
    group_id uuid        NOT NULL REFERENCES user_group (id),
    user_id  uuid        NOT NULL REFERENCES app_user (id),
    -- The source whose rule gave the membership.
    source   text        NOT NULL CHECK (source ~ '^[a-z0-9][a-z0-9-]{0,31}$'),
    added_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX user_group_member_user ON user_group_member (user_id);

-- The service (ADR-0011, roles): groups are created, never changed nor
-- deleted; a membership is added or removed by the synchronisation.
GRANT SELECT, INSERT ON user_group TO ostena_app;
GRANT SELECT, INSERT, DELETE ON user_group_member TO ostena_app;
