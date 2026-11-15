-- Audit chain of the core (ADR-0012): records and signed heads, append only.
--
-- Bodies are stored exactly as ostena-audit encodes them; the hash columns
-- repeat what anyone can recompute from the bodies, and are checked against
-- them by the core before it signs a head.
--
-- With the single owner role of M1 (ADR-0011), the triggers and the REVOKE
-- below only stop mistakes: the owner can disable a trigger. The integrity
-- of the chain is cryptographic (hash chaining and signed heads, checked by
-- the core and by `ostena audit verify`), not a matter of SQL rights. Once
-- the DDL and DML roles are split (docs/notes/core-roles-base.md), the
-- service role only gets SELECT and INSERT on these tables.

CREATE TABLE audit_record (
    seq         bigint      PRIMARY KEY CHECK (seq >= 1),
    -- ostena_audit::MIN_RECORD_LEN to MAX_RECORD_LEN.
    body        bytea       NOT NULL CHECK (length(body) BETWEEN 73 AND 8192),
    hash        bytea       NOT NULL CHECK (length(hash) = 32),
    event       text        NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

-- Events of one kind (signing keys announced, acknowledged breaks).
CREATE INDEX audit_record_event ON audit_record (event, seq);

CREATE TABLE audit_head (
    head_no    bigint      PRIMARY KEY CHECK (head_no >= 1),
    record_seq bigint      NOT NULL REFERENCES audit_record (seq),
    -- ostena_audit::HEAD_LEN.
    body       bytea       NOT NULL CHECK (length(body) = 182),
    hash       bytea       NOT NULL CHECK (length(hash) = 32),
    signed_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_head_record ON audit_head (record_seq);

-- Append only: no update, no delete, no truncation.
CREATE FUNCTION audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table % en ajout seul : % refusé', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_record_append_only
    BEFORE UPDATE OR DELETE ON audit_record
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_record_no_truncate
    BEFORE TRUNCATE ON audit_record
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_head_append_only
    BEFORE UPDATE OR DELETE ON audit_head
    FOR EACH ROW EXECUTE FUNCTION audit_append_only();
CREATE TRIGGER audit_head_no_truncate
    BEFORE TRUNCATE ON audit_head
    FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

-- Contiguity: the next seq and the next head number, nothing else. The core
-- appends under an advisory lock (ostena_core::audit::AUDIT_LOCK_KEY), so
-- the maximum read here is the committed tip.
CREATE FUNCTION audit_record_next() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    expected bigint;
BEGIN
    SELECT coalesce(max(seq), 0) + 1 INTO expected FROM audit_record;
    IF NEW.seq <> expected THEN
        RAISE EXCEPTION 'audit_record : seq % au lieu de %', NEW.seq, expected
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE FUNCTION audit_head_next() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    expected bigint;
    tip bigint;
BEGIN
    SELECT coalesce(max(head_no), 0) + 1 INTO expected FROM audit_head;
    SELECT coalesce(max(seq), 0) INTO tip FROM audit_record;
    IF NEW.head_no <> expected THEN
        RAISE EXCEPTION 'audit_head : tête % au lieu de %', NEW.head_no, expected
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.record_seq > tip THEN
        RAISE EXCEPTION 'audit_head : seq couvert % au-delà du bout %', NEW.record_seq, tip
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER audit_record_contiguous
    BEFORE INSERT ON audit_record
    FOR EACH ROW EXECUTE FUNCTION audit_record_next();
CREATE TRIGGER audit_head_contiguous
    BEFORE INSERT ON audit_head
    FOR EACH ROW EXECUTE FUNCTION audit_head_next();

REVOKE UPDATE, DELETE, TRUNCATE ON audit_record, audit_head FROM PUBLIC;
