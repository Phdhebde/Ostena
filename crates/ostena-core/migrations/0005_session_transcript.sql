-- Session transcripts (ADR-0016): one row per recorded session, from the
-- first byte of its stream to its seal.
--
-- The file itself, `<session>.cast` (asciicast v2), lives in the directory
-- `core.ssh.transcripts_dir`; the seal (SHA-256, size) is also written to
-- the audit chain (`transcript.sealed`), where `ostena audit verify
-- --transcripts` checks the files against it. The row only serves the
-- core: lookups, and the transcripts left unsealed by a stop of the core,
-- sealed as incomplete at the next start.

CREATE TABLE session_transcript (
    session_id    uuid        PRIMARY KEY REFERENCES access_session (id),
    agent_id      uuid        NOT NULL REFERENCES agent (id),
    -- Unix seconds, as access_session.
    started_at    bigint      NOT NULL CHECK (started_at > 0),
    state         text        NOT NULL DEFAULT 'recording'
                              CHECK (state IN ('recording', 'sealed', 'incomplete')),
    -- Keyed hash of the command of an `exec` (HMAC-SHA-256 under
    -- core.ssh.command_mac_key) and its length; the text is in the file.
    command_hmac  bytea       CHECK (length(command_hmac) = 32),
    command_len   integer     CHECK (command_len BETWEEN 0 AND 32768),
    -- Identifier of the command key (short keyed hash of a constant), for
    -- the rotation of the key.
    command_kid   text        CHECK (command_kid ~ '^[0-9a-f]{16}$'),
    sealed_at     bigint,
    sha256        bytea       CHECK (length(sha256) = 32),
    size          bigint      CHECK (size >= 0),
    events        bigint      CHECK (events >= 0),
    invalid_utf8  bigint      CHECK (invalid_utf8 >= 0),
    output_bytes  bigint      CHECK (output_bytes >= 0),
    -- closed, expired, revoked, shutdown, error: from the end frame.
    end_reason    text        CHECK (end_reason IN ('closed', 'expired', 'revoked',
                                                    'shutdown', 'error')),
    -- Why an incomplete transcript is incomplete (REC-E…).
    code          text        CHECK (code ~ '^REC-E[0-9]{3}$'),
    CHECK ((command_hmac IS NULL) = (command_len IS NULL)),
    CHECK ((command_hmac IS NULL) = (command_kid IS NULL)),
    CHECK ((state = 'recording') = (sealed_at IS NULL)),
    -- No digest while recording; a sealed transcript has one; an
    -- incomplete one has none when its file could not be created or is
    -- gone (never a made-up digest).
    CHECK ((sha256 IS NULL) = (size IS NULL)),
    CHECK (state <> 'recording' OR sha256 IS NULL),
    CHECK (state <> 'sealed' OR sha256 IS NOT NULL),
    CHECK ((state = 'incomplete') = (code IS NOT NULL)),
    CHECK (state <> 'sealed' OR end_reason IS NOT NULL)
);

CREATE INDEX session_transcript_recording ON session_transcript (state)
    WHERE state = 'recording';
