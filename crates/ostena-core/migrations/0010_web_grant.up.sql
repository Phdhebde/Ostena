-- Grants issued for the browser gateway (ADR-0020, § 4).
--
-- A grant of channel `web` is asked by the portal (`POST /api/v1/access`)
-- for a browser session, then presented once in the opening of the
-- WebSocket `/api/v1/gateway`: `presented_at` marks it, atomically, so that
-- a second WebSocket with the same grant is refused. `agent_id` is the agent
-- the core chose when it issued the grant; the session may be opened by
-- another agent of the group (`consumed_by`).

ALTER TABLE access_grant
    ADD COLUMN channel text NOT NULL DEFAULT 'cli' CHECK (channel IN ('cli', 'web')),
    ADD COLUMN presented_at bigint,
    ADD CONSTRAINT access_grant_presented_of_web
        CHECK (presented_at IS NULL OR channel = 'web');
