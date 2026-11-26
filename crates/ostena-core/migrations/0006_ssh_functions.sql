-- Functions of an SSH right beyond the terminal and the commands (ADR-0010,
-- ADR-0014): file transfers (sftp, scp, rsync), port forwarding (local,
-- remote, ProxyJump), agent forwarding and X11 forwarding. None by default:
-- each is granted explicitly, carried by the grant as its rights bits
-- (ADR-0004) and enforced by the agent.

ALTER TABLE access_right
    ADD COLUMN functions text[] NOT NULL DEFAULT '{}'
        CHECK (functions <@ ARRAY['transfer', 'port-forwarding', 'agent-forwarding',
                                  'x11-forwarding']::text[]
               AND cardinality(functions) <= 4);

-- The rights bits signed in the grant, for the registry of issued grants.
ALTER TABLE access_grant
    ADD COLUMN rights integer NOT NULL DEFAULT 0
        CHECK (rights >= 0 AND rights < 1024);
