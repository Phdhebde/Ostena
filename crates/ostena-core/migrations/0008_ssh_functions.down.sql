-- Back to migration 7 (ADR-0011, reversible migrations). The functions of
-- the rights and the rights bits of the issued grants do not exist there:
-- both columns go. A right keeps its terminal and its commands, and loses
-- its transfers and forwarding, which fails closed. The grants already
-- issued live at most 60 s and are not touched.

ALTER TABLE access_grant DROP COLUMN rights;
ALTER TABLE access_right DROP COLUMN functions;
