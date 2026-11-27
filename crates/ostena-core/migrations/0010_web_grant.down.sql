-- Back to the previous migration (ADR-0011, reversible migrations). The grants of the
-- browser gateway go, with the sessions opened for them and their
-- transcripts: they belong to login sessions of channel `web`, which the
-- way back to migration 6 removes. The grants of native SSH stay.

DELETE FROM session_transcript WHERE session_id IN (
    SELECT s.id FROM access_session s JOIN access_grant g ON g.jti = s.jti
    WHERE g.channel = 'web');
DELETE FROM access_session WHERE jti IN (SELECT jti FROM access_grant WHERE channel = 'web');
DELETE FROM access_grant WHERE channel = 'web';
ALTER TABLE access_grant
    DROP CONSTRAINT access_grant_presented_of_web,
    DROP COLUMN presented_at,
    DROP COLUMN channel;
