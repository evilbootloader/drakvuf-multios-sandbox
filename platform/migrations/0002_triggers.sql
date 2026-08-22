-- 0002_triggers.sql -- updated_at maintenance and live status notification.
--
-- Issue #35 (DRAFT-042).
--
-- NO BEGIN/COMMIT IN THIS FILE. run.py owns the transaction -- see the note
-- at the head of 0001_jobs.sql.

-- updated_at is maintained here rather than in application code so that it
-- is true for EVERY writer, including a migration, a reaper sweep, and
-- whatever an operator does at a psql prompt at 2am. A column that is only
-- accurate when the application is the writer is worse than no column,
-- because it is trusted.
CREATE FUNCTION jobs_touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER jobs_touch
    BEFORE UPDATE ON jobs
    FOR EACH ROW
    EXECUTE FUNCTION jobs_touch_updated_at();

-- Live status for the web UI, without Redis.
--
-- The payload is deliberately MINIMAL: job id and new state, nothing else.
-- Three reasons, and the last is the load-bearing one:
--
--   1. pg_notify's payload cap is 8000 bytes. A submitted filename is
--      attacker-controlled and can approach that on its own, so a payload
--      built from row content is a payload that can be made to fail.
--   2. A listener that needs more can SELECT it, authorised, through the API
--      that already scopes what a caller may see.
--   3. NOTIFY fans out to every listener on the channel. Putting row content
--      in it means the transport carries data the API's authorisation layer
--      never inspected -- which matters the moment `owner` and `visibility`
--      mean anything (M8).
CREATE FUNCTION jobs_notify_state() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.state IS DISTINCT FROM OLD.state THEN
        PERFORM pg_notify(
            'jobs',
            json_build_object('id', NEW.id, 'state', NEW.state)::text
        );
    END IF;
    RETURN NULL;  -- AFTER trigger; return value is ignored
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER jobs_notify
    AFTER INSERT OR UPDATE ON jobs
    FOR EACH ROW
    EXECUTE FUNCTION jobs_notify_state();