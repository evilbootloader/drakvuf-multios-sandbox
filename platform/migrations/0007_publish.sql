-- 0007_publish.sql -- publication: who may read a finished analysis.
--
-- Issue #40 (DRAFT-047), decisions 5 and 6.
--
-- NO BEGIN/COMMIT IN THIS FILE. run.py owns the transaction -- see the note
-- at the head of 0001_jobs.sql.
--
-- text + CHECK rather than an enum, for the reason 0001 gives for `state`
-- and not the one it gives for `target_os`: the set is expected to grow, and
-- a CHECK is widened by one statement in a later migration. Reserved in 0001
-- and read by nothing until `auth.visible_to` landed in #40.

-- BEFORE the NOT NULL, and this order is the whole point. Every row written
-- since 0001 has visibility NULL; SET DEFAULT does not backfill them, so
-- constraining first fails on any populated database -- and passes on an empty
-- one, which is what the test suite runs against.

UPDATE jobs SET visibility = 'private' WHERE visibility IS NULL;

ALTER TABLE jobs
    ALTER COLUMN visibility SET DEFAULT 'private',
    ALTER COLUMN visibility SET NOT NULL,
    ADD CONSTRAINT jobs_visibility_known
        CHECK (visibility IN ('private', 'public'));

COMMENT ON COLUMN jobs.visibility IS
    'Who may read this analysis besides its owner. private is the default and '
    'the state every row was created in; public makes it readable by every '
    'authenticated user, sample and extracted/ included. Written only by the '
    'publish routes, read by auth.visible_to''s third arm.';