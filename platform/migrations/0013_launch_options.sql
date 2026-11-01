-- Where the sample is dropped inside the guest, and the command line it gets
-- (`sandbox_platform/launch.py`, 2026-11-01).
--
-- NULLABLE with no DEFAULT, unlike 0011, because NULL is the meaning here:
-- "nothing chosen". The analysis host reads it as the guest's default folder
-- and no command line, which is exactly what every row before this ran with,
-- so this statement needs no backfill. A default of 'desktop' would also be
-- wrong for Android, which has no Desktop.
--
-- `drop_location` is a key, never a path; `drop_subdir` is `/`-joined
-- whatever guest it is for. Both are validated by `CreateJobRequest` and again
-- by sandboxd (`guests.resolve_launch`) before a clone exists.
ALTER TABLE jobs
    ADD COLUMN drop_location text,
    ADD COLUMN drop_subdir   text,
    ADD COLUMN arguments     text;
