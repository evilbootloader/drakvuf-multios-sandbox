-- The other two knobs on the submit form, after `plugins` in 0010, and the
-- same reading of an unset value as that migration.
--
-- NOT NULL with a DEFAULT rather than a bare nullable column, because
-- `jobs.claim` reads these straight into `Lease.timeout: int` and
-- `Lease.disable_sysret: bool`. A NULL arrives there as None and the worker's
-- `LeaseResponse` then refuses it, so a row queued before this migration would
-- 500 the claim instead of leasing. Postgres 11+ fills existing rows from the
-- DEFAULT without rewriting the table, so this statement IS the backfill.
--
-- `true` is exact: `guests.default_trace_options` returns `disable_sysret=True`
-- for all three guests today, so a pre-0011 row keeps the behaviour it was
-- queued with.
--
-- `0` is the "use the measured default" sentinel `stages._trace_options`
-- already reads (`if timeout:`), and is unreachable from the API, which takes
-- `gt=0`. A concrete number here would have to be ONE number and the guest
-- defaults are not one number -- an Android APK gets 150s where everything
-- else gets 120s, and APK-ness is decided from the sample's bytes on the
-- worker, not stored on this row. 0 preserves all of them; 120 would silently
-- shorten a queued APK.
ALTER TABLE jobs
    ADD COLUMN disable_sysret   boolean NOT NULL DEFAULT true,
    ADD COLUMN timeout          int     NOT NULL DEFAULT 0;