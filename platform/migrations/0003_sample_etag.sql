-- 0003_sample_etag.sql -- close the admission/execution TOCTOU.
--
-- Issue #36 (DRAFT-043). NO BEGIN/COMMIT -- run.py owns the transaction.
--
-- Admission hashes the uploaded sample and records its SHA-256. But the
-- browser's presigned POST stays valid for its whole TTL, so the object can
-- be OVERWRITTEN after admission has already passed. Demonstrated on
-- 2026-08-23: a benign ELF was admitted and queued, the same upload URL then
-- accepted different bytes, and the object in the bucket no longer matched
-- the digest on the job.
--
-- The consequence is not a corrupt file. It is that Dom0 fetches and executes
-- bytes that were never admitted, while the trace, the verdict and the
-- recorded SHA-256 all describe the file that was replaced -- a sandbox that
-- can be made to analyse one thing and report another.
--
-- The ETag is the object's identity as the store sees it. Recorded at
-- admission and re-checked with a HEAD when a worker claims the job: cheap,
-- and a swap becomes a loud failure instead of a silent substitution.
--
-- Detection rather than prevention, deliberately. Preventing it outright
-- means copying the object to a key the browser holds no capability for,
-- which doubles storage for every sample; that trade is worth revisiting if
-- submission ever becomes untrusted (M8), and is not worth it for one
-- operator.
ALTER TABLE jobs ADD COLUMN sample_etag text;

COMMENT ON COLUMN jobs.sample_etag IS
    'Object ETag observed at admission. Re-checked when a worker claims the '
    'job; a mismatch means the sample was replaced after admission and the '
    'job is failed rather than run.';
