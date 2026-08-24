-- 0004_results_bytes.sql -- bound what one job can write to the store.
--
-- Issue #37 (DRAFT-044). NO BEGIN/COMMIT -- run.py owns the transaction.
--
-- The bucket quota was supposed to be the guard here, and measurement on
-- 2026-08-24 showed it is not a prompt one: 3 MiB was written into a 1 MiB
-- quota and every write succeeded, because MinIO enforces quotas against
-- usage statistics refreshed by its background scanner rather than at write
-- time. The same bucket refused writes ~45s later with
-- XMinioAdminBucketQuotaExceeded. So the quota stops growth over days -- which
-- is the real failure mode, results accumulating -- and permits an overshoot
-- bounded by write rate times scanner interval, which is not a documented
-- contract.
--
-- Nothing else bounded a job at all. `max_artifact_bytes` caps ONE object, but
-- `memdump` dumps the memory regions a process writes, so a run produces many
-- small files, and a worker may request artifact tickets repeatedly.
--
-- This column is that bound, checked at the moment a ticket is minted rather
-- than after the bytes have landed. The accounting is in DECLARED sizes, which
-- is sound because the presigned POST policy binds each upload to the size it
-- was declared with -- a worker cannot declare 1 byte and upload a gigabyte.
--
-- Charged when the TICKET is minted, not when bytes land, because the API is
-- not in the upload path at all -- the worker POSTs straight to MinIO, which
-- is the point of a presigned URL. A ticket the worker never uses is still
-- charged. That over-counts rather than under-counts, which is the safe
-- direction: it refuses slightly early instead of letting the store fill.
--
-- **A lifetime total, with no reset, because a job_id is analysed exactly
-- once.** Nothing returns a claimed job to 'queued' -- an expired lease is
-- marked 'interrupted' and left for sandboxd's reconciliation to judge -- and
-- a re-attempt is a new job with a new id and its own results/<job_id>/
-- prefix. So there is no second attempt to charge against this row, and a
-- reset would be code for a state the schema cannot reach.
ALTER TABLE jobs
    ADD COLUMN results_bytes bigint NOT NULL DEFAULT 0
        CONSTRAINT results_bytes_non_negative CHECK (results_bytes >= 0);

COMMENT ON COLUMN jobs.results_bytes IS
    'Bytes of result artifacts this job has been issued upload tickets '
    'for, in declared sizes. Checked against MAX_JOB_RESULT_BYTES before a '
    'ticket is minted. Never reset: a job_id is analysed once, and a retry is '
    'a new job. The bucket quota is a slower, store-wide backstop -- it lags '
    'behind writes by a scanner interval.';