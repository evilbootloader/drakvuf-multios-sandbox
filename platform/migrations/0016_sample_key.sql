-- Where a job's sample is in the object store, when that is not where an
-- upload puts it (2026-11-15).
--
-- A second run (routers/jobs.py::second_run) runs the sample a finished job
-- ran. It was copied to the new job's own key inside the store, and the
-- store's front refuses that by design: objects.conf answers 403 to every
-- request with x-amz-copy-source, so that the API's key can never read or
-- write across keys in one request (garage/README.md, DECISION A2). So the
-- new job names the first job's object instead, and admission and the
-- worker's claim read the sample from there.
--
-- NULL for every other job: the key is `<key_prefix>samples/<id>/<filename>`
-- (objects.sample_key), as every row before this was.
ALTER TABLE jobs
    ADD COLUMN sample_key text;
