-- The run's score, on its row (operator, 2026-11-14), so the history list can
-- show it without reading every job's report out of the object store.
--
-- CAPE's malscore and the word calc_scoring gives it, computed on Dom0
-- (sandboxd cape_plugin/scoring.py, vendored) and sent with the manifest at
-- `/complete` (routers/worker.py::CompleteRequest). The report holds the same
-- two values; these are a copy for listing, and outlive the report past the
-- retention window.
--
-- NULLABLE with no DEFAULT, because NULL is the meaning: no score -- a run
-- that failed, one from before the CAPE chain, one whose sandboxd predates
-- this column. `backfill_scores.py` fills the completed ones whose report is
-- still in the store.
--
-- Checked here as well as in the request model: the range is calc_scoring's
-- clamp, and the words are enums.MalStatus, which must not drift from it.
ALTER TABLE jobs
    ADD COLUMN malscore  real CHECK (malscore >= 0 AND malscore <= 10),
    ADD COLUMN malstatus text CHECK (malstatus IN
        ('Malicious', 'Suspicious', 'Clean', 'Undetected', 'Failed'));
