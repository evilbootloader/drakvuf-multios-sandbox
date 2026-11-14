-- Run the sample twice (2026-11-14): the analysis host reads the first run's
-- process dumps for code that is in no file -- what a packer unpacked over
-- its own image, a program run from memory -- and traces the sample again
-- with hooks on it (sandboxd/stagehints.py). The second run is the job's
-- result. A choice of the submitter, because it can double the job's time;
-- through the API only, the submit form does not offer it.
--
-- NOT NULL DEFAULT false: every row before this was one run, and `Lease`
-- carries a bool. A host that finds nothing to add runs once whatever this
-- says, and says so in the manifest's notes.
--
-- `second_run_of`: the same thing asked for afterwards, from the page of a
-- finished job's report ("Run again", routers/jobs.py::second_run). Every job whose
-- memory showed such code leaves the lines as an artifact, `hints.txt`; the
-- job made from it has that job's id here, a copy of its sample and its
-- options, and is leased a URL to those lines. NULL for every other job.
-- SET NULL on delete: the second run's report stands without the first.
ALTER TABLE jobs
    ADD COLUMN second_pass   boolean NOT NULL DEFAULT false,
    ADD COLUMN second_run_of uuid REFERENCES jobs(id) ON DELETE SET NULL;
