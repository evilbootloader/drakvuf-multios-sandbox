-- 0005_console.sql -- live console sessions.
--
-- DRAFT-056. NO BEGIN/COMMIT -- run.py owns the transaction.
--
-- Design and threat model: docs/architecture/live-console.md
--
-- TWO COLUMNS, AND THEY DO DIFFERENT JOBS.
--
-- `console_requested` is a REQUEST channel, not a status. Dom0 has no inbound
-- listener -- that is the hardest constraint in platform.md, and it is why
-- cancellation is delivered in a heartbeat RESPONSE rather than pushed. A
-- console session is the same problem: the operator sets this, and sandboxd
-- learns of it on its next beat and dials out. Nothing connects to Dom0.
--
-- So the latency floor is one heartbeat interval. That is the cost of not
-- putting a listener on the machine that runs malware, and it is a cost rather
-- than a defect.
--
-- `interacted` is a FACT ABOUT THE RUN and belongs on the row permanently. A
-- report from an interactive session is not comparable to an automated one: a
-- human made choices that changed what happened. Two reports that look alike
-- must not describe different experiments, so this is a correctness
-- requirement rather than bookkeeping.
--
-- It is set when input is FORWARDED, not when a session opens -- watching
-- changes nothing about the experiment.
--
-- WHY THE SESSION ITSELF IS NOT IN THIS TABLE. A session is a pair of open
-- sockets on one API process. A row describing one would outlive the process
-- holding it, and after a restart would describe a session that cannot exist.
-- The registry is in memory for the same reason a file handle is.

ALTER TABLE jobs
    ADD COLUMN console_requested boolean NOT NULL DEFAULT false,
    ADD COLUMN interacted        boolean NOT NULL DEFAULT false;
