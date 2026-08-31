-- 0006_egress.sql -- where a job's traffic is allowed to go.
--
-- DRAFT-057. NO BEGIN/COMMIT -- run.py owns the transaction.
--
-- Design record: docs/architecture/networking.md. The exit-provider material
-- is deliberately NOT in this repository -- see private/README.md.
--
-- WHY THIS IS AN ENUM AND NOT text + CHECK.
--
-- 0001_jobs.sql draws the line explicitly: `target_os` is an enum because it is
-- a closed set and "the ONLY untrusted routing input in the system"; `state` is
-- text + CHECK because that list is expected to grow.
--
-- This is the SECOND untrusted routing input, and it is the more consequential
-- of the two. `target_os` decides which guest image boots. This decides whether
-- live malware reaches the Internet, and through whose address. An unknown
-- value must fail at the type boundary, before any application code gets the
-- chance to decide what to do with it -- because the only safe thing to do with
-- an unrecognised egress mode is refuse, and "refuse" is not what code written
-- in a hurry does.
--
-- The set is closed by design rather than by accident. Adding a mode is a
-- migration AND a Dom0 implementation, which is the correct amount of friction
-- for a change that alters where malware traffic goes.

CREATE TYPE egress_mode AS ENUM
    ('offline', 'simulated', 'tor', 'routed', 'direct');

ALTER TABLE jobs ADD COLUMN egress_mode egress_mode;

-- BACKFILL: a statement of fact, not a guess.
--
-- Every run before this migration went out through network-setup.sh's
-- unconditional MASQUERADE and its wildcard `-o xenbr0 -j ACCEPT`. There was no
-- other possibility -- no mode existed to select and no rule to select it with.
-- So `direct` is what those jobs actually did, and recording it is more honest
-- than a NULL that reads as "unknown" or a DEFAULT that would claim they were
-- something they were not.
--
-- This matters because of what the column is FOR. DRAFT-057: "A report showing
-- no network activity means nothing without knowing whether egress existed."
-- An old report with a NULL here could not be read at all; with `direct` it can.
UPDATE jobs SET egress_mode = 'direct' WHERE egress_mode IS NULL;

-- The column default is the LAST RESORT, not the policy.
--
-- The policy -- prefer `simulated`, fall back to `offline` when no host offers
-- a responder -- lives in `_resolve_egress` in routers/jobs.py, because it
-- depends on what the analysis hosts currently declare and SQL cannot see that.
-- Every INSERT names this column explicitly, so this default should only ever
-- be reached by a statement that forgot it.
--
-- Which is exactly why it is `offline` and not `simulated`. A forgotten column
-- is a bug, and the traffic consequence of a bug should be no traffic. Setting
-- it to `simulated` would also be a lie on a deployment where no responder
-- exists, and it would claim a mode the host would then refuse.
ALTER TABLE jobs
    ALTER COLUMN egress_mode SET NOT NULL,
    ALTER COLUMN egress_mode SET DEFAULT 'offline';

-- WHICH exit, by name, within the mode. 'es-vps-1', 'tor-default'.
--
-- A NAME, never an endpoint. DRAFT-057 is explicit that peers are server-side
-- configuration: a submitter naming a tunnel endpoint would be choosing where
-- Dom0 sends traffic, which is a different feature with a different threat
-- model. This is matched against the set the analysis host declared and is
-- meaningless otherwise.
--
-- Nullable because `offline` has no exit to name, and because one exit per mode
-- is the starting deployment. Country selection is a set of peers, so growing
-- it is configuration rather than a migration -- which is the whole reason this
-- column exists now instead of later.
ALTER TABLE jobs ADD COLUMN egress_exit text;

-- What the host ACTUALLY installed, as opposed to what was asked for.
--
-- The two differing is not a bug, it is the record that makes a report legible:
-- a run that requested `simulated` on a host whose responder was down ran
-- `offline`, and a network section showing nothing means something completely
-- different in those two cases.
--
-- jsonb because the shape is diagnostic and varies by mode -- an interface, a
-- country, a tunnel handshake age, the upstream port blocks that mode carries.
-- Promoting any of it to a column would freeze a shape that Phases 2 through 5
-- are still deciding. `manifest` on this same table is jsonb for the same
-- reason.
ALTER TABLE jobs ADD COLUMN egress_applied jsonb;

-- What each analysis host can offer as a way out.
--
-- Mirrors worker_pipelines exactly, and for the same reason stated there: only
-- Dom0 knows what its own interfaces are. The platform offers the submitter
-- this set and nothing else.
--
-- THIS TABLE IS THE GATE ON `direct`. A host that does not set
-- SANDBOXD_ALLOW_DIRECT=1 never inserts a `direct` row, so the mode is
-- unselectable in the UI and refused at admission -- with no second check
-- anywhere that could disagree with the first. That is the same shape as
-- required_mib: one authority, declared by the party that knows.
--
-- ON DELETE CASCADE so deregistering a host takes its exits with it. An exit
-- row outliving its worker would offer a way out that nothing can provide.
CREATE TABLE worker_egress (
    worker_id text NOT NULL REFERENCES workers(worker_id) ON DELETE CASCADE,
    name      text NOT NULL,
    mode      egress_mode NOT NULL,
    country   text,
    -- Upstream limitations that must reach the REPORT: 'tcp-only',
    -- 'smtp-blocked-upstream'. DRAFT-057's acceptance criterion 7 -- if an exit
    -- blocks a port, the report must distinguish "no SMTP traffic" from "SMTP
    -- was blocked upstream", or a provider's policy silently becomes a false
    -- negative that looks exactly like a result.
    caveats   jsonb NOT NULL DEFAULT '[]'::jsonb,
    PRIMARY KEY (worker_id, name)
);

-- Admission asks "does any host offer this exit?" on every submission, the way
-- it already asks about capacity. Small table, but the question is on the hot
-- path and the answer decides whether a sample runs.
CREATE INDEX worker_egress_name ON worker_egress (name);