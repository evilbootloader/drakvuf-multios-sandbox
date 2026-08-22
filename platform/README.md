# platform

The analysis platform: job state, the queue, the API, and the web UI. Runs in
an unprivileged LXC on L0 — **not** on Dom0, and it never executes a sample.

Design record: `docs/architecture/platform.md`. Decision: issue
[#34](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/34).

Nothing here talks to Xen, LVM or OVS. That separation is the point: Dom0
dials out to this service and this service has no route back.

## Layout

```
migrations/     numbered SQL, applied in order, exactly once   (#35)
sandbox_platform/   the service                                (#36, #38)
tests/          pytest, against a real Postgres                (#35 onward)
```

## Local setup

Postgres 15 or newer. The LXC runs 17.11; this container runs 18.6, and
nothing in the schema depends on the difference.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

sudo -n runuser -u postgres -- createdb -O "$USER" sandbox_platform_test
export DATABASE_URL="postgresql:///sandbox_platform_test"
.venv/bin/python migrations/run.py
```

## Migrations

One versioned change to the database structure per file, applied once, in
lexical order. `schema_migrations` records what has been applied, keyed by
filename, with a SHA-256 of the bytes as a tripwire.

```bash
.venv/bin/python migrations/run.py --status   # report, change nothing
.venv/bin/python migrations/run.py            # apply pending
```

**Never edit an applied migration.** Add a new numbered file with an `ALTER`.
The runner refuses a file whose bytes changed after it was applied, because at
that point the file and the live database have silently stopped describing the
same schema — and an edit cannot reach a database that already ran the
original. While a migration has not been applied anywhere, editing it is free;
once it lands somewhere that cannot be dropped, it is frozen.

**No `BEGIN`/`COMMIT` inside a migration.** The runner owns the transaction so
that the schema change and its bookkeeping row commit together. A `COMMIT` in
the file closes that transaction early and leaves the schema applied but
unrecorded — observed for real on 2026-08-22, which is why `run.py` now
rejects it rather than trusting the convention. Function bodies are exempt:
`$$ … $$` is masked before the check, so plpgsql's block `BEGIN` is fine.