# platform

The analysis platform: job state, the queue, the API, and the web UI. Runs in
its own Xen PVH DomU — **not** on Dom0, and it never executes a sample.
(It was an unprivileged LXC on Proxmox until 2026-08-28; see
`docs/architecture/platform.md` and `docs/CURRENT-STATE.md` §1.3.)

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

Postgres 15 or newer. The DomU runs 17.x; this container runs 18.x, and
nothing in the schema depends on the difference.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Then bring up Postgres and MinIO. **`scripts/dev-services.sh` does this and is
idempotent** — it starts the cluster, creates `sandbox_platform_test`, starts
MinIO with the credentials and `MINIO_SITE_REGION` that `tests/conftest.py`
expects, creates the `analysis` bucket, and reports anything still missing:

```bash
../scripts/dev-services.sh
.venv/bin/python -m pytest -q
```

By hand, if you would rather:

```bash
sudo -n runuser -u postgres -- createdb -O "$USER" sandbox_platform_test
export DATABASE_URL="postgresql:///sandbox_platform_test"
.venv/bin/python migrations/run.py
```

**The region is not optional.** `conftest.py` sets `S3_REGION=eu-central-1`,
and MinIO's own `MINIO_SITE_REGION` is part of the SigV4 signing scope. Start
MinIO without it and presigned URLs fail with a 403 that talks about
signatures and never mentions regions — which reads as a bug in the signing
code rather than a missing environment variable.

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