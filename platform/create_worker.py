#!/usr/bin/env python3
"""Provision an analysis host and print its credential once.

DRAFT-061, closing KNOWN GAP (DRAFT-043/046). Until this existed the worker
channel used one shared `WORKER_TOKEN` and took the caller's identity from an
`X-Worker-Id` header, so any token holder could act as any worker.

    cd platform && .venv/bin/python create_worker.py dom0-1

**A worker cannot enrol itself.** `POST /worker/register` declares capacity for
the worker its token names and cannot bring a new one into existence -- so the
decision about which hosts may run jobs belongs to whoever can run this script,
not to whoever can reach the port.

**The token is printed once and never stored.** Only its sha256 reaches the
database, for the reason every other bearer credential here is hashed: a dump, a
backup or a read-only injection would otherwise hand over the worker channel.
Losing it means running this again with `--rotate`, which is also how a
compromised worker is cut off -- the lookup is per request, so revocation takes
effect immediately rather than at the next restart.

Safe to run against the deployment. It writes one row and reads nothing else.
"""

from __future__ import annotations

import argparse
import os
import secrets
import sys

import psycopg

from sandbox_platform.config import settings
from sandbox_platform.credentials import hash_refresh_token


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worker_id", help="e.g. dom0-1")
    parser.add_argument(
        "--rotate", action="store_true",
        help="replace the credential of a worker that already exists",
    )
    args = parser.parse_args()

    dsn = os.environ.get("DATABASE_URL", settings.database_url)
    print(f"database: {dsn}")

    token = secrets.token_urlsafe(32)

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT token_hash FROM workers WHERE worker_id = %s",
                    (args.worker_id,))
        existing = cur.fetchone()

        if existing is not None and not args.rotate:
            sys.exit(
                f"worker {args.worker_id!r} already exists; pass --rotate to "
                "replace its credential (the old one stops working at once)"
            )

        if existing is None:
            # **Placeholder capacity, and it cannot be zero.** 0001 puts
            # `CHECK (total_mib > 0)` on all three columns, and that migration
            # is applied on the deployment, so 1 is the smallest honest stand-in
            # until the worker reports real figures on its next `register`.
            #
            # A provisioned worker that has not checked in still cannot be given
            # work: the capacity join in `queries.CAPACITY` matches through
            # `worker_pipelines`, and only `register` writes those rows. The one
            # visible effect is that `worker_count` now includes it, so
            # admission says `no_capacity` rather than `no_workers` -- which is
            # the more accurate of the two for a host that exists and is silent.
            cur.execute(
                """
                INSERT INTO workers (worker_id, total_mib, total_vlans,
                                     total_slots, token_hash)
                VALUES (%s, 1, 1, 1, %s)
                """,
                (args.worker_id, hash_refresh_token(token)),
            )
            action = "created"
        else:
            cur.execute("UPDATE workers SET token_hash = %s WHERE worker_id = %s",
                        (hash_refresh_token(token), args.worker_id))
            action = "rotated"

    print(f"{action} worker {args.worker_id}")
    print()
    print("  WORKER_TOKEN=" + token)
    print()
    print("Put that in /etc/sandboxd/sandboxd.env on the analysis host.")
    print("It is not stored anywhere and cannot be shown again.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
