#!/usr/bin/env python3
"""Apply numbered SQL migrations, in order, exactly once.

Issue #35 (DRAFT-042). Plain SQL over Alembic deliberately: Alembic's value is
autogenerating diffs from ORM models, and there is no ORM here -- the claim
query is hand-written SQL that no ORM would express well. Adopting it would
mean adopting SQLAlchemy models that exist only to be diffed against. Numbered
SQL is auditable by reading it, which matters more here.

Usage:
    DATABASE_URL=... python run.py             # apply pending
    DATABASE_URL=... python run.py --status    # report only, change nothing
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
from pathlib import Path

import psycopg

MIGRATIONS_DIR = Path(__file__).parent

# filename is the key, sha256 is the integrity check, and they are not
# interchangeable -- asked and answered 2026-08-22.
#
# The filename identifies WHICH migration; the digest identifies WHICH BYTES.
# Keying on the digest instead would defeat the check in main(): editing an
# applied migration changes its digest, so the row would no longer match, the
# file would look brand new, and it would be applied a second time. The exact
# failure the digest exists to catch would become the one it cannot see.
BOOTSTRAP = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    filename    text PRIMARY KEY,
    sha256      text NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now()
);
"""


def discover() -> list[Path]:
    """Migration files, in lexical order.

    Lexical order is the contract, which is why the names are zero-padded.
    A file added out of order is a bug in the name, not something for this
    script to be clever about.
    """
    return sorted(MIGRATIONS_DIR.glob("[0-9][0-9][0-9][0-9]_*.sql"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Matches a dollar-quote delimiter: plain $$, or tagged like $body$.
DOLLAR_TAG = re.compile(r"\$[A-Za-z_]\w*\$|\$\$")


def mask_dollar_quoted(sql: str) -> str:
    """Blank out $$...$$ bodies with spaces, preserving line numbers.

    A plpgsql function body opens with its own BEGIN, which is a BLOCK
    delimiter and not transaction control. Without this, the check below
    rejects every trigger function in the tree -- which it did, on 0002.

    Newlines are preserved so reported line numbers stay accurate. An
    unterminated quote stops the masking rather than blanking the rest of the
    file: that SQL is malformed, and Postgres reports it better than we would.
    """
    out = list(sql)
    i, n = 0, len(sql)
    while i < n:
        if m := DOLLAR_TAG.match(sql, i):
            tag = m.group(0)
            end = sql.find(tag, m.end())
            if end == -1:
                break
            for j in range(m.start(), end + len(tag)):
                if out[j] != "\n":
                    out[j] = " "
            i = end + len(tag)
        else:
            i += 1
    return "".join(out)


def check_no_transaction_control(path: Path) -> str | None:
    """Reject a migration that manages its own transaction.

    This runner's contract is that a migration and its schema_migrations row
    commit together. A BEGIN or COMMIT inside the file breaks it: the file's
    COMMIT closes the runner's transaction early, the DDL lands, and the
    bookkeeping insert then fails against a savepoint that no longer exists --
    leaving the schema applied and unrecorded, which is exactly the state the
    transaction was there to prevent.

    Observed for real on 2026-08-22, on the first run of 0001. Hence a check
    rather than a comment.
    """
    masked = mask_dollar_quoted(path.read_text())
    for n, line in enumerate(masked.splitlines(), 1):
        stripped = line.split("--", 1)[0].strip().upper().rstrip(";")
        if stripped in ("BEGIN", "COMMIT", "ROLLBACK", "START TRANSACTION"):
            return f"{path.name}:{n}: {stripped} -- run.py owns the transaction"
    return None


def check_encoding(conn: psycopg.Connection) -> str | None:
    """Refuse to run against a SQL_ASCII database.

    SQL_ASCII is not an encoding, it is the absence of one: Postgres stores
    and returns bytes with no validation or conversion. psycopg cannot decode
    text columns and hands back `bytes` instead of `str`, which broke this
    runner in the quietest way available -- applied() built a dict keyed by
    b'0001_jobs.sql', `path.name` is str, the `in` test never matched, and
    EVERY migration looked pending forever. Observed on the platform LXC
    2026-08-22 and reproduced locally; the container had no UTF-8 locale, so
    initdb defaulted to SQL_ASCII while the development container was UTF8.

    Refusing rather than coping with bytes is deliberate. The API (#36) and
    the web UI (#38) would each hit the same wall independently, and this
    database stores attacker-controlled filenames that will contain UTF-8 --
    text this project has to compare, index and render, not just echo.

    Note the defensive decode: under SQL_ASCII even `SHOW server_encoding`
    comes back as bytes, so a naive `== "SQL_ASCII"` silently passes.
    """
    value = conn.execute("SHOW server_encoding").fetchone()[0]
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    if value.upper() != "SQL_ASCII":
        return None
    return (
        "database encoding is SQL_ASCII; refusing to run.\n"
        "       psycopg returns bytes rather than str for every text column,\n"
        "       so migration bookkeeping silently never matches and each run\n"
        "       re-applies everything.\n"
        "       Recreate the database as UTF8 -- while it holds no analyses\n"
        "       this costs nothing, and after it does it means a dump and\n"
        "       restore:\n"
        "         dropdb sandbox_platform\n"
        "         createdb -O platform -E UTF8 -T template0 sandbox_platform"
    )


def applied(conn: psycopg.Connection) -> dict[str, str]:
    with conn.cursor() as cur:
        cur.execute("SELECT filename, sha256 FROM schema_migrations")
        return dict(cur.fetchall())


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--status", action="store_true",
                    help="report applied and pending, apply nothing")
    args = ap.parse_args()

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL is not set", file=sys.stderr)
        return 2

    files = discover()
    if not files:
        print(f"no migrations found in {MIGRATIONS_DIR}", file=sys.stderr)
        return 2

    # Checked for every file on every run, applied or not: a file that would
    # break the transaction contract should be rejected before anything runs,
    # not discovered halfway through a batch.
    if problems := [m for p in files if (m := check_no_transaction_control(p))]:
        for m in problems:
            print(f"ERROR: {m}", file=sys.stderr)
        return 1

    with psycopg.connect(dsn) as conn:
        if problem := check_encoding(conn):
            print(f"ERROR: {problem}", file=sys.stderr)
            return 1

        conn.execute(BOOTSTRAP)
        conn.commit()
        seen = applied(conn)

        # An applied migration whose bytes have changed is the failure this
        # check exists for: the file and the live database have silently
        # stopped describing the same schema, and everything built later
        # trusts the file. Refuse rather than guess.
        #
        # The fix is ALWAYS a new migration -- 0003_whatever.sql with an ALTER
        # -- never an edit to an applied one, because an edit cannot reach a
        # database that already ran the original. While a migration has not
        # been applied anywhere yet, editing it is free; the moment it lands
        # somewhere that cannot be dropped, it is frozen.
        for path in files:
            if path.name in seen and seen[path.name] != digest(path):
                print(f"ERROR: {path.name} was modified after it was applied.\n"
                      f"       Add a new migration; do not edit an applied one.\n"
                      f"       (If this is a throwaway dev database, drop and "
                      f"recreate it.)",
                      file=sys.stderr)
                return 1

        pending = [p for p in files if p.name not in seen]

        if args.status:
            for path in files:
                mark = "applied" if path.name in seen else "pending"
                print(f"{mark:>8}  {path.name}")
            return 0

        if not pending:
            print("up to date")
            return 0

        for path in pending:
            # Each migration and its bookkeeping row commit together, so an
            # interrupted run leaves the database consistent with
            # schema_migrations rather than half-applied and unrecorded.
            with conn.transaction():
                conn.execute(path.read_text())
                conn.execute(
                    "INSERT INTO schema_migrations (filename, sha256) VALUES (%s, %s)",
                    (path.name, digest(path)),
                )
            print(f"applied  {path.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())