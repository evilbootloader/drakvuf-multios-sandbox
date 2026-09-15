#!/usr/bin/env python3
"""Create an account directly, without the registration route.

DRAFT-061 decisions 1 and 3. `REGISTRATION_OPEN` is off by default, so on a
closed deployment this is the only way in -- and on an open one it is still how
the first account gets made, because signup needs a Telegram bot that may not be
configured yet.

    cd platform && .venv/bin/python create_user.py alice@example.com

**Safe to run against the deployment**, unlike the test suite: it inserts three
rows and reads nothing it does not write. `DATABASE_URL` decides which database,
and it defaults to the production name -- so running it in the development
container without setting that will politely create a user in
`sandbox_platform`, which may not be what was meant. It prints which database it
used before doing anything.

**The password is prompted for, never an argument.** A password on the command
line is in `ps` output for every user on the host, in the shell history file,
and in any process accounting -- three places it outlives the terminal. Piping
from stdin is supported for scripted use, where the caller has already decided
where the value comes from.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys

import psycopg

from sandbox_platform import auth, credentials
from sandbox_platform.config import settings


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        password = sys.stdin.readline().rstrip("\n")
        if not password:
            sys.exit("no password on stdin")
        return password

    password = getpass.getpass("Password: ")
    if len(password) < 12:
        # The same floor `SignupRequest` applies. An operator-made account that
        # could not have been made through the route is a difference nobody
        # documents and everybody is surprised by.
        sys.exit("password must be at least 12 characters")
    if password != getpass.getpass("Repeat: "):
        sys.exit("passwords do not match")
    return password


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("email")
    parser.add_argument(
        "--telegram-id", type=int, default=None,
        help="link a Telegram account, so password reset works for this user",
    )
    parser.add_argument(
        "--balance", type=int, default=None,
        help="opening analysis seconds (default: the column default in 0008)",
    )
    parser.add_argument(
        "--password-stdin", action="store_true",
        help="read the password from stdin instead of prompting",
    )
    # **The one place the two keyspaces may deliberately be joined.**
    #
    # `resolve_tenant` refuses to infer that a signup address and an Access
    # assertion are the same person -- inferring it is the pre-hijacking hole
    # DRAFT-061 closed, because signup takes an address entirely on trust. An
    # OPERATOR may know it, from evidence this platform does not have, and this
    # is how that knowledge gets recorded. Without it the same human arriving
    # through Access mints a second identity beside this one.
    #
    # Pass exactly what `access_identity` would report for them: their address
    # as the identity provider spells it, or `service:<common_name>` for a
    # service token. Anything else silently binds nothing.
    parser.add_argument(
        "--access-subject", default=None, metavar="SUBJECT",
        help="bind this account to an existing Cloudflare Access identity "
             "(their address, or service:<common_name>); omit unless you know "
             "they are the same person",
    )
    args = parser.parse_args()

    # The same predicate `SignupRequest` applies, imported rather than repeated:
    # an operator-made account that could not have been made through the route
    # is a difference nobody documents and everybody is surprised by.
    email = args.email.strip().lower()
    if not auth.address_admissible(email):
        sys.exit(f"not an email address: {email!r}")

    dsn = os.environ.get("DATABASE_URL", settings.database_url)
    print(f"database: {dsn}")

    password = _read_password(args.password_stdin)
    # Hashed before the connection is opened, so the ~100ms of argon2 is not
    # spent holding one.
    hashed = credentials.hash_password(password)

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        # The whole thing in one transaction: an identity with no credentials
        # row is an account nobody can log into and nobody can re-create,
        # because the address is taken.
        cur.execute(
            "SELECT id FROM identities WHERE lower(email) = %s", (email,)
        )
        if cur.fetchone() is not None:
            sys.exit(f"an identity already exists for {email}")

        # Checked separately, and before the insert rather than by catching the
        # unique violation: binding to a subject some other identity already
        # holds is an operator mistake worth naming, not a crash. It also means
        # the address check above cannot be mistaken for covering both columns.
        subject = args.access_subject.strip() if args.access_subject else None
        if subject is not None:
            cur.execute(
                "SELECT id FROM identities"
                " WHERE lower(access_subject) = lower(%s)",
                (subject,),
            )
            if cur.fetchone() is not None:
                sys.exit(f"another identity is already bound to {subject!r}")

        # **Every placeholder is cast.** Without `::bigint` Postgres cannot
        # infer the type of a bare NULL in either position and refuses the
        # statement outright -- so the script worked with `--telegram-id` and
        # failed without it, which is the common case. `::text` is here for the
        # same reason, for `--access-subject`.
        cur.execute(
            """
            INSERT INTO identities (email, access_subject, telegram_user_id,
                                    telegram_verified_at)
            VALUES (%s, lower(%s::text), %s::bigint,
                    CASE WHEN %s::bigint IS NULL THEN NULL ELSE now() END)
            RETURNING id
            """,
            (email, subject, args.telegram_id, args.telegram_id),
        )
        owner = cur.fetchone()[0]

        cur.execute(
            "INSERT INTO tenant_credentials (owner, hashed_password)"
            " VALUES (%s, %s)",
            (owner, hashed),
        )

        if args.balance is None:
            # Left to the column default rather than repeated here: 0008's
            # comment says to read the grant back from the row and never
            # hardcode it, precisely so this script cannot disagree with the
            # schema about what a new tenant gets.
            cur.execute("INSERT INTO tenants (owner) VALUES (%s)", (owner,))
        else:
            cur.execute(
                "INSERT INTO tenants (owner, balance_seconds) VALUES (%s, %s)",
                (owner, args.balance),
            )

        cur.execute(
            "SELECT balance_seconds FROM tenants WHERE owner = %s", (owner,)
        )
        balance = cur.fetchone()[0]

    print(f"created {email}")
    print(f"  tenant id       {owner}")
    print(f"  balance         {balance} seconds")
    print(f"  telegram linked {'yes' if args.telegram_id else 'no -- password '
                               'reset will not work for this account'}")
    print(f"  access subject  {subject if subject else 'none -- signing in '
                              'through Cloudflare Access will create a SECOND '
                              'identity, not reach this one'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())