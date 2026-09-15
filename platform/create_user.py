#!/usr/bin/env python3
"""Create an account directly, without the registration route.

DRAFT-061 decisions 1 and 3. `REGISTRATION_OPEN` is off by default, so on a
closed deployment this is the only way in -- and on an open one it is still how
the first account gets made, because signup needs a Telegram bot that may not be
configured yet.

    cd platform && .venv/bin/python create_user.py alice@example.com
    cd platform && .venv/bin/python create_user.py alice@example.com --set-password

**Two verbs, and the second exists because of the cut-over.** Migration 0009
seeded `identities` from the owners already in `jobs` and `tenants`, so a
deployment that ran behind Cloudflare Access came out of it holding identities
with an address, an `access_subject`, a prepaid balance and a history of
jobs -- and **no password**, because there was never anything to set one
with. Those accounts cannot be created (the address is taken, and rightly)
and cannot reset (reset needs a linked Telegram account they do not have).
`--set-password` is the way in for them.

**It never creates an identity, and creating never sets a password on one that
exists.** Those two guards are the same guard from opposite sides, and what
they protect is the binding between a person and their jobs: minting a second
identity for an address that already owns work leaves the work, the prepaid
balance and the `u/<uuid>/` object prefix with the old row while the password
logs into a new empty one.

**Safe to run against the deployment**, unlike the test suite: it writes only
the rows named above and reads nothing it does not write. `DATABASE_URL`
decides which database, and it defaults to the production name -- so running it
in the development container without setting that will politely create a user
in `sandbox_platform`, which may not be what was meant. It prints which
database it used before doing anything.

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

from sandbox_platform import auth, credentials, sessions
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


def _set_password(conn, cur, args, email: str, existing, hashed: str) -> int:
    """Give a password to an identity that already exists.

    **It refuses to create one.** An address with no identity behind it is
    almost always a typo, and inventing the row here would produce exactly the
    account `create_user.py` exists to make properly -- minus the tenants row,
    so its first balance read would create one silently.

    An upsert rather than an UPDATE, because the accounts this verb is for have
    no `tenant_credentials` row at all: 0009 seeded their identity from the
    owner column of a job, and there was no password in the Access era to seed
    beside it. The UPDATE half then covers the ordinary case of an operator
    resetting a password for someone who cannot use the Telegram route.

    The three lockout columns are cleared on the same statement, matching
    `auth.py`'s reset route: a new password that still refuses the login
    because the old one was typed wrong five minutes ago is indistinguishable
    from a password that did not take.

    **`totp_*` is deliberately untouched.** A second factor is not a password
    and this verb does not claim to be a recovery path for one -- if it wiped
    the secret, "set a password" would quietly become "remove MFA", which is
    the sentence an attacker with shell on the DomU would most like to be true.
    Whether one is enrolled is printed, so nobody is surprised at the prompt.
    """
    if existing is None:
        sys.exit(f"no identity for {email}"
                 f" -- omit --set-password to create one")

    # Named rather than ignored. Both write something this verb has no business
    # writing, and silently dropping them is how an operator concludes the
    # balance was topped up when it was not.
    for flag, value in (("--balance", args.balance),
                        ("--access-subject", args.access_subject)):
        if value is not None:
            sys.exit(f"{flag} is for creating an account, not for"
                     f" --set-password; change it with psql if that is"
                     f" really what is wanted")

    owner = existing[0]

    if args.telegram_id is not None:
        # Checked before writing, for the reason the create path checks
        # `access_subject`: `telegram_user_id` is UNIQUE, so a value another
        # identity holds is an operator mistake worth naming rather than an
        # IntegrityError traceback.
        cur.execute(
            "SELECT id FROM identities WHERE telegram_user_id = %s",
            (args.telegram_id,),
        )
        held = cur.fetchone()
        if held is not None and held[0] != owner:
            sys.exit(f"another identity is already linked to Telegram user"
                     f" {args.telegram_id}")
        cur.execute(
            "UPDATE identities"
            "   SET telegram_user_id = %s, telegram_verified_at = now()"
            " WHERE id = %s",
            (args.telegram_id, owner),
        )

    cur.execute(
        """
        INSERT INTO tenant_credentials (owner, hashed_password,
                                        password_changed_at)
             VALUES (%s, %s, now())
        ON CONFLICT (owner) DO UPDATE
                SET hashed_password = EXCLUDED.hashed_password,
                    password_changed_at = now(),
                    failed_attempts = 0,
                    last_failed_at = NULL,
                    locked_until = NULL
          RETURNING totp_confirmed_at IS NOT NULL
        """,
        (owner, hashed),
    )
    mfa = cur.fetchone()[0]

    # **Revoking is the point, not a courtesy** -- the same reason the reset
    # route does it. An operator setting a password by hand is usually doing it
    # because the old one is not trusted, and a session minted under it outlives
    # the change by REFRESH_TOKEN_TTL_DAYS otherwise.
    revoked = sessions.revoke_all_for_owner(conn, owner)

    cur.execute(
        "SELECT balance_seconds FROM tenants WHERE owner = %s", (owner,)
    )
    row = cur.fetchone()

    print(f"password set for {email}")
    print(f"  tenant id       {owner}")
    print(f"  balance         "
          f"{f'{row[0]} seconds' if row else 'no tenants row yet -- one is '
             'created, with the opening grant, the first time they load a page'}")
    print(f"  sessions ended  {revoked}")
    print(f"  second factor   {'still enrolled -- they will be asked for a code'
                               if mfa else 'none'}")
    if args.telegram_id is None:
        cur.execute(
            "SELECT telegram_user_id FROM identities WHERE id = %s", (owner,)
        )
        if cur.fetchone()[0] is None:
            print("  telegram linked no -- password reset will not work for"
                  " this account; pass --telegram-id to fix that")
    return 0


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
    parser.add_argument(
        "--set-password", action="store_true",
        help="set the password on an identity that ALREADY exists, instead of "
             "creating one; for the accounts migration 0009 seeded from the "
             "Access era, which have no credentials row and cannot reset",
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
        existing = cur.fetchone()

        if args.set_password:
            return _set_password(conn, cur, args, email, existing, hashed)

        if existing is not None:
            sys.exit(f"an identity already exists for {email}"
                     f" -- use --set-password to give it one")

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