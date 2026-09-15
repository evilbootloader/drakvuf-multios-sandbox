"""The out-of-band channel: signup verification and password reset.

DRAFT-061 decisions 1 and 2. Telegram rather than SMS because it needs no
carrier and no per-message cost, and because what it stores is a numeric user id
rather than a phone number -- a much smaller thing to hold, though still
personal data and still in DRAFT-022's erasure scope.

**Outbound only, via `getUpdates`. Never a webhook.** A webhook is an inbound
HTTP endpoint, and this platform has none by design: no public IP, no open
ports, everything through the tunnel. Polling keeps that property, at the cost
of a background task.

**A bot cannot message a user who has not started it**, which is what decides
the signup flow. The user taps `t.me/<bot>?start=<nonce>` or sends `/start`, and
only then can anything be delivered to them. So:

    /start            ->  an identity with a telegram id, no email, no password
    the bot replies   ->  a single-use code
    POST /auth/signup ->  the code, an address and a password, redeemed together

The identity exists before the address does, which is why `identities.email` is
nullable and why `verification_tokens.owner` is too. Nothing is granted and
nothing can be logged into until the code is redeemed.
"""

from __future__ import annotations

import asyncio
import logging
import secrets

import httpx

from .config import settings
from .credentials import CredentialsUnconfigured
from .db import connection

log = logging.getLogger(__name__)

_API = "https://api.telegram.org"

# Long-polling: Telegram holds the request open until an update arrives or this
# elapses, so the loop costs one connection rather than one request per second.
# Below the client timeout, so the server closes first and the difference is not
# read as a network failure.
_POLL_SECONDS = 25
_HTTP_TIMEOUT = 30.0

# How long a code is good for. Short because it travels instantly -- the user is
# already looking at Telegram when it arrives -- and because an unredeemed code
# is a credential lying around.
_CODE_TTL_MINUTES = 15

_task: asyncio.Task | None = None


def _require_bot_token() -> str:
    """The bot token, or a refusal.

    Empty is not a usable token: the Bot API would answer 401 for every call,
    so the failure would surface as "Telegram is down" rather than "this
    deployment was never configured". Refusing here names it once.
    """
    if not settings.telegram_bot_token:
        raise CredentialsUnconfigured(
            "TELEGRAM_BOT_TOKEN is unset; the verification channel is not "
            "configured"
        )
    return settings.telegram_bot_token


def send_message(chat_id: int, text: str) -> None:
    """Deliver one message, or log and move on.

    **Failures are not raised to the caller.** The caller is a route that has
    already decided to mint a code, and the code's existence is what matters;
    a delivery failure means the user retries rather than that the request was
    invalid. Raising would also turn Telegram being unreachable into a 500 on
    password reset, which tells an attacker nothing useful and the user nothing
    actionable.
    """
    try:
        httpx.post(
            f"{_API}/bot{_require_bot_token()}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=_HTTP_TIMEOUT,
        ).raise_for_status()
    except CredentialsUnconfigured:
        raise
    except Exception:
        log.exception("could not deliver a Telegram message to %s", chat_id)


def mint_code(conn, owner: str, purpose: str) -> str:
    """A single-use code for `owner`, stored as a hash.

    Hashed for the reason a refresh token is: the value is a bearer credential
    for the few minutes it lives, so a database disclosure would otherwise hand
    over every outstanding signup and reset.

    `token_urlsafe` rather than six digits: the code is copied out of a chat
    rather than typed from memory, so there is no usability argument for a short
    one, and a six-digit code is a million guesses that the rate limiter would
    otherwise have to be the only thing standing in front of.
    """
    from .credentials import hash_refresh_token

    code = secrets.token_urlsafe(16)
    conn.execute(
        """
        INSERT INTO verification_tokens (token_hash, owner, purpose, expires_at)
        VALUES (%s, %s, %s, now() + make_interval(mins => %s))
        """,
        (hash_refresh_token(code), owner, purpose, _CODE_TTL_MINUTES),
    )
    return code


def redeem_code(conn, code: str, purpose: str) -> str | None:
    """The owner a live code belongs to, marking it used. None if it is not.

    **One UPDATE, not a SELECT then an UPDATE.** Single-use has to be atomic:
    two requests arriving with the same code would both read it as unused and
    both proceed, which for a password reset means two parties setting a
    password. `used_at IS NULL` inside the statement is what makes the database
    pick a winner.

    `purpose` is matched as well as the hash, so a code minted to link a
    Telegram account cannot be redeemed as a password reset.
    """
    from .credentials import hash_refresh_token

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE verification_tokens
               SET used_at = now()
             WHERE token_hash = %s
               AND purpose = %s
               AND used_at IS NULL
               AND expires_at > now()
            RETURNING owner
            """,
            (hash_refresh_token(code), purpose),
        )
        row = cur.fetchone()
    return str(row[0]) if row else None


def handle_start(conn, telegram_user_id: int) -> str:
    """Link a Telegram account to an identity and return a signup code.

    Idempotent on the Telegram id, which `identities.telegram_user_id UNIQUE`
    enforces: pressing /start twice returns a second code for the same identity
    rather than creating a second account. That matters because the obvious
    thing to do when a code expires is to press it again.

    **The identity created here has no email and no credentials.** It cannot be
    logged into and has no balance -- `tenants` is written at signup, not here.
    So the growth this allows is one empty row per Telegram account that ever
    messages the bot, which is bounded by Telegram's own account creation and
    carries nothing worth stealing.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO identities (telegram_user_id, telegram_verified_at)
            VALUES (%s, now())
            ON CONFLICT (telegram_user_id)
            DO UPDATE SET telegram_verified_at = now()
            RETURNING id
            """,
            (telegram_user_id,),
        )
        owner = str(cur.fetchone()[0])

    return mint_code(conn, owner, "telegram_linking")


def handle_update(conn, update: dict) -> None:
    """Act on one update from `getUpdates`.

    Only `/start` is understood. Anything else is ignored rather than answered:
    a bot that replies to arbitrary text is a bot that can be used to send
    messages, and this one exists to deliver codes to people who asked for them.
    """
    message = update.get("message") or {}
    text = (message.get("text") or "").strip()
    sender = (message.get("from") or {}).get("id")

    if sender is None or not text.startswith("/start"):
        return

    # **Nothing is created when registration is closed**, not even the empty
    # identity. Minting a code nobody can redeem would be a row per Telegram
    # account that ever messages the bot, growing a table for a route that
    # refuses -- and it would tell the sender to go and try something that
    # cannot work.
    if not settings.registration_open:
        send_message(
            int(sender),
            "Registration is closed on this deployment. Ask the operator for "
            "an account.",
        )
        return

    code = handle_start(conn, int(sender))
    send_message(
        int(sender),
        "Your sandbox signup code:\n\n"
        f"{code}\n\n"
        f"It is valid for {_CODE_TTL_MINUTES} minutes and can be used once.",
    )


def poll_once(offset: int) -> tuple[int, int]:
    """One `getUpdates` pass. Returns `(next offset, updates handled)`.

    Separated from the loop so a test can drive it, the same shape
    `maintenance.sweep` uses.

    **The offset is how Telegram acknowledges.** Asking for `last_id + 1` is
    what tells the server the previous batch was processed; without advancing
    it, the same updates arrive forever and every /start is answered repeatedly.
    """
    response = httpx.get(
        f"{_API}/bot{_require_bot_token()}/getUpdates",
        params={"offset": offset, "timeout": _POLL_SECONDS},
        timeout=_HTTP_TIMEOUT + _POLL_SECONDS,
    )
    response.raise_for_status()
    updates = response.json().get("result", [])

    handled = 0
    for update in updates:
        try:
            with connection() as conn:
                handle_update(conn, update)
            handled += 1
        except Exception:
            # One malformed update must not stop the rest of the batch, and
            # must not stop the offset advancing -- otherwise it is redelivered
            # forever and the channel wedges on a single bad message.
            log.exception("could not handle Telegram update %s",
                          update.get("update_id"))

    if updates:
        offset = max(u["update_id"] for u in updates) + 1
    return offset, handled


async def _loop() -> None:
    offset = 0
    while True:
        try:
            offset, handled = await asyncio.to_thread(poll_once, offset)
            if handled:
                log.info("handled %d Telegram update(s)", handled)
        except CredentialsUnconfigured:
            # Unconfigured is not a transient failure. Log once a minute rather
            # than once a second, and keep the task alive so setting the token
            # and restarting is the only step needed.
            log.warning("Telegram polling idle: no bot token configured")
            await asyncio.sleep(60)
        except Exception:
            log.exception("Telegram poll failed")
            await asyncio.sleep(5)


def start() -> None:
    global _task
    if not settings.telegram_bot_token:
        log.warning("Telegram disabled: signup and password reset will not work")
        return
    _task = asyncio.create_task(_loop())


async def stop() -> None:
    global _task
    if _task is None:
        return
    _task.cancel()
    try:
        await _task
    except asyncio.CancelledError:
        pass
    _task = None