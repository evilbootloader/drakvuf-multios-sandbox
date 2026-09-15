-- 0009_tenant_credentials.sql -- an opaque identity of record, and somewhere to
-- keep credentials we hold ourselves.
--
-- DRAFT-061 decisions 2 and 3. NO BEGIN/COMMIT -- run.py owns the transaction,
-- per the note at the head of 0001_jobs.sql. That matters more here than in any
-- previous migration: this one REWRITES existing rows, so a partial application
-- would leave `jobs.owner` half email and half uuid, and no later run could tell
-- which was which.
--
-- **The email stops being an identifier and becomes an attribute.** Until now
-- the Access identity -- an email address -- was the join key everything hung
-- off: `jobs.owner`, `tenants.owner`, `auth.visible_to`, and the object key
-- prefix that 0008 decision 7 built from it. An address is a poor identifier for
-- two reasons that only get more expensive with time.
--
-- **Erasure is the one that decides it.** 0008 put the submitter's address in
-- the S3 key path, and `16-deploy-tenancy-and-quota.md` records what that costs:
-- "An email address in an object key cannot be erased by nulling a column ... a
-- DRAFT-022 erasure request means copy-and-delete across live malware, plus
-- MinIO's access logs and any backups." With an opaque id in the path, keys hold
-- no personal data at all and erasure is one UPDATE. Every job submitted before
-- this migration writes another address into the bucket, which is why it is
-- worth doing now rather than after the second tenant.
--
-- The second reason is smaller: an address can change, and a join key cannot.
--
-- **Three tables, each with one job**, which is DRAFT-061 decision 2 carried one
-- step further than it was written:
--
--   identities          who someone is           -- id, email, access_subject
--   tenants             what they have paid for  -- balance_seconds
--   tenant_credentials  how they prove it        -- argon2id hash, lockout
--
-- `email` and `access_subject` are two names for the same person and are NOT
-- interchangeable: the first is a login address this platform accepts on trust
-- at signup, the second is what an external provider asserts. Resolution joins
-- on the second and never on the first. The comment on that column has why, and
-- it is the one thing in this file that is a security boundary rather than a
-- schema preference.
--
-- Decision 2 argued only for keeping credentials out of `tenants`, because
-- `SELECT balance_seconds` runs on every page load and that query should not
-- touch password hashes. Splitting `identities` out as well is what makes the
-- rest of the argument hold: the jobs list needs the email for its Owner column,
-- so without a third table the display join would read either the balance row or
-- the hash row on every render. As it stands the balance page touches no hash
-- AND no address, and the display join touches no hash.
--
-- It is also what lets erasure and retention pull in opposite directions without
-- fighting, which decision 2 named as the second reason: null
-- `identities.email` and drop the credentials row, while the `tenants` row --
-- a financial record -- survives untouched.
--
-- **`uuid` rather than `text` holding a uuid.** Checked against Postgres 18
-- before choosing: `WHERE owner = %s` with a plain Python `str` still matches a
-- `uuid` column, in dashed, undashed and upper-case forms alike, because
-- Postgres normalises the text representation inside the comparison. So
-- `auth.visible_to`, `_owned_or_404` and `create_job` need no change, `Identity`
-- stays `str`, and the whole class of case-folding bug moves from "a convention
-- Python has to keep" to "a thing the database cannot get wrong". `text` would
-- have worked and would have kept that risk.

CREATE TABLE identities (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email       varchar(254),
    access_subject text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    telegram_user_id bigint UNIQUE,
    telegram_verified_at timestamptz
);

-- DRAFT-061 decision 3. A long-lived, revocable credential, so that the access
-- token can be short-lived: the short one is checked by signature alone and
-- cannot be withdrawn before it expires, and this is what makes "log out
-- everywhere" and "this session was stolen" expressible at all.
CREATE TABLE refresh_tokens (
    id          serial PRIMARY KEY,
    token_hash  text NOT NULL UNIQUE,
    owner       uuid NOT NULL,
    replaced    integer REFERENCES refresh_tokens(id),
    CONSTRAINT  fk_owner FOREIGN KEY (owner) REFERENCES identities(id),
    issued_at   timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz
);

COMMENT ON TABLE refresh_tokens IS
    'Long-lived session credentials, one row per issued refresh token. Rotated '
    'on every use: presenting a token mints a new row and points the old one at '
    'it through `replaced`, so a token is valid exactly once. Deliberately its '
    'own table rather than sharing `verification_tokens` -- these rotate and '
    'live for weeks, those are single-use and live for minutes, and merging '
    'them would mean one expiry policy for both.';

COMMENT ON COLUMN refresh_tokens.token_hash IS
    'A HASH of the token, never the token. Same reasoning as a password hash: '
    'the value handed to the browser is a bearer credential, so a database '
    'disclosure -- a dump, a backup, a read-only SQL injection -- would '
    'otherwise hand over every live session rather than merely the means to '
    'crack them offline. UNIQUE because this is the lookup key, which also '
    'provides the index the login path needs.';

COMMENT ON COLUMN refresh_tokens.replaced IS
    'The token issued in place of this one, or NULL if it has not been rotated. '
    '**NULL is the meaningful state and the reason this column is nullable**: a '
    'live token has no successor. It was briefly declared `serial`, which is '
    'not a type but `integer NOT NULL DEFAULT nextval(...)`, so every row was '
    'born pointing at its own id and every live token looked already replaced.'
    ' '
    'What it buys is REUSE DETECTION. A token that is presented after it has '
    'been replaced is not a mistake -- the legitimate client moved on to the '
    'successor -- so it means the value leaked and two parties hold it. The '
    'correct response is to revoke the whole chain, not just the replay, '
    'because which of the two holders is the attacker cannot be known.';

COMMENT ON COLUMN refresh_tokens.expires_at IS
    'NOT NULL deliberately: a NULL here would be an immortal session, and NULL '
    'is exactly what a buggy INSERT that forgets the column would produce. The '
    'failure mode of this constraint is a loud error at issuance; the failure '
    'mode without it is a credential that never stops working.';

COMMENT ON COLUMN refresh_tokens.revoked_at IS
    'When this token was withdrawn, or NULL. Distinct from `expires_at` because '
    'the two answer different questions -- expiry is scheduled and revocation '
    'is a decision, and an audit needs to tell "the session timed out" from '
    '"someone logged out, or we detected a replay". Rows are kept rather than '
    'deleted so a replayed token still finds its row and is recognised as '
    'revoked rather than as unknown.';

-- Short-lived single-use codes, shared by password reset and Telegram linking
-- because the mechanics are identical: mint a secret, deliver it out of band,
-- accept it once, within a few minutes. Two tables would have been two copies of
-- the same expiry and single-use logic.
CREATE TABLE verification_tokens (
    token_hash  text PRIMARY KEY,
    owner       uuid,
    purpose     text NOT NULL,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    CONSTRAINT  fk_owner FOREIGN KEY (owner) REFERENCES identities(id),
    CONSTRAINT verification_tokens_purpose_known
        CHECK (purpose IN ('telegram_linking', 'password_reset'))
);

COMMENT ON TABLE verification_tokens IS
    'Single-use codes delivered out of band, for password reset and Telegram '
    'linking. `token_hash` is the PRIMARY KEY, which is what makes single-use '
    'enforceable: without it two rows could carry one token and "has it been '
    'used?" would depend on which was read.';

COMMENT ON COLUMN verification_tokens.owner IS
    'NULLABLE ON PURPOSE, unlike `refresh_tokens.owner`, and the difference is '
    'the whole reason this column is worth a comment. A password reset belongs '
    'to an existing identity; a Telegram linking nonce is minted DURING signup, '
    'before any identity row exists -- the nonce travels in the deep link, the '
    'user taps it, and what comes back from Telegram is what the new identity '
    'is then built around. A NOT NULL here would make signup impossible.';

COMMENT ON COLUMN verification_tokens.purpose IS
    'NOT NULL, and that is load-bearing rather than tidiness. A CHECK fails only '
    'on FALSE, and `NULL IN (...)` evaluates to NULL -- so while this column was '
    'nullable the constraint below admitted a NULL purpose and the enumeration '
    'was advisory. Measured, not assumed.'
    ' '
    'Separating the two purposes matters because they are not interchangeable: '
    'a token minted to link a Telegram account must not be redeemable as a '
    'password reset. The redeeming code has to match on purpose as well as on '
    'the hash, and this constraint is what keeps the set of purposes closed.';

COMMENT ON COLUMN verification_tokens.used_at IS
    'When it was redeemed, or NULL. Set rather than deleted so a second '
    'presentation is recognised as ALREADY USED rather than as unknown -- the '
    'same argument as `refresh_tokens.revoked_at`, and the reason neither table '
    'reclaims space by deleting rows that still have something to say. '
    '`maintenance._loop` is where the genuinely expired ones go.';

-- Fixed-window counters for the attempts that do NOT resolve to an account:
-- unknown addresses and signup spam. Per-account throttling needs none of this
-- and is already in `tenant_credentials` -- `failed_attempts`, `locked_until`,
-- `last_failed_at` -- which is the case that matters most, since credential
-- stuffing targets an address someone knows exists.
--
-- **In Postgres rather than in the process**, though uvicorn runs single-worker
-- today and a dict would be coherent. It would be coherent by accident: nothing
-- records single-worker as a contract, `--workers` is the obvious first answer
-- to load, and a restart resets the counter -- with `Restart=on-failure` and
-- deploys, an attacker need not even cause one. This project has already been
-- bitten by in-process state exactly once, in F11, where the console registry
-- lived in one process while the platform ran two and sessions hung with no
-- error. Redis was rejected on different grounds: a new service, a new failure
-- mode, and one more thing to secure on a host whose neighbour runs malware.
--
-- The write cost is not the constraint. The route this protects already runs
-- argon2id, which is orders of magnitude dearer than an UPSERT.
CREATE TABLE rate_limit (
    window_start    timestamptz,
    bucket_key      text,
    count           bigint NOT NULL DEFAULT 1,
    CONSTRAINT pk_rate_limit PRIMARY KEY (window_start, bucket_key)
);

COMMENT ON TABLE rate_limit IS
    'Fixed-window attempt counters, one row per bucket per window. The PRIMARY '
    'KEY is what makes the design work at all: incrementing is an UPSERT with '
    '`ON CONFLICT (window_start, bucket_key)`, and without a matching unique '
    'constraint Postgres refuses the statement -- every attempt would insert a '
    'fresh row, every count would stay 1, and the limiter would never fire. '
    'Expired windows are swept by `maintenance._loop`, which already owns the '
    'periodic DB work.';

COMMENT ON COLUMN rate_limit.bucket_key IS
    'What is being limited, as `<kind>:<value>` -- `ip:203.0.113.5` today. '
    '**The client IP is a trust boundary, not an input.** Behind Caddy it '
    'arrives as a forwarded header and through Cloudflare as CF-Connecting-IP, '
    'so it must be read from the one source the proxy sets unconditionally and '
    'refused from anywhere else. A limiter keyed on a header the caller can '
    'set is decorative: the attacker rotates it. Same discipline as the '
    'verified-subject header in DRAFT-061 decision 5, and it belongs in the '
    'same test.';

COMMENT ON COLUMN rate_limit.count IS
    'Attempts in this window. **This bounds attempts over time and does NOT '
    'bound concurrent memory**, which is a separate limit the login path needs: '
    'each argon2id hash allocates its `m` parameter for as long as it runs, so '
    'requests arriving together all allocate before any window closes. On a '
    '2048 MiB DomU (the figure as DEPLOYED -- `CURRENT-STATE.md` also carries a '
    'committed-but-unapplied 4096) that is a memory-exhaustion lever no counter '
    'here can close. The cap on concurrent hashes is what closes it.';

COMMENT ON TABLE identities IS
    'Who a tenant is. The identity of record since 0009: `id` is what '
    '`jobs.owner`, `tenants.owner` and `tenant_credentials.owner` all join on, '
    'and the email is an attribute of it rather than a key. Created at signup, '
    'unlike the `tenants` row, which is still created on first contact.';

COMMENT ON COLUMN identities.email IS
    'Login address, lower-cased. NULLABLE ON PURPOSE: a DRAFT-022 erasure nulls '
    'this and drops the credentials row, leaving the id and the `tenants` '
    'balance -- a financial record -- intact. A unique index over lower(email) '
    'permits many NULLs, so erasing a second account does not collide with the '
    'first.';

COMMENT ON COLUMN identities.access_subject IS
    'What the EXTERNAL identity provider calls this identity, or NULL for one '
    'that no provider has ever asserted. `auth.resolve_tenant` resolves on this '
    'column and on nothing else.'
    ' '
    '**A separate column from `email` because they have different writers, and '
    'that is the whole point of it.** While resolution joined on `email`, one '
    'user-writable column was the join key for two independent issuers: '
    '`/auth/signup` takes an address on trust -- a Telegram code proves control '
    'of a Telegram account, never of an address -- so claiming an address no '
    'identity held yet meant the next Access assertion for it resolved to the '
    'CLAIMANT''s row, handing over that tenant''s jobs, balance and object '
    'prefix. Nothing is written here by any route a stranger can reach, so the '
    'two keyspaces cannot collide however the address column is filled.'
    ' '
    'Holds the string `auth.access_identity` returns: an address for a user, '
    '`service:<common_name>` for a service token. Deliberately NOT the JWT''s '
    '`sub` claim, which is the better identifier and cannot be backfilled -- '
    'there is no way to derive a Cloudflare subject id from an address without '
    'asking Cloudflare, so migrating to it would orphan every row seeded below '
    'from its jobs. `text` rather than `varchar(254)` so that switching to one '
    'later is a write and not a column change; `auth.MAX_EMAIL_OCTETS` is what '
    'bounds what reaches it today.'
    ' '
    '**In DRAFT-022 erasure scope, exactly like the email**, and the one that is '
    'easy to miss: erasure now nulls two columns rather than one.';

COMMENT ON COLUMN identities.telegram_user_id IS
    'The Telegram account this identity signed up with. `bigint` because '
    'Telegram ids are int64; UNIQUE so two accounts cannot claim one Telegram '
    'user, which is the whole of what the signup gate buys.'
    ' '
    '**Still personal data, and in DRAFT-022 erasure scope exactly like the '
    'email.** It is pseudonymous rather than anonymous -- it singles out a '
    'person and resolves to a real account -- so "no PII" is not the right '
    'description of it. It is a large improvement on storing a phone number, '
    'which is what it replaced, and nulling it is the erasure action.';

COMMENT ON COLUMN identities.telegram_verified_at IS
    'When the link was PROVEN, not when it was claimed. Nullable until then, so '
    'an unverified row cannot be mistaken for a verified one by a query that '
    'only checks the id is present.'
    ' '
    'Proven by the deep-link nonce in `verification_tokens`: a Telegram bot '
    'cannot message a user who has not started it, so the flow must be user-'
    'initiated -- signup mints a nonce, the user taps `t.me/<bot>?start=<nonce>`,'
    ' and the nonce coming back is what binds that Telegram account to that '
    'signup attempt. Read through `getUpdates` polling and NEVER a webhook: a '
    'webhook is an inbound HTTP endpoint, which is the one thing this '
    'architecture does not have.';

COMMENT ON COLUMN identities.created_at IS
    'When the account was created. NOT the same question as tenants.created_at, '
    'which 0008 defines as first CONTACT -- written by the balance endpoint or '
    'create_job, so it can post-date signup by any amount and does not exist at '
    'all for someone who signed up and never submitted. This is the column to '
    'ask "when did this person appear", including when asking it of a burst of '
    'signups. Rows backfilled by 0009 carry the migration''s own timestamp, '
    'which is the earliest date this platform can honestly claim to know.';

-- **Refuse to run rather than merge two balances into one.**
--
-- Seeding lower-cases every address, so two `tenants` rows differing only in
-- case collapse to ONE identity -- and then both are rewritten to the same uuid
-- and collide on `tenants_pkey`. Merging is very likely the right answer for a
-- real duplicate, because they are one person, but it is a DATA decision and not
-- one a migration may take silently: their `balance_seconds` have to be summed,
-- and picking a row to keep would discard prepaid analysis seconds someone paid
-- for. That is a financial error, not a rounding one.
--
-- So this aborts, names the addresses, and says what to do. A guard rather than
-- a comment for the reason `check_no_transaction_control` in run.py is a check
-- rather than a comment: a precondition a human has to remember is not a
-- precondition. It costs one aggregate over a table with a handful of rows.
DO $guard$
DECLARE
    collisions text;
BEGIN
    SELECT string_agg(format('%s (%s rows)', addr, n), ', ' ORDER BY addr)
      INTO collisions
      FROM (
        SELECT lower(owner) AS addr, count(*) AS n
          FROM tenants
         GROUP BY 1
        HAVING count(*) > 1
      ) d;

    IF collisions IS NOT NULL THEN
        RAISE EXCEPTION
            'tenants holds addresses differing only in case: %', collisions
            USING HINT =
                'Each collapses to one identity, so the tenants rows would '
                'collide on tenants_pkey and one prepaid balance would be '
                'lost. Sum balance_seconds into a single row per address, '
                'delete the rest, then re-run this migration.';
    END IF;
END
$guard$;

-- **Seeded from `jobs` as well as `tenants`, and the second branch is not
-- redundant.** 0008 created `tenants` with no backfill, and its own comment says
-- rows are "created on first contact by the balance endpoint or create_job,
-- never by an admin" -- so a job submitted BEFORE 0008 has an owner that was
-- never recorded in `tenants` at all. Seeding from `tenants` alone leaves those
-- rows matching nothing in the UPDATE below, still holding an address, and the
-- migration dies at `ALTER COLUMN owner TYPE uuid` with `invalid input syntax
-- for type uuid`. Measured against a job history shaped that way, not reasoned
-- about.
--
-- `UNION`, not `UNION ALL`: the de-duplication is the point, and it is also why
-- neither branch needs its own DISTINCT.
--
-- An identity seeded from `jobs` alone ends up with no `tenants` row, which is
-- correct and not a missing backfill -- there is no foreign key in that
-- direction, and `routers/account.py` creates the balance row on first contact
-- exactly as it does for anyone else.
--
-- Lower-cased on the way in, the same normalisation `objects.owner_prefix`
-- already applies when it builds a key. The address as the identity provider
-- spelled it is not preserved anywhere; that is a deliberate loss, because two
-- spellings already shared one object prefix and pretending otherwise is the
-- ambiguity this migration exists to remove.
-- **The length filter EXCLUDES rather than aborts, and that is a deliberate
-- choice with a consequence worth stating.** Confirmed with the operator
-- 2026-09-11: the production database holds no owner longer than 254, so the
-- filter selects nothing out today and is here as an expression of intent.
--
-- `length()` and not `octet_length()`, because what this filter has to protect
-- is the `varchar(254)` column below, and that counts characters. The
-- application bound (`auth.MAX_EMAIL_OCTETS`) counts octets and is stricter, so
-- the two measure different things on purpose -- each matches what it guards.
--
-- **If it ever does exclude a row, the failure lands 40 lines below and names
-- the wrong cause.** An excluded owner gets no `identities` row, so the UPDATEs
-- that follow match nothing for it, its address survives, and
-- `ALTER COLUMN owner TYPE uuid` fails with `invalid input syntax for type
-- uuid: "<the address>"` -- which reads as a broken identity mapping rather
-- than as a length exclusion. Measured, not predicted: seeded with a 257-
-- character owner, that is the exact error. If that ever happens, look here
-- first.
-- **`access_subject` gets the same value, and every seeded row is entitled to
-- it.** These addresses come from `jobs.owner` and `tenants.owner`, which until
-- this migration held whatever `auth.access_identity` returned -- so each one is
-- by construction an identity some external provider already asserted, not a
-- self-claimed address. Seeding only `email` would leave the existing tenants
-- resolving to nothing on their next request and minting fresh identities beside
-- their own jobs.
INSERT INTO identities (email, access_subject)
    (SELECT lower(owner), lower(owner) FROM tenants WHERE length(owner) <= 254
      UNION
     SELECT lower(owner), lower(owner) FROM jobs WHERE length(owner) <= 254);

-- Created AFTER the insert above, which is safe only because the `UNION` there
-- cannot emit the same address twice. The order is not what protects this -- put
-- the index first and the insert would still have to be collision-free -- the
-- de-duplication is.
--
-- **Functional, so `WHERE email = %s` cannot use it.** Verified with
-- `enable_seqscan = off`: an equality query on the bare column still sequential
-- scans, while `WHERE lower(email) = lower(%s)` index-scans. Login must be
-- written the second way -- which it wants to be regardless, since that is also
-- what makes `Alice@` and `alice@` the same account.
CREATE UNIQUE INDEX identities_email_lower_unique
    ON identities (lower(email));

-- **Lower-cased, and the seed above is why rather than taste.** A provider
-- subject is an identifier and there is a real argument for matching it byte for
-- byte -- but the rows seeded from `jobs.owner` were lower-cased on the way in,
-- and 0009 records that "the address as the identity provider spelled it is not
-- preserved anywhere". So a case-sensitive lookup would MISS every existing
-- tenant whose Access address is not already lower-case, mint a second identity
-- beside their own jobs, and hand them an empty history and a fresh balance.
-- Folding case is what makes the backfill and the lookup agree.
--
-- Nothing about the security property depends on this. What closes the
-- pre-hijacking hole is that no route a stranger can reach writes this column;
-- the case rule only decides which rows are the same row.
--
-- UNIQUE for the reason `identities_email_lower_unique` is: it is the lookup
-- key, so two rows sharing one subject would make the answer depend on row
-- order. Many NULLs are permitted, which is what lets every signup-only and
-- Telegram-only identity coexist without a partial index.
CREATE UNIQUE INDEX identities_access_subject_lower_unique
    ON identities (lower(access_subject));

-- Rewrite both owner columns BEFORE re-typing them: `owner` is still `text` at
-- this point, which is the only reason `i.id::text` can be assigned to it. The
-- foreign keys come last, after the values they constrain exist -- added any
-- earlier they would have nothing to point at.
--
-- `lower(i.email)` is redundant on the left, since the insert above lower-cased
-- it. Kept so the join reads as the same rule on both sides rather than relying
-- on the reader remembering the insert.
UPDATE tenants t
    SET owner = i.id::text
    FROM identities i
    WHERE lower(i.email) = lower(t.owner);

-- No ON DELETE, so both foreign keys here are NO ACTION by omission, and that is
-- the intent: deleting an identity is refused while any balance or any job still
-- references it. It makes "erasure nulls the email, it never deletes the row" a
-- fact the schema enforces rather than a convention DRAFT-022 has to remember.
ALTER TABLE tenants
    ALTER COLUMN owner TYPE uuid USING owner::uuid,
    ADD CONSTRAINT tenants_owner_fkey
    FOREIGN KEY (owner)
    REFERENCES identities(id);

UPDATE jobs j
    SET owner = i.id::text
    FROM identities i
    WHERE lower(i.email) = lower(j.owner);

-- **`key_prefix` is deliberately NOT rewritten, and that is what makes this
-- migration safe against a populated bucket.** 0008 stored the prefix instead of
-- deriving it for exactly this case -- "a later change to the naming rule must
-- not move objects that were already written under the old one" -- so a row
-- legitimately ends up with a uuid `owner` beside a `key_prefix` of
-- `u/alice@example.com/b98/`, and every key builder still reproduces the key
-- byte for byte by concatenating the stored value.
--
-- So the column now holds three naming eras: `''` for pre-#40 flat keys,
-- `u/<email>/<shard>/` for #40, and `u/<uuid>/<shard>/` from here on. The 0008
-- CHECK (`^u/[^/]+/[0-9a-f]{3}/$`) accepts all three unchanged -- verified, not
-- assumed -- so no constraint moves.
--
-- **Anyone tempted to "tidy" the old prefixes should price it first**: it is a
-- copy-and-delete of every object in a bucket of live malware, which is the same
-- operation this migration exists to avoid ever having to perform.
ALTER TABLE jobs
    ALTER COLUMN owner TYPE uuid USING owner::uuid,
    ADD CONSTRAINT jobs_owner_fkey
    FOREIGN KEY (owner)
    REFERENCES identities(id);

-- DRAFT-061 decision 3: the platform issues its own credentials, which is
-- security-critical surface it did not previously have. Kept beside `tenants`
-- rather than inside it because auth grows columns -- MFA secrets, recovery
-- codes, more counters -- and a seconds balance does not.
--
-- One row per identity, enforced by the PRIMARY KEY: two hashes for one account
-- would make login's answer depend on row order.
CREATE TABLE tenant_credentials (
    owner           uuid PRIMARY KEY REFERENCES identities(id),
    hashed_password text NOT NULL,
    failed_attempts int NOT NULL DEFAULT 0,
    locked_until    timestamptz DEFAULT NULL,
    last_failed_at  timestamptz DEFAULT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    password_changed_at timestamptz,
    totp_secret text,
    totp_confirmed_at timestamptz,
    totp_last_step bigint
);

COMMENT ON TABLE tenant_credentials IS
    'How a tenant proves who they are. Read only by the login path -- never by '
    'the balance endpoint, which is why it is not part of `tenants`, and never '
    'by the jobs list, which is why the email is not part of this.';

COMMENT ON COLUMN tenant_credentials.hashed_password IS
    'argon2id. The cost parameters are encoded in the hash string itself, so a '
    'later change to them is a rehash-on-next-login and not a migration. Note '
    'that every unauthenticated login attempt now runs argon2id on this DomU: '
    'the memory cost is an availability lever as much as a security one, and '
    'Cloudflare Access no longer absorbs the attempts.';

COMMENT ON COLUMN tenant_credentials.locked_until IS
    'When a lockout expires, or NULL. A timestamp rather than a boolean so it '
    'clears itself -- nothing has to run to unlock an account.';

COMMENT ON COLUMN tenant_credentials.last_failed_at IS
    'When the counter beside it last moved. This is what lets failed_attempts '
    'DECAY: a bare counter that only ever increases locks an account out on its '
    'fifth lifetime typo.';

COMMENT ON COLUMN tenant_credentials.totp_secret IS
    'The TOTP shared secret, or NULL where MFA is not enrolled. **Here rather '
    'than on `tenants`**, which is where it briefly was: `routers/account.py` '
    'reads `tenants` on every page load, and decision 2 exists precisely so '
    'that query never touches a secret. This table is read by the login path '
    'and nothing else.'
    ' '
    'TOTP rather than SMS, although signup already proves a Telegram account: '
    'a messaging channel is a delivery mechanism someone else can take over, '
    'and TOTP needs no provider, no per-message cost and no outbound call on '
    'the login path.'
    ' '
    'KNOWN GAP (DRAFT-061): stored in the clear, so a database disclosure '
    'yields the second factor alongside the password hash it was meant to be '
    'independent of. Encrypting it with a key from `api.env` would not survive '
    'a host compromise -- which already owns everything -- but would cover the '
    'dump, backup and read-only-injection cases. Decide that before MFA is '
    'offered to anyone, not after.';

COMMENT ON COLUMN tenant_credentials.totp_confirmed_at IS
    'When a code was first verified, or NULL while enrolment is incomplete. '
    'Enrolment is not finished when the secret is generated -- it is finished '
    'when the user has proven their authenticator agrees. Treating a generated '
    'secret as active is how people lock themselves out of their own account '
    'between scanning the QR code and it working.';

-- **What erasure has to do about sessions, stated once here because the schema
-- does not say it.** Every foreign key in this migration is NO ACTION by
-- omission, `refresh_tokens.owner` and `verification_tokens.owner` included. So
-- a DRAFT-022 erasure cannot simply delete the identity: it has to delete that
-- identity's refresh tokens and verification tokens first, then drop the
-- credentials row, then null `email` and `telegram_user_id` -- keeping the
-- identity row and its `tenants` balance, which is a financial record.
--
-- NO ACTION rather than CASCADE deliberately. CASCADE would make an accidental
-- `DELETE FROM identities` silently destroy job history through `jobs.owner`,
-- and the blast radius of a mistyped WHERE clause is not the place to save a
-- few lines in an erasure routine that will be written once and reviewed.
COMMENT ON COLUMN tenant_credentials.totp_last_step IS
    'The last TOTP time-step accepted for this account, or NULL. **Replay '
    'protection, and TOTP has none of its own**: a code stays valid for its '
    'whole 30-second step, so anyone who observes one -- a shoulder, a '
    'compromised proxy, a phishing page relaying it -- can spend it again '
    'inside that window. Refusing a step that has already been accepted turns '
    'a code into something usable exactly once.'
    ' '
    'A step number rather than a timestamp because that is what the comparison '
    'needs: `<=` against the step just verified is the whole check, and storing '
    'a time would mean deriving the step from it on every login.';

-- **What a lost authenticator costs, and the only thing that makes it
-- recoverable without an operator.** A second factor with no fallback turns a
-- dropped phone into a lost account; the obvious alternative -- letting the
-- Telegram-verified password reset also clear TOTP -- would make the second
-- factor only as strong as Telegram, which is the channel signup already used.
-- These are the third option: secrets the user holds, generated once, usable
-- once each.
--
-- One row per code rather than an array on `tenant_credentials`, because each
-- is independently spendable and `used_at` is per code. An array would mean
-- rewriting the whole set to mark one used.
CREATE TABLE mfa_recovery_codes (
    code_hash   text PRIMARY KEY,
    owner       uuid NOT NULL REFERENCES identities(id),
    created_at  timestamptz NOT NULL DEFAULT now(),
    used_at     timestamptz
);

CREATE INDEX mfa_recovery_codes_owner ON mfa_recovery_codes (owner);

COMMENT ON TABLE mfa_recovery_codes IS
    'Single-use fallbacks for a lost authenticator. Shown to the user exactly '
    'once, when the second factor is enabled, and never readable again -- '
    'regenerating replaces the whole set, which is also how someone who has '
    'spent most of theirs gets more.';

COMMENT ON COLUMN mfa_recovery_codes.code_hash IS
    'sha256 of the code, never the code. Fast rather than argon2, and for the '
    'same reason `refresh_tokens.token_hash` is: these are high-entropy values '
    'from `secrets`, so there is nothing to brute-force and a slow hash would '
    'buy only latency. PRIMARY KEY because it is the lookup key, which also '
    'makes a collision across users impossible to insert.';

COMMENT ON COLUMN mfa_recovery_codes.used_at IS
    'When it was spent, or NULL. Set rather than deleted so a second '
    'presentation is recognised as ALREADY USED rather than as unknown -- the '
    'same argument as `verification_tokens.used_at`, and it keeps the count of '
    'remaining codes honest.';

-- **Per-worker credentials, closing KNOWN GAP (DRAFT-043/046).**
--
-- Until now the worker channel authenticated with one shared `WORKER_TOKEN` and
-- took the caller's identity from an `X-Worker-Id` HEADER -- two values with
-- nothing binding them, so any token holder could present any worker id, claim
-- another worker's job through `reconcile`, or attach to a running clone's
-- console. `auth.py` said so in its module docstring and named per-worker
-- credentials as the fix.
--
-- This is that fix, and its shape is the whole of it: **the token names the
-- worker.** The id is looked up FROM the credential rather than declared
-- alongside it, so "present someone else's id" stops being a thing that can be
-- said. `X-Worker-Id` is not merely unchecked afterwards -- it is gone.
--
-- Hashed rather than stored, and sha256 rather than argon2, for the reason
-- `refresh_tokens.token_hash` gives: these are high-entropy values from
-- `secrets`, so there is nothing to brute-force and a slow hash on every
-- heartbeat would be latency for nothing.
--
-- NULLABLE, and that is a transition state rather than a design: a worker row
-- created before this migration has no credential and cannot authenticate until
-- `create_worker.py` gives it one. Refusing is the right answer there -- the
-- alternative is a worker that authenticates as nobody.
ALTER TABLE workers ADD COLUMN token_hash text UNIQUE;

COMMENT ON COLUMN workers.token_hash IS
    'sha256 of this worker''s bearer token, or NULL for a row that predates '
    'per-worker credentials and cannot authenticate. The token IS the '
    'identity: `auth.authenticated_worker` looks the worker up by this hash, '
    'so there is no separate header claiming who is calling and therefore '
    'nothing for a credential and a claim to disagree about.';

COMMENT ON TABLE workers IS
    'One row per analysis host. Created by an OPERATOR with create_worker.py, '
    'never by the worker itself -- `POST /worker/register` declares capacity '
    'for the worker its token names and cannot bring a new one into existence. '
    'Self-enrolment would put the decision of who may run jobs in the hands of '
    'whoever reaches the port.';
