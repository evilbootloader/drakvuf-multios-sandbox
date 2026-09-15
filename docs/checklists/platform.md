# Web Sandbox Platform — Implementation Checklist and Command Log

> **Status: deployed and serving.** Rewritten 2026-08-29. This file previously
> read *"skeleton only. No web-platform work has started as of 2026-08-07"* and
> *"Current phase: Not started — blocked on M0–M6 and the licensing decision"*,
> which stayed unchanged while the platform was designed, built, deployed,
> tested and migrated to a new host. `CLAUDE.md` routes readers here for
> per-component progress, so that gap was not cosmetic.
>
> **Execution evidence lives in the runbooks, not here.**
> `docs/runbooks/08-deploy-platform-lxc.md` is 3,191 lines of it for the
> original build; `platform-domu.md` covers the rebuild as a Xen PVH domain.
> This file tracks what is done against what is not.

## Project status

| Field | Value |
|---|---|
| Current phase | **M7 delivered and running**; M8 (public hardening) partly done, partly open |
| Job queue technology | **Postgres**, `FOR UPDATE SKIP LOCKED` with head-of-line reservation. Not RQ+Redis — decided 2026-08-21 (DRAFT-041), because the queue and the job records want the same transaction |
| Web framework | **FastAPI**, server-rendered Jinja2 UI, htmx vendored rather than fetched |
| Object store | **MinIO**, presigned object-scoped PUT/GET; sample bytes never touch the API's filesystem |
| Runtime | **Xen PVH DomU** at `192.168.1.10` since 2026-08-28, replacing the unprivileged LXC (CT 102) |
| Licensing gate | **Not a blocker for lab work**, and never was. `docs/architecture/licensing.md` says so in its own header: *"This does not block internal lab automation work happening now."* It gates **commercial/paywalled** use, which is an M8+ question |

### Status legend

- [x] Completed and evidenced
- [ ] Not started
- `BLOCKED:` Waiting on a dependency or unresolved fault
- `SKIPPED:` Deliberately excluded, with reason recorded

---

# M7 — Web platform MVP

- [x] **Job schema and the claim query** (#35). Migrations under
  `platform/migrations/`, applied by `migrations/run.py`, which owns the
  transaction and refuses a file whose bytes changed after it was applied.
- [x] **Choose job queue technology** — Postgres, above.
- [x] **Job submission API** (#36): admission, the worker channel, and the
  state machine. `platform/sandbox_platform/routers/`.
- [x] **Multi-OS target selection** — `catalogue.py` refuses to invent a
  package for a target that has never executed, which is why Windows raises
  rather than defaulting to the Linux options.
- [x] **MinIO bucket layout, policy and presigned access** (#37).
  `platform/minio/provision.sh` is the single re-appliable copy; step 15 of
  runbook 08 is superseded by it.
- [x] **Minimal UI: upload, status, results** (#38). Server-rendered, autoescape
  on, `| safe` greppable. Artifact ZIP downloads implemented and tested here.
- [x] **The Dom0 orchestrator** (#41) — `sandboxd/`, claiming over mutual TLS,
  with host-global admission instead of fixed clone slots.
- [x] **Live console** — off by default on both ends.
- [ ] Reuse `[preset.x]`-style per-OS configuration presets.

**Not yet evidenced on the deployment:** artifact ZIP downloads have been
tested in the development container only.

# M8 — Public hardening + legal gate

- [x] **AuthN** — **this platform issues its own credentials as of 2026-09-15**
  (DRAFT-061, `docs/runbooks/17-deploy-own-identity.md`). Passwords hashed with
  argon2id, sessions as signed access and refresh tokens, TOTP as a second
  factor, and per-worker tokens on the worker channel in place of one shared
  secret. Cloudflare Access was removed at step 10 and the tunnel kept: it is
  transport, not identity.

  Until then this read "Cloudflare Access at the edge, JWT verified against the
  team domain's JWKS" with a separate mTLS worker channel on 8443. Both are
  gone — 8443 was retired at step 11, and `REQUIRE_ACCESS_JWT`,
  `ACCESS_TEAM_DOMAIN` and `ACCESS_AUD` are no longer set on the deployment.
  `access_identity` remains in the code so a future deployment *could* sit
  behind an external provider; nothing here does.
- [x] **Transport security** (#39) — Cloudflare Tunnel outward, an internal CA
  inward. The CA's signing key lives on the operator's workstation and
  deliberately not on the platform: a platform compromise must not be able to
  mint worker certificates.
- [ ] **AuthZ / per-user isolation** (#40) — open, and partly landed.
  Read-path scoping is in the repository as of 2026-09-05: one predicate,
  `auth.visible_to`, in the WHERE clause of every browser read. Publishing
  followed on 2026-09-06 — migration 0007, `POST /jobs/{id}/publish` and
  `/unpublish` gated on `owner = %s` rather than on that predicate, and the UI
  control behind an irreversibility warning. `platform/tests/test_tenancy.py`
  covers both against a second user. **Not deployed and not verified on the
  deployment**, so this stays unticked.

  **Decisions 7 and 8 landed 2026-09-07**, both in migration 0008. Objects
  gain a per-user key prefix, `u/<owner>/<3 hex of job id>/`, taken from the
  row rather than from whoever is asking — the shard bounds directory fan-out
  under one owner for MinIO's listing and lifecycle scan, and is unmeasured
  but cheap now and expensive later. And the runtime quota became a **prepaid
  balance** rather than a rolling window: a `tenants` row per Access identity,
  3600 s granted on first contact, drawn down by
  `worker._charge_for_runtime` when a job reaches a terminal state having had
  a clone. 402 at admission when it is spent. `platform/tests/test_quota.py`
  is sixteen tests.

  **A job the platform lost track of is not charged.** `REAP` and `RECONCILE`
  fire because Dom0 crashed, restarted or lost its link, and the platform
  cannot say when the job stopped — `updated_at` is when the sweep noticed, so
  the elapsed time carries 120–150 s of detection lag at minimum and
  unbounded lag for a reconcile. That decision is why the charge lives in the
  worker routes rather than in a trigger.

  **`owner` is NOT NULL as of 0008**, for traceability. The mTLS listener can
  therefore no longer submit — `auth.required_identity` refuses it with a 403
  — which resolves once the CLI routes through the tunnel and carries an
  Access service token. `visible_to`'s `owner IS NULL` arm is now unreachable
  and kept deliberately; see the docstring there.

  **Decision 3 was deployed 2026-09-06 and REVERSED 2026-09-10.** The browser
  listener bound `127.0.0.1` and `cloudflared` dialled it over TLS on loopback
  (`platform-domu.md` §E4a). It held for four days, and what ended it was the
  live console: `sandboxd` dials that same listener from Dom0, and loopback is
  not reachable across machines, so every trace logged a
  `ConnectionRefusedError`. The listener is back on the LAN address and
  **`REQUIRE_ACCESS_JWT=1` is the whole gate** — the bind was defence in depth
  behind it.

  Two things that costs, both being the pre-2026-09-06 state rather than new:
  a lost `access.conf` drop-in is now a config slip on a LAN socket, and the
  console's worker end on `:8000` has no `--ssl-ca-certs`, so attaching to a
  running clone over the LAN needs only the bearer token.

  **DRAFT-061 delivered its half on 2026-09-15** (runbook 17): that bearer
  token is now per worker, issued by `create_worker.py`, stored as a sha256
  and revocable per host with `--rotate`. What it does not do is add a second
  factor — the decision at the head of that runbook dropped Caddy and mTLS, so
  **the worker channel is one factor on the LAN** by choice, and that is
  recorded as a known gap rather than closed.
  The scope check on the SSE stream and the console socket runs once, at
  connect, so it depends on publication being restricted to terminal jobs —
  no connection can be open on a job that is publishable. Relaxing that
  restriction would reopen it; the two rules are coupled.
- [ ] **Rate limiting, abuse controls** — the login path only, and unexercised
  on the deployment. DRAFT-061 shipped per-identity and per-IP throttling with
  lockout and decay in front of argon2, configured at runbook 17 step 3 and
  live since the cut-over removed Access from in front of it. It stays unticked
  for two reasons: **nothing has driven a burst of failed logins at it on this
  host**, so its behaviour under load — and whether `TRUSTED_CLIENT_IP_HEADER`
  picks the right bucket behind cloudflared — is unevidenced; and abuse
  controls on submission, which is where the compute is, are not started.
- [ ] **Tenant isolation** — not started; depends on #40.
- [ ] **Egress routing** (#42) — open. Whether analysis traffic goes offline,
  direct, or through an exit of our choosing. See `ideas.md` for the VPN
  research.
- [ ] **Retention** — open (DRAFT-041, DRAFT-022). A 30-day lifecycle rule and
  a 200 GiB bucket quota are applied, but retention is unresolved as *policy*.
- [ ] **Formal legal review** before any external or paying users. The desk
  research in `docs/architecture/licensing.md` is not a substitute, and it
  flags that DRAKVUF's licence text reaches subprocess-orchestration-and-parse
  explicitly.
- [x] **The public web application must never expose privileged Xen operations
  to clients.** Structural, not a control: Dom0 opens every connection and has
  no inbound listener, so there is no path from the web tier to `xl`.

---

## Known gaps carried from the deployment

| Gap | Where it is recorded |
|---|---|
| **Storage capacity is a shared failure domain.** `platform_data` sits in `vg-root/thinpool` alongside the golden images and every clone snapshot; a full pool stops the analysis lab | `docs/architecture/platform.md`, `docs/CURRENT-STATE.md` §1.1 |
| **Two uvicorn processes over one app**, so the console relay's in-process registry differs between them — both ends of a session must reach the same listener | `docs/CURRENT-STATE.md` §1.3 |
| **Direct kernel boot**: a guest `apt upgrade` does not change what Xen boots. The kernel must be re-copied to Dom0 by hand | `platform-domu.md` §F2 |
| **Job history and artifacts from before 2026-08-28 are gone** — CT 102's backup was encrypted with a key held only on the erased Proxmox host | `platform-domu.md` FINDING E-1 |
| **`libmagic1t64` is a runtime dependency pip does not install.** `python-magic` is a ctypes wrapper; the LXC template happened to carry libmagic and a debootstrap base does not | `platform-domu.md` FINDING E-4 |

## Testing

Never against the deployment — the `conn` fixture truncates the jobs table.

```bash
scripts/dev-services.sh                        # Postgres + MinIO, locally
cd platform && .venv/bin/python -m pytest -q
```

The deployment is verified by the runbooks' `curl` checks and by looking at
the UI.