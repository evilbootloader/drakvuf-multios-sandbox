# DRAFT-046: Transport security — Cloudflare Tunnel outward, an internal CA inward

**Status:** **[#39](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/39) — published 2026-08-23, OPEN.**
**Area:** core/platform, security
**OS:** ALL
**Milestone:** M1 → gates M7/M8
**Priority:** P0 — the worker channel carries a bearer token, and a bearer
token on a plaintext link is a token anyone on the path can replay.
**Depends on:** DRAFT-041 (decided). Serves **#36** (the API) and **#37**
(MinIO); owned by neither, which is why it is separate.
**Needs Dom0:** to install the trust anchor and its client certificate.
The CA and the certificates are produced on a workstation.

# Objective

Secure every connection on the platform, with the split the topology actually
has: **Cloudflare Tunnel for anything a browser touches, an internal CA for
the LAN links Dom0 uses.**

# Context

## Two trust domains, not one

The browser and Dom0 reach this platform by different routes and should be
secured differently.

| Connection | Transport | Authenticated by |
|---|---|---|
| Browser → API | Cloudflare Tunnel | Cloudflare TLS + Access |
| Browser → MinIO | Cloudflare Tunnel (second hostname) | Cloudflare TLS + Access |
| **Dom0 → API** | **LAN** | **mTLS, internal CA + bearer token** |
| **Dom0 → MinIO** | **LAN** | **TLS, internal CA + presigned URL** |
| API → Postgres | Unix socket | Peer authentication |

**Cloudflare Tunnel removes most of the certificate problem.** `cloudflared`
dials *outbound*, so there is no inbound port, no public DNS to arrange, no
ACME, and no browser-facing certificate for this project to issue or renew.
It also fits the posture the rest of the design already has: Dom0 dials out,
and now the platform does too.

**Dom0 stays on the LAN, deliberately.** Sending the worker channel out to
Cloudflare and back would make local analysis depend on an external service
being reachable, and would put the worker token through a third party. A
sandbox that cannot analyse a sample because someone else's edge is down is
worse than one with an extra certificate to manage.

That leaves the internal CA with three certificates and a small job.

## What crosses Cloudflare, and the constraint it puts on artifacts

Cloudflare terminates TLS, so anything crossing the tunnel is plaintext at
their edge. Their self-serve terms prohibit using the service to *distribute*
malicious code. Uploading a sample into your own storage is materially
different from distributing it — but **the return path is where that
distinction gets thin**, because `fileextractor` output is files the malware
wrote, and a dropper's second stage is exactly the sort of thing the clause is
about.

**Decision: everything is downloadable, but anything executable is served as
a password-protected archive.** Samples and `extracted/` are wrapped; traces,
pcaps, memdumps and metadata are not. This is the long-standing convention for
moving malware between analysts, and it does two useful things at once: what
crosses the wire is an encrypted blob rather than a PE, and the operator's own
antivirus stops quarantining their results.

**The wrapping happens on Dom0, at collection time — not in the API.** This
matters more than it looks. Having the API archive a sample on demand would
stream those bytes through the process that holds the database and
object-store credentials, giving up precisely the property that made
direct-to-MinIO upload worth its routing complexity: *the platform never
handles a sample*. Dom0 already has the files; it wraps them before upload,
and what lands in the bucket is already safe to serve.

*Implemented by the artifact-upload issue, not here. Recorded here because
this is where the decision was made and why.*

## Why an internal CA rather than self-signed certificates

**mTLS forces the question.** Verifying a client certificate means verifying
it against something, so a certificate authority exists whether or not it is
named. Given that, one CA signing all three certificates is simpler than three
self-signed certificates pinned separately, and Dom0 gets a single trust
anchor.

## Why uvicorn terminates TLS, and not a reverse proxy

DRAFT-043 assumed nginx or Caddy in front. On reflection this milestone does
not need one: `cloudflared` fronts the browser side, and uvicorn does server
TLS and client-certificate verification directly (`--ssl-certfile`,
`--ssl-keyfile`, `--ssl-ca-certs`, `--ssl-cert-reqs=2`) for the LAN side.

**mTLS here is a transport gate, not an identity source.** The bearer token
and `X-Worker-Id` already say which worker, and `lease_owner` already bounds
what it may touch — so the client certificate only has to prove the connection
came from a holder of a CA-signed certificate. Extracting a certificate
subject and mapping it to an identity is the part that wants a proxy, and this
design does not need it.

Revisit at M8, when an internet-facing tier wants a proxy for other reasons.

# The decisions

| # | Decision |
|---|---|
| 1 | **Cloudflare Tunnel** fronts the API and MinIO for browsers. Two hostnames, both behind Access |
| 2 | **Dom0 reaches the platform over the LAN**, never through the tunnel |
| 3 | **One internal CA** signs the API cert, the MinIO cert and Dom0's client cert |
| 4 | **The CA root key never touches the platform container** |
| 5 | **uvicorn terminates TLS and verifies client certificates.** No reverse proxy at M1 |
| 6 | **Executable artifacts are served as password-protected archives**, wrapped on Dom0 |
| 7 | **No generated key or certificate is tracked in this repository** |
| 8 | **TLS 1.2 minimum, pinned explicitly** on both the API and MinIO |

## On forward secrecy, and the `dhparam` file that is not here

Raised in review, and worth recording because the answer is counterintuitive
and the habit is widespread.

**Forward secrecy is already guaranteed and requires no configuration.** TLS
1.3 removed static RSA key exchange from the protocol, so every 1.3 handshake
is ephemeral by construction. On TLS 1.2, OpenSSL's modern defaults negotiate
ECDHE; forward secrecy is lost only by explicitly enabling `TLS_RSA_*` cipher
suites, which nothing here does.

**`openssl dhparam` is therefore not used.** It supplies parameters for
*finite-field* DHE specifically. TLS 1.3 does not use custom DH parameters at
all — it uses named groups (RFC 7919) — and ECDHE uses named curves. A
`dhparam.pem` on this platform would be a file nothing reads. The practice
comes from nginx guides written when finite-field DHE was common and Logjam
had just demonstrated the risk of weak or shared parameters; named groups
replaced it.

**What the question did surface is decision 8.** The library defaults are
correct today, and the reason to pin a floor anyway is that a package upgrade
on a host nobody is watching must not be able to re-enable TLS 1.0 or 1.1
silently. `--ssl-version` on uvicorn; MinIO already refuses below 1.2, and the
runbook asserts it rather than assuming it.

Note also that key exchange is negotiated **per connection**, not carried in a
certificate — so none of this affects issuance. It is server configuration,
verified by `openssl s_client` in TEST rather than by reading a certificate.

## Why the CA is offline, which is the point of the issue

The platform container holds the database credentials, the object-store
credentials and the worker token. DRAFT-041 accepted that concentration
deliberately, in exchange for a narrow blast radius on Dom0.

**A CA root key there would undo that trade.** A CA mints identities: an
attacker holding it can issue a client certificate indistinguishable from
Dom0's and walk into the worker channel. The blast radius grows from "the
credentials that host holds" to "any identity in the system, including ones
not yet issued".

Held offline, a platform compromise gets the certificates already on that host
and cannot produce more, and revocation stays possible from a machine the
attacker does not control. The cost is a manual step at renewal, which at
three certificates is not a burden — and which *should* be deliberate.

# Dependencies

- **#36** consumes the API certificate and the CA bundle.
- **#37** consumes the MinIO certificate and the tunnel hostname, which
  determines what the presigned-URL issuer puts in `S3_ENDPOINT`.
- The artifact-upload issue implements decision 6.

# Out of scope

- **Public certificates for M8.** Cloudflare provides the public face; if the
  web tier later needs its own, that is a separate trust model.
- **Automated renewal / ACME.** Deliberate: automation implies an online CA,
  which decision 4 rejects.
- **A revocation list served over the network.** With three certificates,
  revocation is reissuing the bundle and restarting two services.
- **Encrypting the Postgres connection.** The API and the database share a
  container and speak over a Unix socket; TLS there would be theatre.
- **Cloudflare Access policy design** — who may authenticate, and with what.
  Real work, and M8's alongside the rest of authentication.
- **A reverse proxy.** M8.

# PLAN

1. Write the issuance tooling — CA creation, server certificates with correct
   SANs, client certificates.
2. Issue the three certificates and verify each against the CA.
3. Configure uvicorn for TLS and client-certificate verification.
4. Configure MinIO for TLS.
5. Stand up `cloudflared` with two hostnames; confirm no inbound port opened.
6. Install the trust anchor and client certificate on Dom0.
7. Verify the negative cases, which are the ones that matter.

# CREATE

- `tls/issue-cert.sh` — creates the CA once, then issues server and client
  certificates from it.
- `tls/README.md` — the custody model, and what must never be committed.
- A run script or systemd unit for uvicorn carrying the TLS flags.
- MinIO's certificate in `~/.minio/certs/`.
- A `cloudflared` config with the two ingress rules.

**IP addresses go in the SAN, not the CN.** Modern clients ignore the common
name entirely; a certificate for `192.168.1.10` with the address only in CN
fails verification with an error that does not say so.

**`cloudflared` connects to its origins over localhost**, so the tunnel does
not depend on the LAN certificate being valid for a public name — the origin
is `https://127.0.0.1`, verified against the internal CA.

# TEST

Positive cases prove it works. **The negative cases prove it is doing
anything**, and they are the ones worth writing.

1. **HTTPS to the API succeeds** with the CA bundle, and **fails without it**
   — otherwise the client is not verifying anything.
2. **Plain HTTP to the API is refused**, not silently upgraded.
3. **No client certificate → refused at the TLS layer**, before the bearer
   token is read. A 401 here means mTLS is *not* configured, because the
   request should never have reached a handler.
4. **A client certificate signed by a different CA is refused.** Generate a
   throwaway second CA for this; without it, test 3 passes against a server
   that accepts any certificate at all.
5. **MinIO over HTTPS**, and a presigned URL whose scheme is `https`.
6. **The certificate covers the IP** — verification against `192.168.1.10`
   succeeds with hostname checking left on.
6a. **TLS 1.1 and below are refused**, on both the API and MinIO:
   `openssl s_client -tls1_1` must fail. Asserting the floor rather than
   trusting the default is the whole of decision 8.
6b. **The negotiated cipher is ephemeral** — `openssl s_client` reports an
   `ECDHE` key exchange. Cheap to check, and it is the evidence that forward
   secrecy is present without a `dhparam` file.
7. **The CA key is absent from the platform container**, asserted rather than
   assumed: a `find` that returns nothing.
8. **The tunnel opens no inbound port** — `ss -lntp` on the container shows
   nothing new listening externally.

# DEPLOY

Certificates are generated on the workstation and copied in; the CA key never
moves. Recorded in `docs/runbooks/08-deploy-platform-lxc.md` as its own section,
with the negative checks run against the real deployment.

Rollback is reverting to plaintext on the LAN links — a decision, not an
accident, and one to record if taken.

# Acceptance criteria

- [ ] The API serves HTTPS on the LAN and refuses plaintext.
- [ ] The API refuses a connection with no client certificate, and one signed
      by a different CA — both at the TLS layer, before any handler.
- [ ] MinIO serves HTTPS and presigned URLs carry the `https` scheme.
- [ ] Certificates carry the IP in a SAN and verify with hostname checking on.
- [ ] Dom0 holds the CA certificate and one client certificate, nothing else.
- [ ] **The CA root key is not on the platform container**, asserted by a
      command in the runbook.
- [ ] `cloudflared` serves both hostnames and opens no inbound port.
- [ ] No key or certificate is tracked in git.
- [ ] `docs/architecture/networking.md` records the two trust domains and what
      each connection authenticates.

# Evidence required

- `openssl s_client` transcripts for each negative case — "it works in a
  browser" does not distinguish a verified connection from a dismissed
  warning.
- `openssl x509 -text` for each certificate, showing the SANs.
- `ss -lntp` before and after `cloudflared`.
- The `find` result showing no CA key on the platform.

# Security considerations

- **The CA is the highest-value key in the system, and it is not on the
  system.** A CA on the platform would let a compromise mint a Dom0 client
  certificate and enter the worker channel, turning credential theft into
  identity forgery.
- **mTLS is a transport gate, not an identity source.** Do not later
  "simplify" by deriving worker identity from the certificate subject without
  redesigning the authorisation that depends on the token and `lease_owner`.
- **TLS does not replace the bearer token.** A client certificate on Dom0 is
  a file; a sample that escapes there has both it and the token. Containment
  remains lease scoping, not transport security.
- **Cloudflare sees plaintext at its edge.** That is inherent to terminating
  TLS there and is why decision 6 exists. Read the acceptable-use terms
  directly rather than relying on a summary — this becomes the normal path,
  and the clause that matters is about *distribution*.
- **Private keys are `0600` and owned by the service user.** A world-readable
  key in a container running a web service makes all of the above ornamental.
- **Certificate expiry is an outage.** With manual issuance and no monitoring,
  the failure mode is the platform stopping on a date nobody wrote down.
  Record expiry where it will be seen.

# Documentation changes

- **New:** `tls/README.md`; a TLS and tunnel section in
  `docs/runbooks/08-deploy-platform-lxc.md`.
- **Updated:** `docs/architecture/networking.md` — the two trust domains.
- **Updated:** `docs/architecture/platform.md` — its topology figure shows
  HTTPS without saying what verifies it, and does not show the tunnel.
- **Updated:** `.github/issue-drafts/DRAFT-043.md` — annotate that the reverse
  proxy it assumed is deferred to M8, with the reason.

# Recovery / rollback

Reissuing a certificate is running the script and restarting one service.
Losing the CA key means reissuing all three and reinstalling the trust anchor
on Dom0 — recoverable, and the reason the key is backed up somewhere that is
not the platform.