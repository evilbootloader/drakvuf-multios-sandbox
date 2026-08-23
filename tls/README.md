# tls — the internal CA

Issue #46 (DRAFT-046). Certificates for the **LAN** links between Dom0 and
the platform. The browser-facing side is Cloudflare's and needs nothing here.

## What this covers, and what it does not

| Connection | Secured by |
|---|---|
| Browser → API | Cloudflare Tunnel — **not this CA** |
| Browser → MinIO | Cloudflare Tunnel — **not this CA** |
| **Dom0 → API** | **This CA. mTLS: server cert + client cert + bearer token** |
| **Dom0 → MinIO** | **This CA. Server cert + presigned URL** |
| API → Postgres | Unix socket, peer auth — no TLS, no network hop |

Three certificates: `api`, `minio`, and one client certificate per analysis
host.

## The rule that matters

**The CA root key never goes on the platform container, or on Dom0.**

A CA mints identities. An attacker holding this key can issue themselves a
client certificate indistinguishable from Dom0's and walk into the worker
channel — turning a credential theft into an identity forgery, and growing
the blast radius of a platform compromise from "the credentials that host
holds" to "any identity in the system, including ones not yet issued".

Kept off those hosts, a compromise gets the certificates already there and
cannot produce more, and revocation stays possible from a machine the
attacker does not control.

`init` refuses to run somewhere that looks like the platform. That is a
heuristic, not a proof — the rule is yours to keep.

## Custody

- `ca/ca.key` — **the secret.** Workstation or an encrypted volume. Back it
  up somewhere that is not the platform; losing it means reissuing all three
  certificates and reinstalling the trust anchor on Dom0.
- `ca/ca.crt` — the trust anchor. Public. Copy to the platform and to Dom0.
- `ca/<name>.key`, `ca/<name>.crt` — issued material. Copy the pair to the
  host it belongs to and nowhere else.

**Nothing under `ca/` is tracked.** `.gitignore` covers `*.key` and `*.pem`
repository-wide; `tls/ca/` is ignored outright so a stray `.crt` cannot be
committed either.

## Use

```bash
./issue-cert.sh init                              # once, ever

./issue-cert.sh server api   192.168.1.10 platform.lan
./issue-cert.sh server minio 192.168.1.10 platform.lan
./issue-cert.sh client dom0-lab

./issue-cert.sh verify api
```

Server certificates always gain `127.0.0.1` and `localhost` on top of the
SANs given, because `cloudflared` reaches its origins over loopback.

## Things that are deliberate

**IP addresses go in the SAN, never only the CN.** Modern clients ignore the
common name entirely. A certificate for `192.168.1.10` with the address only
in CN fails verification with an error that does not mention the reason, and
the temptation is then to disable hostname checking — which discards the
verification altogether.

**Server and client certificates have disjoint extended key usage.** One
valid for both roles could authenticate *to* the service it also identifies.
Asserted by `platform/tests/test_tls.py`.

**The client certificate's CN is decoration.** It carries the worker id so a
human can tell the files apart. Nothing authorises against it: the bearer
token says what a caller may do, and `lease_owner` bounds which jobs it may
touch. mTLS here is a transport gate, not an identity source — do not
"simplify" later by deriving worker identity from the subject without
redesigning the authorisation that depends on it.

**825 days for leaf certificates.** The ceiling public CAs enforce, adopted
here so the habit matches the constraint you would hit anywhere else. Longer
would work internally and would mean the renewal step is forgotten for years.

**There is no `dhparam.pem`, and adding one would do nothing.** Forward
secrecy comes from the protocol: TLS 1.3 removed static RSA key exchange, and
TLS 1.2 negotiates ECDHE by default. `openssl dhparam` supplies parameters
for *finite-field* DHE, which 1.3 does not use and which nothing here enables.
The practice comes from nginx guides written when that was the live concern.
`test_the_key_exchange_is_ephemeral` asserts the property directly rather
than trusting the reasoning.

## Expiry is an outage

Manual issuance and no monitoring means the failure mode is the platform
stopping on a date nobody wrote down. `verify` prints `notAfter`; record it
somewhere it will be read.

```
CA         expires  ____________________
api        expires  ____________________
minio      expires  ____________________
dom0-lab   expires  ____________________
```