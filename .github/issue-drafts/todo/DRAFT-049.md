# DRAFT-049: Network processing — read the pcap we already capture

**Status:** Drafted 2026-08-25. Not published.
**Area:** enrichment
**OS:** ALL — the pcap is captured outside DRAKVUF, so this is guest-agnostic.
**Milestone:** M4
**Priority:** P1
**Depends on:** #37. Enriched by DRAFT-050 (`socketmon`, `tlsmon` — Windows).
**Needs Dom0:** **No.**

# Objective

Turn the per-run pcap into readable network activity: DNS, HTTP, TLS metadata,
connections, and Suricata alerts.

# Context

## We capture it on every run and have never read it

`automation/tcpdump.sh` writes a pcap on the clone's VLAN sub-interface for
every analysis. It is collected, stored, and never opened. That is the
cheapest capability in the project: the data exists, the collection is
evidenced, and nothing new has to run on Dom0.

## What the capture position gives us for free

The pcap is taken on Dom0's VLAN sub-interface — **outside the guest**. Two
consequences worth stating:

- **It cannot be tampered with by the sample.** A rootkit that hides
  connections from the guest's own tooling does not hide them here. This is
  the same argument DRAKVUF makes for VMI, applied to the network.
- **It is complete.** Every packet the clone sent or received, including
  traffic from processes the sample spawned and traffic after the sample
  exited.

Against that: it sees ciphertext. TLS is most of what matters, and the pcap
alone gives SNI and certificate metadata, not content.

## TLS, and the one route that exists

`tlsmon` extracts TLS keys and is **Windows-only** — confirmed by source read
(`src/plugins/tlsmon/tlsmon.cpp` hooks `ncrypt.dll`/Schannel;
`docs/architecture/networking.md`). With it, Windows captures can be decrypted
using our own keys, with no MITM proxy and no certificate installed in the
guest. That is a materially better position than the MITM approach ANY.RUN and
others use, because a MITM proxy is detectable by the sample and this is not.

**There is no equivalent for Ubuntu or Android.** Roadmap risk #4 records it.
So the honest statement: full HTTP visibility on Windows, metadata only on the
other two, and the UI must not present an empty HTTP list on Ubuntu as though
the sample made no requests.

# Dependencies

- **#37** — the pcap object.
- **DRAFT-050** — `socketmon` attributes connections to processes on Windows;
  `tlsmon` supplies keys.
- **DRAFT-057** — egress routing changes what a capture even contains.

# Out of scope

- **Live traffic manipulation**, MITM proxies, response injection.
- **Threat-intelligence lookups.** Sending observed IOCs to a third party
  discloses what is being analysed and when; that decision belongs with
  DRAFT-022, not here.
- **Retention of pcaps.** #37 decided 30 days for everything.

# PLAN

1. Protocol extraction first — it needs no rule corpus and no licence
   decision.
2. Suricata second, once the ruleset question is settled.
3. TLS decryption last, and only where `tlsmon` makes it possible.

# CREATE

## Extraction

DNS queries and responses; HTTP requests and responses; TCP/UDP connection
table with bytes and duration; TLS handshakes with SNI, JA3/JA4 and
certificate details. Structured rows, not a packet dump — the pcap stays
downloadable for anyone who wants Wireshark.

**JA3/JA4 is worth calling out.** A TLS fingerprint identifies the client
stack even when the payload is opaque, which is exactly the Ubuntu and Android
situation. It is the one thing that partly compensates for having no keys.

## Suricata

Alerts with rule ID, signature and severity. The ruleset is a **licence
decision before it is a technical one** — ET Open is BSD-ish, ET Pro is
commercial, and DRAFT-022 owns the position. Pin the version.

## The empty-list problem

On Ubuntu, "HTTP requests: none" is ambiguous between *the sample made no
requests* and *we cannot see inside TLS*. The UI must distinguish them, or it
reports a false negative in the most confident possible tone. Where no keys
are available, say so beside the list rather than leaving it empty.

# TEST

1. **A capture with known traffic** — a fixture that resolves a name, fetches
   a URL and opens a TLS connection — produces exactly those rows.
2. **A truncated or empty pcap** is handled: an empty capture is a real result
   (the clone generated no traffic) and must not read as a failure.
3. **A malformed pcap does not crash the parser.**
4. **Suricata alerts render**, and a ruleset that fails to load is a loud
   failure rather than silently zero alerts.
5. **TLS metadata is extracted without keys** — SNI and JA3 present on an
   Ubuntu capture.
6. **With `tlsmon` keys, a Windows capture decrypts** and HTTP inside TLS
   appears.
7. **The no-keys case is labelled**, not left as an empty list.
8. **A large pcap streams** rather than loading whole — 180s of traffic from a
   noisy sample is not small.

# DEPLOY

A post-processing step alongside DRAFT-019 and DRAFT-048. Output
`results/<job_id>/network.json`.

> **Wrapped in the DRAFT-018 envelope (added 2026-08-26).** This draft
> specified a bare `*.json`; it is now `sandbox.network/1` inside the shared envelope —
> `schema`, `job_id`, `produced_at`, `producer` (with `ruleset_version`),
> `status`, `status_reason`, `data`. The payload this draft describes goes in
> `data` and is unchanged. **`status` is not optional decoration:** a run that
> hit its timeout part-way through produces real findings that read exactly
> like a clean sample, and this is the field that tells them apart. See
> `docs/architecture/result-schema.md` §4.3 and
> `sandbox_platform/manifest.py`.

# Acceptance criteria

- [ ] DNS, HTTP, connections and TLS metadata extracted from a real capture.
- [ ] JA3/JA4 recorded.
- [ ] Suricata runs against a ruleset whose version and licence are recorded.
- [ ] TLS decryption works on Windows where `tlsmon` provides keys.
- [ ] Absence of visibility is stated, never rendered as absence of traffic.
- [ ] Parsing is streamed and bounded.
- [ ] No third-party lookups.

# Evidence required

- A capture with known traffic, beside the extracted rows.
- A Windows capture decrypted with `tlsmon` keys.
- An Ubuntu capture showing SNI and JA3 with the no-keys label.
- Ruleset version and licence.

# Security considerations

- **Pcaps contain third-party traffic.** DRAFT-022's central concern: a
  capture includes whatever the sample contacted, and those parties did not
  consent. This is the strongest argument for #37's retention window and
  against any third-party lookup.
- **The parser is attacker-influenced.** The sample chooses the packets.
  Malformed protocol parsing is a classic memory-safety surface, and this runs
  on the credential-holding container — bound it and isolate it.
- **Suricata rules are executable input**, like YARA rules. Pin and review.
- **TLS keys are sensitive beyond the run.** `tlsmon` output decrypts that
  session; it lands in the object store under the same retention as
  everything else, which is worth a deliberate look rather than an assumption.
- **JA3 is a fingerprint of our guest as much as of the sample.** If captures
  are ever shared, the fingerprint identifies the sandbox — a sandbox-detection
  signal handed over voluntarily.

# Documentation changes

- **New:** what is extracted, and the per-guest TLS position.
- **Updated:** `docs/architecture/networking.md` — the capture is now read.
- **Updated:** `docs/architecture/result-schema.md` — `network.json`.

# Recovery / rollback

Stop running the step. The pcap remains downloadable, which is today's state.
