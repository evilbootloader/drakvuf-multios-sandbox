# DRAFT-022: Establish the legal and compliance position for networked malware analysis (Spain/EU)

**Status:** Drafted, not published
**Area:** compliance / governance
**Milestone:** M2 (before any non-benign sample runs with networking) → M8
**Priority:** **P1** — raised from P2. The lab has working, deliberate NAT
egress today (DRAFT-028), so the question is live rather than deferred.
**Depends on:** None open. Informed by DRAFT-028 (what the network actually
permits) and DRAFT-013 (containment verification).
**Origin:** Roadmap risk #3 and the "legal/compliance review (Spain)" node
in the dependency graph.

> **This draft is desk research, not legal advice.** The provisions below
> were read from primary and official sources on 2026-08-11 and are cited
> so they can be re-checked. What they mean *for this lab* is a question for
> a Spanish lawyer, and engaging one is this issue's main deliverable.

# Objective

Answer, in writing and with citations, three questions the project cannot
currently answer:

1. Is holding and executing malware samples for analysis lawful in Spain?
2. Under what conditions, if any, may a sample be detonated with **live
   Internet access**?
3. What does GDPR require of the artifacts this lab already produces —
   pcaps, memory dumps, extracted files?

# Context

`automation/network-setup.sh` MASQUERADEs every analysis clone to the
uplink. Since DRAFT-028 that egress is narrowed to the Internet only —
the LAN, the router, Dom0 and IPv6 are all blocked, counter-verified on
2026-08-11 — but **Internet access itself is deliberate and unrestricted**,
and `docs/architecture/networking.md`'s `offline` / `simulated` /
`controlled-internet` modes do not exist.

`docs/checklists/android.md` §1.3 carries the row
`Reach Internet IPv4 | Expected: Blocked`, which contradicts the decided
policy. That contradiction is currently resolved in the checklist by a note
saying the row needs re-scoping. It actually needs this issue.

## What the research found (2026-08-11)

### Possession and analysis of malware — the favourable finding

**Art. 264 ter CP** (added by LO 1/2015, in force 1 July 2015) is the
provision that appears to criminalise holding malware. Verbatim:

> «Será castigado con una pena de prisión de seis meses a dos años o multa
> de tres a dieciocho meses el que, **sin estar debidamente autorizado**,
> produzca, adquiera para su uso, importe o, de cualquier modo, facilite a
> terceros, **con la intención de facilitar la comisión** de alguno de los
> delitos a que se refieren los dos artículos anteriores: a) un programa
> informático, concebido o adaptado principalmente para cometer alguno de
> los delitos […]»

Two cumulative elements — *without due authorisation* **and** *with the
intention of facilitating the commission* of an Art. 264 / 264 bis offence.
Capability alone is not the offence.

The **Fiscalía General del Estado's circular** on cybercrime
(`FIS-C-2017-00003`) is the authoritative prosecutorial reading and is
explicit that dual-use tooling is not caught:

> «Many tools susceptible to being employed for committing these illicit
> acts may have been created and commercialised for lawful objectives and
> even necessary ones, such as auditing system security…»

**Working conclusion, to be confirmed by counsel:** operating this lab —
holding samples, executing them under introspection, retaining artifacts —
does not engage Art. 264 ter, because the specific intent element is
absent. This is the question most people assume is the hard one. It is not.

### The offences that actually matter for live detonation

- **Art. 264 CP** — unauthorised and *serious* deletion, damage,
  deterioration, alteration or suppression of another's data, programs or
  electronic documents. 6 months–3 years, aggravated to 2–5 years where
  organised crime, critical infrastructure or essential public services are
  involved.
- **Art. 264 bis CP** — unauthorised and serious obstruction or
  interruption of another's information system. 6 months–3 years.
- **Art. 264 quater CP** — corporate criminal liability for legal persons
  for the above.

These are intentional offences, which is favourable: a sandbox operator
does not *intend* the sample's outbound conduct. **But that is a criminal-law
answer only.** Civil liability for negligence (`Código Civil` art. 1902,
responsabilidad extracontractual) has no intent requirement, and "I permitted
unrestricted egress from a host I controlled, knowing it was running
malware" is exactly the fact pattern negligence is for. Counsel must address
the civil exposure separately; it is the larger risk and it is the one this
project has never considered.

### GDPR — the obligation that applies whether or not egress is allowed

**Recital 49** makes network and information security an explicit legitimate
interest, naming CERTs, CSIRTs and «providers of security technologies and
services», for processing «strictly necessary and proportionate».

That is a usable Art. 6(1)(f) basis. It is **not** a blanket permission, and
two limits bite here:

- *Strictly necessary and proportionate.* `tcpdump.sh` captures the clone's
  entire VLAN interface. A sample exfiltrating a victim's credentials or
  documents puts that victim's personal data — possibly Art. 9 special
  categories — into a pcap this project retains indefinitely, keyed by MD5,
  with no retention policy and no access control. That is hard to defend as
  proportionate.
- *This applies today.* It does not depend on Internet egress. An offline
  sample dumping memory produces the same problem. **This is the most likely
  live compliance gap in the project right now**, and it is unaddressed.

### NIS2 — not yet law in Spain

Spain has **not transposed** Directive (EU) 2022/2555. The *Anteproyecto de
Ley de Coordinación y Gobernanza de la Ciberseguridad* was approved by the
Consejo de Ministros on **14 January 2025** and remains in tramitación as of
July 2026; Spain missed the 17 October 2024 deadline, and the Commission
issued a **second formal notice on 19 May 2026** under infringement
`INFR(2024)0270` — the step before referral to the CJEU.

Practical consequence: NIS2 obligations are **not** directly applicable to
this lab yet, but the framework is arriving and will create a national
authority (Centro Nacional de Ciberseguridad). Counsel should say whether
the eventual law brings a lab of this kind into scope, so the answer is
known before it lands rather than after.

### Contractual and operational exposure

Not law, but the risk that most reliably materialises:

- **ISP acceptable-use terms.** Residential and most business connections
  prohibit this outright. The realistic failure is an abuse report followed
  by disconnection, not a prosecution.
- **Blocklisting** of the lab's address.
- **Cloud provider AUPs** forbid live malware execution — relevant if the
  L0 host ever moves off-premises.

# Dependencies

- None open.
- **Blocks** any non-benign sample execution with networking enabled.
- Informs DRAFT-013 (containment verification) and the network-mode work in
  `docs/architecture/networking.md`.
- Interacts with DRAFT-018 (result schema) — retention and access control
  are schema-adjacent decisions.

# Out of scope

- Implementing the `offline` / `simulated` / `controlled-internet` modes.
  This issue decides what is *required*; building it is separate work.
- The DRAKVUF licensing question (roadmap risk #3's other half, and
  `docs/architecture/licensing.md`). Copyright, not compliance.
- Any change to `automation/`.

# PLAN

1. **Decide the operating entity before consulting anyone.** Personal
   operation, a company, or affiliation with a university or CERT changes
   liability, insurance and how an abuse report is handled. This is the
   input to every other question, not an output.
2. **Establish the connection's status.** Which line does `xenbr0` reach the
   Internet through, and what do its terms say? A residential contract makes
   most of the rest moot until it changes.
3. Prepare a written brief for Spanish counsel from the findings above.
4. Engage counsel with competence in `derecho penal informático` **and**
   data protection — they are frequently not the same person.
5. Record the answers as a decision document, not as advice-in-an-inbox.

# CREATE

The deliverable is `docs/architecture/legal-compliance.md`, stating:

1. The lawful basis for holding and executing samples, with citations.
2. **A decision on live-Internet detonation**: permitted / permitted under
   conditions / prohibited. If conditional, the conditions must be
   mechanically checkable, not aspirational.
3. A GDPR position: Art. 6 basis, Art. 30 record of processing, retention
   periods for pcaps / memdumps / extracted files, access control, and the
   procedure when a sample is found to contain third-party personal data.
4. An incident procedure for the case where a detonation causes or is
   alleged to cause harm.
5. The NIS2 watch item and what would bring the lab into scope.

Then update `docs/checklists/android.md` §1.3's Internet row and
`docs/architecture/networking.md` to match the decision.

# TEST

No code. Verification is review-based:

- Every legal proposition carries a citation to primary law, official
  guidance, or written advice — no unsourced assertions.
- The live-detonation decision is unambiguous enough that an operator can
  apply it without asking.
- The GDPR retention periods are numbers, not adjectives.

# DEPLOY

Not applicable. If the decision restricts current behaviour, the
implementing change is separate work with its own review.

# Acceptance criteria

- [ ] The operating entity is decided and recorded.
- [ ] The uplink's contractual position is established in writing.
- [ ] Spanish counsel has reviewed and responded, in writing.
- [ ] `docs/architecture/legal-compliance.md` exists and covers all five
      CREATE items.
- [ ] A clear yes/no/conditional answer on live-Internet detonation.
- [ ] A GDPR Art. 30 record of processing exists.
- [ ] Retention periods are set for pcaps, memory dumps and extracted files.
- [ ] `docs/checklists/android.md` §1.3's Internet row and
      `docs/architecture/networking.md` agree with the decision.
- [ ] Roadmap risk #3 updated with the outcome.

# Evidence required

Counsel's written response; the ISP terms; the decision document. The
research in this draft is the starting brief, not the evidence.

# Security considerations

- **The lab currently permits unrestricted Internet egress from analysis
  clones.** DRAFT-028 narrowed it to the Internet only — LAN, router, Dom0
  and IPv6 are blocked and counter-verified — but a real sample would still
  reach its C2, pull second stages, and could participate in attacks
  attributable to this connection.
- **Only benign fixtures have been detonated to date**, which is why this
  has not yet been a problem. It becomes one the first time a real sample
  runs, and that is a decision someone will make casually unless this issue
  lands first.
- **The GDPR exposure is already live** and does not depend on egress. Every
  pcap and memory dump in `/malware_finished/` may contain third-party
  personal data, retained indefinitely with no policy.
- Counsel should be asked specifically about the **civil** negligence
  exposure. The criminal analysis is comparatively favourable and is not
  where the risk concentrates.

# Documentation changes

New: `docs/architecture/legal-compliance.md`.
Updated: `docs/roadmap/project-roadmap.md` (risk #3),
`docs/architecture/networking.md`, `docs/checklists/android.md` §1.3.

# Recovery / rollback

Not applicable — no infrastructure or code changes. If counsel's answer
restricts current behaviour, implementing that restriction is its own
change with its own rollback.

---

## Sources consulted (2026-08-11)

| Source | Used for |
|---|---|
| [Art. 264 ter CP, consolidated text (Iberley)](https://www.iberley.es/legislacion/articulo-264-ter-codigo-penal) | Verbatim wording and the two cumulative elements |
| [Fiscalía General del Estado circular `FIS-C-2017-00003` (BOE)](https://www.boe.es/buscar/doc.php?id=FIS-C-2017-00003) | Official reading of 264 ter; dual-use/security-auditing carve-out |
| [Art. 264 CP explained](https://www.conceptosjuridicos.com/codigo-penal-articulo-264/) | Penalties and aggravating circumstances |
| [Universidad de La Laguna — daños informáticos, arts. 264–264 quater](https://portalciencia.ull.es/documentos/63f5731e92c1515eee0e1be8) | Structure of the 264 family |
| [GDPR Recital 49](https://gdpr-info.eu/recitals/no-49/) | Network security as legitimate interest |
| [Botnet defence under EU data protection law (ScienceDirect)](https://www.sciencedirect.com/science/article/pii/S0267364924001468) | Recital 49 applied to security research |
| [NIS2 status in Spain](https://nisd2.eu/es/wiki/timelines-and-status/nis2-status-spain) | Transposition state |
| [NIS2 España — transposición, plazos](https://www.legiscope.com/blog/nis2-espana-transposicion.html) | Anteproyecto date, infringement `INFR(2024)0270`, 19 May 2026 notice |
| [ZeroFox — detonate malware safely](https://www.zerofox.com/blog/detonate-malware-safely/) | Controlled-egress practice |
| [OpenMetal — pentest lab infrastructure](https://openmetal.io/resources/blog/build-a-secure-penetration-testing-lab-with-on-demand-private-cloud-infrastructure/) | Hyperscaler AUP position |

Secondary sources are used for orientation only; the two primary ones are
the consolidated Art. 264 ter text and the Fiscalía circular.