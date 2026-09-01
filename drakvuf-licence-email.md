# Draft email to the DRAKVUF maintainer

**Untracked working file, not part of the repository deliverable.** Edit
freely; delete once sent. If the reply changes the project's licensing
position, record *that* in `docs/architecture/licensing.md` — not this
file.

**To:** Tamas K Lengyel — `tamas@tklengyel.com` (the address in the
licence header; `tamas.k.lengyel@gmail.com` also appears there)

**Status:** not sent.

---

**Subject:** Publishing a DRAKVUF-based multi-OS sandbox, and a question
about hosted use

Hi Tamas,

I've built an automation layer around DRAKVUF — a multi-OS analysis lab
(Ubuntu, Android/BlissOS, Windows) running Xen nested inside Proxmox,
using LVM copy-on-write clone-per-run rather than snapshot-restore, with
per-VLAN network isolation. It orchestrates `drakvuf` and `injector` as
subprocesses and parses their output.

I'm planning to publish the source, and I'd like to check two things with
you before I do.

**First**, my reading of the DRAKVUF licence is that orchestration of this
kind is a derivative work — the terms are explicit that executing a helper
program to run or parse Covered Software counts. So the compliant path is
to release under the same terms, GPL-2 with DRAKVUF's clarifications,
which is what I intend. Does that match your intent?

**Second**, I'd eventually like to offer hosting as a paid service, for
people who want this kind of analysis but can't run nested-virtualisation
infrastructure themselves. The source would remain public under the same
licence. My understanding is that GPL-2 doesn't treat hosting as
distribution and doesn't restrict charging, and that your additional terms
are aimed at proprietary embedding rather than at commercial use of
licensed code — so I read this as permitted. I'd rather confirm that with
you than assume it.

Happy to share the repository if it's useful context.

Thanks for DRAKVUF — it's been a genuinely good foundation to build on.

[name]

---

## Notes on the draft — not part of the email

**The second question is framed as confirming, not asking permission**, and
that is deliberate. GPL-2 has no network-copyleft clause, hosting is not
distribution, and GPL explicitly permits charging. The licence's additional
restrictions target *proprietary* embedding, which public source avoids. So
permission is very likely not his to grant or refuse. Asking anyway is
cheap insurance and good manners; framing it as a permission request would
misstate the position and invite a "no" to something that was never a
prohibition.

**Held back for a follow-up, once he has replied:** the licence says
*"Covered Work may not be combined (even as part of a larger work) with
plain GPL software."* GPL-2 §6 forbids further restrictions; DRAKVUF's
licence imposes them; so the two are incompatible for combination
purposes, and a plain-GPL library linked into Covered Work would make the
result undistributable by anyone. Same structure as the historical Nmap
licence problem, from which this text is derived.

Its immediate practical consequence — worth acting on regardless of his
reply — is that **the repository cannot be labelled plain GPL-2**. A stock
`LICENSE` file would contradict itself. Reproduce DRAKVUF's text with its
clarifications, as `automation/*.sh` already do in their headers.

Not currently a risk: LGPL linking is explicitly permitted (glib, LibVMI,
the Xen libraries); separate programs exchanging data are not "combined"
(capa reading a log file); Redis is a network service and its clients are
permissive. The trap is prospective — the day a plain-GPL library gets
linked into this project's own code.

## What this email does NOT cover

The licence is probably the **smaller** legal question, and this email
should not be mistaken for having handled the larger one. From DRAFT-022:

- **GDPR.** `tcpdump.sh` captures the clone's whole interface, so a sample
  exfiltrating a victim's data puts third-party personal data into a pcap,
  retained indefinitely with no retention policy. This applies *today* and
  gets materially worse the moment third parties can submit samples.
- **Civil negligence** (Código Civil art. 1902) has no intent element.
  "I permitted unrestricted egress from a host I knew was running malware"
  is the fact pattern it exists for.
- **ISP terms** — the risk that most reliably materialises in practice: an
  abuse report and disconnection, not a prosecution.

DRAFT-022 names two prerequisites answerable without a lawyer, and a paid
service makes both sharper:

1. **What entity operates the lab?** A paid service almost certainly means
   the answer cannot remain "a private individual" — it changes liability,
   insurance, and how an abuse report is handled.
2. **What connection does `xenbr0` reach the Internet through, and what do
   its terms say?** If it is a residential line, that is the binding
   constraint and most of the rest is moot until it changes.