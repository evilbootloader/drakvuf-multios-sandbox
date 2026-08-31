# `private/` — compliance, legal and correspondence. Not tracked.

**Everything in this directory except this file is gitignored**, and that is
deliberate rather than tidy. This repository is intended to become public.

The pattern is the one `profiles/`, `state/` and `tls/ca/` already use here: a
tracked `README.md` naming what belongs in a directory whose contents never
reach a commit.

## What belongs here

| | |
|---|---|
| `legal/` | The legal and compliance position — operating entity, uplink, jurisdiction analysis, anything written for or by counsel |
| `egress-exits.md` | Which hosts can carry analysis egress, what their AUPs say, and the letter that asks them |
| `outreach/` | Letters sent to hosts and the replies. **A reply is the agreement** — file it with its date |

## Why, precisely

Not squeamishness. Three specific reasons, each with a different shape:

1. **Analysis of one's own liability is not documentation, it is
   discoverable material.** A public file reasoning about whether an activity
   breaches a contract or a statute is a written record that the operator
   considered the question — useful to a counterparty in a dispute, in a way
   that a firewall rule is not.
2. **A stated intention is a commitment to a third party.** Business plans and
   host correspondence describe what has been promised to whom. Publishing
   them publishes the other party's position as well as ours.
3. **Naming which hosts said yes advertises the exit.** The value of a host
   that agreed in writing is partly that not everyone knows which one it is.

## What stays public, and this is the useful half

**The mechanism.** Egress modes, the per-VLAN chains, the kill-switch design,
the throttles, the evidence that they work — all of it is ordinary engineering
documentation and publishing it costs nothing. `docs/architecture/networking.md`
carries it.

The rule that separates them: **a public document may say what the system
does and why that is the right design. It should not say what the operator
fears, owes, or intends commercially.** "Egress leaves through a chosen exit
and fails closed if the tunnel drops" is public. "…because otherwise the
household line gets disconnected" is not.

## Two things a mv does not fix

- **Git history.** A file that was ever committed stays in history, and a
  repository going public publishes its history. Moving something here today
  protects it only if it was never committed. See `docs/TROUBLESHOOTING.md`
  before assuming a move was sufficient.
- **Cross-references.** Tracked documents may still quote the material. A
  pointer to this directory leaks nothing; a restatement of the contents does.