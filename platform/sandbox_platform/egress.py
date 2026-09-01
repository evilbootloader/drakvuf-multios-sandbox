"""What each egress mode means, written for the person choosing one.

DRAFT-057. Parallel to `catalogue.py`, and for the same reason it exists: the
form must not offer something the deployment cannot do, and it must not present
"available" and "safe" as the same claim.

**Nothing here decides availability.** That comes from `worker_egress`, which
the analysis host writes at registration -- only Dom0 knows what its own
interfaces are. This module supplies the words; the database supplies the set.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import EgressMode


@dataclass(frozen=True)
class ModeInfo:
    """How one mode is described on the submit form."""

    mode: EgressMode
    label: str
    #: One line, for someone who has not read any of this repository.
    describes: str
    #: What this mode costs, stated where the choice is made rather than
    #: discovered afterwards in a report that showed nothing.
    caution: str = ""
    #: True for modes where the sample genuinely reaches the Internet. The form
    #: renders these differently -- this is the line the whole issue is about.
    live: bool = False


# Ordered safest-first, and the form renders them in this order. A person
# scanning a list takes the first plausible option, so the first option should
# be the one that cannot hurt them.
MODES: tuple[ModeInfo, ...] = (
    ModeInfo(
        EgressMode.SIMULATED, "Simulated internet",
        "A responder on the gateway answers the sample instead of the real "
        "Internet. DNS resolves, connections succeed, nothing leaves the host.",
        caution="Responses are synthetic, so a sample that checks for a "
                "specific server will not find one. No real C2 is contacted.",
    ),
    ModeInfo(
        EgressMode.OFFLINE, "No network",
        "The clone has an address and a gateway, and no route out.",
        caution="A black-holed network is itself a sandbox signal -- the guest "
                "sees timeouts where a real host would answer with RST or "
                "ICMP unreachable.",
    ),
    ModeInfo(
        EgressMode.TOR, "Through Tor",
        "Real Internet access, transparently through the Tor network. The "
        "sample's traffic leaves from a Tor exit rather than from this lab.",
        caution="Tor carries TCP only. UDP command-and-control and direct DNS "
                "cannot leave and will be absent from the capture -- absent "
                "because they were blocked, which the report says explicitly. "
                "Tor's default exit policy also rejects ports 25 and 445, so "
                "mail and SMB behaviour will not appear.",
        live=True,
    ),
    ModeInfo(
        EgressMode.ROUTED, "Through our exit",
        "Real Internet access through a server we rent, in a country you "
        "select. All protocols, nothing filtered that we did not filter.",
        caution="The sample really does contact its infrastructure, from an "
                "address that is ours.",
        live=True,
    ),
    ModeInfo(
        EgressMode.DIRECT, "Direct (host uplink)",
        "NAT straight out of the analysis host's own connection.",
        caution="The traffic carries this lab's own address. Available only "
                "when an operator has explicitly enabled it on the host, and "
                "intended for reproducing earlier measurements rather than for "
                "analysing anything real.",
        live=True,
    ),
)

BY_MODE = {m.mode: m for m in MODES}

#: Rendered next to an exit that carries one, so a limitation is visible at the
#: moment of choosing rather than inferred later from an empty pcap.
#:
#: DRAFT-057 acceptance criterion 7: an exit that blocks a port must make the
#: report distinguish "no SMTP traffic" from "SMTP was blocked upstream". These
#: are the same strings sandboxd attaches to an exit, kept here as prose.
CAVEATS: dict[str, str] = {
    "tcp-only": "TCP only — UDP and ICMP cannot leave",
    "dns-via-resolver-only": "DNS is answered by the exit's resolver",
    "smtp-blocked-upstream": "port 25 blocked upstream — no SMTP will appear",
    "smb-blocked-upstream": "ports 137-139/445 blocked upstream — no SMB",
    "no-real-internet": "nothing reaches the real Internet",
    "egresses-via-host-uplink": "traffic carries this lab's own address",
    "tls-untrusted-cert": (
        "HTTPS is refused by the sample, not answered — the responder's "
        "certificate is not one the guest trusts, so encrypted traffic will "
        "be absent from the report"
    ),
}


def describe_caveat(slug: str) -> str:
    """Prose for a caveat, falling back to the slug itself.

    A slug this deployment has not seen is still shown. The alternative --
    dropping it -- would hide a limitation the analysis host explicitly
    reported, which is precisely the failure the caveat mechanism exists to
    prevent. An ugly string on the page beats a silent omission.
    """
    return CAVEATS.get(slug, slug)


@dataclass(frozen=True)
class Offer:
    """One exit a submitter may actually choose, as the host declared it."""

    name: str
    mode: EgressMode
    country: str | None = None
    caveats: tuple[str, ...] = ()

    @property
    def info(self) -> ModeInfo:
        return BY_MODE[self.mode]

    @property
    def caveat_text(self) -> list[str]:
        return [describe_caveat(c) for c in self.caveats]


def sort_offers(offers: list[Offer]) -> list[Offer]:
    """Safest first, matching MODES order, then by name within a mode.

    Deterministic ordering matters beyond tidiness: the form pre-selects the
    first entry, so an unstable sort would make the default depend on row order
    from the database.
    """
    rank = {m.mode: i for i, m in enumerate(MODES)}
    return sorted(offers, key=lambda o: (rank.get(o.mode, len(rank)), o.name))