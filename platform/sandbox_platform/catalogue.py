"""What each guest OS can actually produce, and how sure we are.

Issue #38. Source of truth: `drakvuf_plugin_os_support[plugin][os]` in
DRAKVUF's `src/plugins/plugins.h`, read 2026-08-24 against both
`tklengyel/main` and `lfreijo/memdump` -- see
`docs/architecture/upstream-drakvuf.md` for the full 45-plugin matrix.

**This exists so the UI cannot offer a tab that can never be filled.** A
Registry tab is meaningless on Ubuntu because `regmon` is Windows-only;
`ebpfmon` cannot exist on Windows. A fixed tab list would give an Ubuntu
report a row of tabs that are permanently empty, which reads as a broken page
rather than as a property of the guest.

**`AVAILABLE` is not `PROVEN`, and the gap is per GUEST rather than per OS
family.** `plugins.h` carries a single `VMI_OS_LINUX` flag, but Ubuntu and
Android share only a kernel: Android's userspace is Bionic, ART and binder,
so a plugin walking `task_struct` against BlissOS is not the same test as
against Ubuntu, and either may fail where the other works. Windows joined the
evidenced set on 2026-09-17, on one end-to-end job (operator-confirmed,
2026-09-05, DRAFT-034) -- which is a thinner basis than Ubuntu's or Android's
and is recorded as such at `_EVIDENCED`.

So evidence is tracked as a set of guests, never as a property of the plugin.
The per-guest validation matrix in `docs/checklists/android.md` §0.4 is the
pattern; DRAFT-050 owns doing it for all 45 against all three.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .enums import TargetOs


class Support(StrEnum):
    """How much we actually know about this plugin on this guest."""

    # Enabled in the pipeline today and evidenced end to end.
    PROVEN = "proven"
    # plugins.h permits it for this OS family; never run against our guests.
    CANDIDATE = "candidate"
    # plugins.h forbids it for this OS family. Shown greyed, never selectable,
    # because "why is there no registry tab" is a question worth answering on
    # the page instead of in a document.
    UNSUPPORTED = "unsupported"


# The guests each of the four current plugins has actually run against.
#
# Ubuntu and Android are evidenced end to end -- Ubuntu throughout, Android on
# 2026-08-17 (`docs/runbooks/07-verify-android-mvp.md`).
#
# **Windows was added 2026-09-17 on a weaker basis than the other two, and the
# difference is worth knowing before trusting the badge.** It rests on one
# end-to-end job, operator-confirmed for 2026-09-05 (DRAFT-034), with no
# runbook behind it -- where the other two point at dated transcripts. What
# that job proves is that the pipeline COMPLETES on Windows with these four
# enabled. It does not prove each one produced output: nobody has run the
# per-plugin validation matrix against a Windows guest, and `syscalls` in
# particular degrades to silence rather than to an error when the symbol JSON
# is partial (`sandboxd/guests.py`). DRAFT-050 owns that matrix for all 45
# plugins against all three guests, and it is what would put Windows on the
# same footing rather than merely in the same set.
_EVIDENCED = frozenset({TargetOs.UBUNTU, TargetOs.ANDROID, TargetOs.WINDOWS})


@dataclass(frozen=True)
class Plugin:
    name: str
    # One line, written for someone who has not read DRAKVUF's source. This is
    # what the advanced disclosure shows next to each checkbox.
    describes: str
    linux: bool
    windows: bool
    # Pre-ticked on the submit form. Separate from evidence: these are what
    # drakvuf-<os>.sh enables today, which on Windows is a plan rather than a
    # record.
    default: bool = False
    # Guests this has actually run against. Never inferred from `linux`.
    proven_on: frozenset[TargetOs] = frozenset()
    # Rough run-time cost. `ipt` and `apimon` are heavy enough to matter
    # against the 180s trace cap the old watcher compiled in, and Android already needs
    # `-F --disable-sysret` merely to finish.
    heavy: bool = False

    def support(self, os_: TargetOs) -> Support:
        # Android is a Linux-kernel guest, so it reads the same flag as
        # Ubuntu. That is where the similarity ends -- see `proven_on`.
        ok = self.windows if os_ is TargetOs.WINDOWS else self.linux
        if not ok:
            return Support.UNSUPPORTED
        return Support.PROVEN if os_ in self.proven_on else Support.CANDIDATE


# Only the plugins a person might plausibly choose. The full 45 -- including
# the ones nothing here would ever want, like `bsodmon` -- belong in
# DRAFT-050's audit, not in a form.
PLUGINS: tuple[Plugin, ...] = (
    Plugin("syscalls", "System calls made by the sample",
           linux=True, windows=True, default=True, proven_on=_EVIDENCED),
    Plugin("filetracer", "File opens, writes and deletes",
           linux=True, windows=True, default=True, proven_on=_EVIDENCED),
    Plugin("fileextractor", "Recovers files the sample wrote",
           linux=True, windows=True, default=True, proven_on=_EVIDENCED),
    Plugin("memdump", "Memory regions the sample wrote to",
           linux=True, windows=True, default=True, proven_on=_EVIDENCED),

    Plugin("procmon", "Process creation and exit -- the process tree",
           linux=True, windows=True),
    Plugin("procdump2", "Dumps whole process memory",
           linux=True, windows=True),
    Plugin("cpuidmon", "The sample's own checks for a hypervisor",
           linux=True, windows=True),
    Plugin("debugmon", "Debug registers and breakpoint use",
           linux=True, windows=True),
    Plugin("ipt", "Instruction-level trace (Intel PT)",
           linux=True, windows=True, heavy=True),
    Plugin("hidsim", "Injects synthetic mouse and keyboard input",
           linux=True, windows=True),

    Plugin("ptracemon", "Anti-debugging via ptrace",
           linux=True, windows=False),
    Plugin("ebpfmon", "eBPF programs loaded into the kernel",
           linux=True, windows=False),
    Plugin("unixsocketmon", "Unix-domain socket messages",
           linux=True, windows=False),
    # The Linux counterpart of `apimon`, from our DRAKVUF fork. `heavy` for
    # the same reason apimon is: a breakpoint per hooked function, and the
    # hook list decides the cost (`sandboxd/data/so-hooks-linux.txt`).
    #
    # `linux=True` covers Ubuntu AND Android, because `support()` reads one
    # flag for both -- but only Ubuntu has it on by default, and Android's
    # standing is unverified rather than proven. `proven_on` is therefore
    # left empty, which renders it Candidate on both; see the
    # `_ANDROID_PLUGINS` comment in `sandboxd/guests.py`.
    Plugin("libmon", "Linux shared-library calls, with arguments",
           linux=True, windows=False, heavy=True),

    Plugin("apimon", "Windows API calls and DLL loads",
           linux=False, windows=True, heavy=True),
    Plugin("regmon", "Registry reads and writes",
           linux=False, windows=True),
    Plugin("socketmon", "Network connections, from inside the guest",
           linux=False, windows=True),
    Plugin("tlsmon", "TLS keys -- lets captured HTTPS be decrypted",
           linux=False, windows=True),
    Plugin("rootkitmon", "Kernel structures altered by rootkits",
           linux=False, windows=True),
)

BY_NAME = {p.name: p for p in PLUGINS}


def for_os(os_: TargetOs) -> list[tuple[Plugin, Support]]:
    """Every offerable plugin with its standing on this guest, unsupported
    ones last so the selectable set reads as one block."""
    rated = [(p, p.support(os_)) for p in PLUGINS]
    rated.sort(key=lambda r: (r[1] is Support.UNSUPPORTED,
                              r[1] is not Support.PROVEN, r[0].name))
    return rated


# `defaults(os_)` was removed 2026-09-17 with DRAFT-052. It existed to tell a
# report page which plugins a job PROBABLY ran, back when the selection was not
# recorded; the job now carries its own `plugins`, so the guess had exactly one
# caller and that caller was the placeholder. The checkbox defaults on the
# submit form come from `Plugin.default` directly.


# --- tabs ------------------------------------------------------------------
#
# Each tab names the plugins that could fill it. A tab whose every source is
# UNSUPPORTED on this guest is not rendered at all -- that is the whole point
# of this module.


@dataclass(frozen=True)
class Tab:
    slug: str
    label: str
    # Empty means the tab does not depend on any plugin: Overview and
    # Artifacts are built from the job row and the manifest, so they exist
    # for every OS and are the only two #38 actually fills.
    sources: tuple[str, ...] = ()
    # The issue that will fill it. Rendered in the empty state, because
    # "not collected yet" without a pointer is just a dead end.
    #
    # NOT the job's owner, and nothing to do with tenancy -- this is the DRAFT
    # that owns delivering the tab, rendered as prose by `_job_tabs.html` and
    # `tabs/_pending.html`. Typing it as a tenant id broke the package at
    # import (a non-default field cannot follow `sources`), 2026-09-11.
    owner: str = ""


TABS: tuple[Tab, ...] = (
    Tab("overview", "Overview"),
    Tab("behaviour", "Behaviour",
        ("syscalls", "procmon", "apimon"), "DRAFT-050 + DRAFT-019"),
    # Always present: a pcap is captured on every run, outside DRAKVUF entirely
    # (`sandboxd/guests.py::argv_tcpdump`, spawned for the trace's lifetime by
    # `sandboxd/stages.py`), so network data does not depend on any plugin. The
    # plugins listed only ENRICH it -- socketmon attributes connections to
    # processes, tlsmon supplies keys to decrypt what was captured.
    Tab("network", "Network",
        ("socketmon", "tlsmon", "unixsocketmon"), "DRAFT-049"),
    Tab("static", "Static", (), "DRAFT-048 + DRAFT-019"),
    Tab("memory", "Memory",
        ("memdump", "procdump2", "fileextractor"), "DRAFT-051"),
    Tab("registry", "Registry", ("regmon",), "DRAFT-050"),
    Tab("artifacts", "Artifacts"),
)

# Tabs that exist for every guest, because nothing about them depends on a
# plugin: Overview and Artifacts come from the job row and the manifest;
# Static is driven by the uploaded bytes rather than the trace; Network rests
# on the pcap sandboxd captures on every run, outside DRAKVUF.
_ALWAYS = {"overview", "artifacts", "static", "network"}


def tabs_for(os_: TargetOs) -> list[Tab]:
    """The tabs this guest can ever fill."""
    out = []
    for tab in TABS:
        if tab.slug in _ALWAYS:
            out.append(tab)
            continue
        if any(BY_NAME[s].support(os_) is not Support.UNSUPPORTED
               for s in tab.sources):
            out.append(tab)
    return out
