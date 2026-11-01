"""Where a sample is dropped inside the guest, and the command line it gets.

Added 2026-11-01. Three submit options, all optional, and a job that sets none
of them runs exactly as every job did before they existed:

* **A drop location** -- a KEY from a fixed per-guest list, never a path. The
  list here is what the form offers and what `create_job` accepts; the
  analysis host turns the key into a directory with its own copy of the table
  (`sandboxd/guests.py` `PATHS`), so nothing a submitter types becomes a guest
  path. `sandboxd/tests/test_guests.py` pins that the two tables agree.
* **A subfolder** under that location, which the host creates. Held to an
  ASCII allowlist, because on Windows it is made by `cmd.exe /c mkdir` and so
  is shell text there -- see `guests._SUBDIR_CHARS` for the reasoning, which
  `split_subdir` below must not loosen on its own.
* **A command line.** Split into argv words on Ubuntu and Android, passed as
  one string on Windows, where a program parses its own.

The paths shown are built with `settings.analysis_username`, which the
Makefile renders into `api.env` from the same `ANALYSIS_VM_USER` it writes into
`sandboxd/config.py`. **Display only**: if the two ever differ, the form shows
the wrong user's folder and the host still drops into its own.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from enum import StrEnum

from .enums import TargetOs


class DropLocation(StrEnum):
    DESKTOP = "desktop"
    DOWNLOADS = "downloads"
    HOME = "home"
    TEMP = "temp"
    APPDATA = "appdata"
    PROGRAMDATA = "programdata"


@dataclass(frozen=True)
class Location:
    key: DropLocation
    label: str
    # `{user}` is replaced by the analysis username.
    template: str

    def path(self, user: str) -> str:
        return self.template.format(user=user)


#: Per guest, the guest's default FIRST -- the one a job that names no
#: location is dropped into, and the one the form pre-selects.
LOCATIONS: dict[TargetOs, tuple[Location, ...]] = {
    TargetOs.UBUNTU: (
        Location(DropLocation.DESKTOP, "Desktop", "/home/{user}/Desktop"),
        Location(DropLocation.DOWNLOADS, "Downloads", "/home/{user}/Downloads"),
        Location(DropLocation.HOME, "Home", "/home/{user}"),
        Location(DropLocation.TEMP, "Temp", "/tmp"),
    ),
    # One, because the obvious second -- shared storage's Download folder --
    # is mounted noexec, and a native sample dropped there could not run.
    TargetOs.ANDROID: (
        Location(DropLocation.TEMP, "Temp", "/data/local/tmp"),
    ),
    TargetOs.WINDOWS: (
        Location(DropLocation.DESKTOP, "Desktop", "C:\\Users\\{user}\\Desktop"),
        Location(DropLocation.DOWNLOADS, "Downloads", "C:\\Users\\{user}\\Downloads"),
        Location(DropLocation.HOME, "Home", "C:\\Users\\{user}"),
        Location(DropLocation.TEMP, "Temp", "C:\\Users\\{user}\\AppData\\Local\\Temp"),
        Location(DropLocation.APPDATA, "AppData", "C:\\Users\\{user}\\AppData\\Roaming"),
        Location(DropLocation.PROGRAMDATA, "ProgramData", "C:\\ProgramData"),
    ),
}

#: How each guest joins a folder and a name.
SEP: dict[TargetOs, str] = {
    TargetOs.UBUNTU: "/", TargetOs.ANDROID: "/", TargetOs.WINDOWS: "\\",
}

#: True: the command line is split into argv words, POSIX-shell style, and
#: nothing expands. False: it is passed as typed.
SPLITS_ARGUMENTS: dict[TargetOs, bool] = {
    TargetOs.UBUNTU: True, TargetOs.ANDROID: True, TargetOs.WINDOWS: False,
}

MAX_ARGUMENT_BYTES = 1024
MAX_SUBDIR_BYTES = 128
MAX_SUBDIR_DEPTH = 8

_SUBDIR_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                          "abcdefghijklmnopqrstuvwxyz"
                          "0123456789 ._-()+")
_WINDOWS_DEVICE = re.compile(r"\A(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(\..*)?\Z",
                             re.IGNORECASE)

#: The characters cmd.exe re-parses inside a quoted command. A Windows command
#: line holding one is still accepted -- it reaches the sample byte-exact --
#: but the host then starts the sample without its launch delay
#: (`guests._windows_launch`), and the form says so before submission.
CMD_SPECIAL = '"%&<>|^!'


def locations_for(os_: TargetOs) -> tuple[Location, ...]:
    return LOCATIONS[os_]


def default_location(os_: TargetOs) -> Location:
    return LOCATIONS[os_][0]


def check_location(os_: TargetOs, key: DropLocation | None) -> None:
    if key is None:
        return
    offered = [loc.key for loc in LOCATIONS[os_]]
    if key not in offered:
        raise ValueError(
            f"drop location {key.value!r} is not offered on {os_.value}; "
            f"choose one of {[k.value for k in offered]}"
        )


def split_subdir(os_: TargetOs, raw: str | None) -> tuple[str, ...]:
    """The same rule as `sandboxd.guests.split_subdir`. Raises ValueError."""
    text = (raw or "").strip()
    if not text:
        return ()
    if len(text.encode()) > MAX_SUBDIR_BYTES:
        raise ValueError(f"subfolder exceeds {MAX_SUBDIR_BYTES} bytes")
    parts = re.split(r"[\\/]", text.rstrip("\\/"))
    if len(parts) > MAX_SUBDIR_DEPTH:
        raise ValueError(f"subfolder is more than {MAX_SUBDIR_DEPTH} levels deep")
    for part in parts:
        if part in ("", ".", ".."):
            raise ValueError(f"subfolder {text!r} is not a plain relative path")
        bad = sorted(set(part) - _SUBDIR_CHARS)
        if bad:
            raise ValueError(
                f"subfolder name {part!r} contains {''.join(bad)!r}; use letters, "
                f"digits, spaces and . _ - ( ) +")
        if part != part.strip() or part.endswith("."):
            raise ValueError(
                f"subfolder name {part!r} starts or ends with a space, or ends "
                f"with a dot")
        if os_ is TargetOs.WINDOWS and _WINDOWS_DEVICE.match(part):
            raise ValueError(f"subfolder name {part!r} is reserved on windows")
    return tuple(parts)


def check_arguments(os_: TargetOs, raw: str | None) -> str:
    """The command line, stripped, or ValueError. `""` is no command line."""
    text = (raw or "").strip()
    if len(text.encode()) > MAX_ARGUMENT_BYTES:
        raise ValueError(f"command line exceeds {MAX_ARGUMENT_BYTES} bytes")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise ValueError(f"command line contains a control character: {text!r}")
    if text and SPLITS_ARGUMENTS[os_]:
        try:
            shlex.split(text)
        except ValueError as exc:
            # shlex's own words are "No closing quotation" and "No escaped
            # character"; say which rule they come from.
            raise ValueError(
                f"command line cannot be split into arguments: {exc}") from None
    return text


def drop_dir(os_: TargetOs, key: str | None, subdir: str | None,
             user: str) -> str:
    """The guest directory a job's sample was dropped into, for display.

    Never raises: it renders a stored row, and a value no longer offered is
    shown as stored rather than hiding the job.
    """
    by_key = {loc.key.value: loc for loc in LOCATIONS[os_]}
    base = (by_key[key].path(user) if key in by_key
            else default_location(os_).path(user) if key is None
            else f"<{key}>")
    parts = [p for p in re.split(r"[\\/]", subdir or "") if p]
    return SEP[os_].join((base, *parts))