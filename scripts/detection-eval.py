#!/usr/bin/env python3
"""Measure the signatures on samples whose answer is known: benign and malicious, both guests.

`submit` feeds the platform a labelled set; `report` reads every run's
`cape_results.json` back and says which signatures fire on which side, so
severities can be tuned against data. Linux comes first in the report, because
the Linux signatures (`modules/signatures/linux/`) are ours.

    scripts/detection-eval.py submit --platform https://sandbox.example.com --malicious 20 --benign 20
    scripts/detection-eval.py report --platform https://sandbox.example.com --os ubuntu

Where the samples come from:

* **Malicious**: MalwareBazaar, taken exactly as `bazaar-submit.py` takes
  them. Its query, download, AES-zip extraction and header sniff are imported
  from that script, not copied. `exe` rows go to the Windows guest, `elf` rows
  to Ubuntu. The header has the last word, so ARM and MIPS ELF are skipped.
  `--query detections[:HOURS]` adds a query that script has not:
  `recent_detections`, the files MalwareBazaar put a family on in the last
  HOURS. Its rows carry a hash and a family and no file type, so each one is
  described by a `get_info` lookup before it is downloaded (`--lookups` caps
  them). Whatever the query, families take turns, the least run first, and
  `--per-family` caps the jobs one family gets on a guest: the newest ELF on
  a given morning is one campaign, and nine runs of it measure one behaviour.
* **Never the same file twice**: a sample is skipped when its sha256 has a
  job in the state file, in bazaar-submit.py's state file (`--bazaar-state`),
  or on the platform itself (`GET /api/v1/jobs?sha256=`, which answers for
  the caller's own jobs and the public ones). A job that failed is not a run.
* **Benign**: drawn at random from software distributions' own indexes,
  which publish a hash for every file they serve, so nothing is hardcoded.
  Searched 2026-11-13, no open database hands out labelled known-good
  executables for both guests the way MalwareBazaar hands out malware. The
  labelled corpora (EMBER, BODMAS, SOREL-20M) ship features or disarmed
  binaries. DikeDataset has real files, but Windows only, frozen since 2023,
  and its benign side was gathered from web searches. The sandboxes that hold
  both sides (Triage, Hybrid Analysis, VirusTotal) keep downloads behind
  vetted or paid access, and label a file by their own verdict, which is the
  very thing being measured here.
  - Ubuntu: the archive of the guest's own release (`--ubuntu-dist`, jammy,
    because the golden image is 22.04), components `main` and `universe`. One
    program comes from each `.deb`, and the package is checked against the
    `Packages` index. `universe` brings the Go and Rust builds, `main` the
    distribution's dynamically linked programs. The index is trusted on HTTPS
    alone: nothing here verifies the archive's GPG signature.
  - Windows: Scoop's `main` bucket, whose rule is command-line programs only
    (GUI programs go to `extras`). Each manifest gives the download URL, its
    hash, and which `.exe` is the program. Only manifests that are one
    zip/tar/exe download are used. Ones that run install scripts, depend on
    other apps, or come as 7z or MSI are passed over.
  Before submission, each benign file is looked up in MalwareBazaar, and
  dropped if MalwareBazaar has it. `--benign-exclude` drops names by regex,
  for the dual-use tools both indexes carry (nmap, socat, netcat).

  Nothing in the benign set needs a person, for now. On Ubuntu the sample is
  exec'd from pid 1 with stdin on /dev/null, and the GUI sections and the
  ones made of interactive programs are skipped. On Windows the sample runs
  under `cmd /c` with a console. A command-line program that reads that
  console when given no arguments (an editor, a REPL, a pager) waits there
  until the trace ends, which costs the run its behavior but not the run
  itself.

How they run: with `bazaar-submit.py`'s options and its submit path. That
means the submit page's default plugins, `--seconds`, `--egress`,
`--concurrent` jobs in flight, and each job published once it ends unless
`--private`. Every sample goes in as `<sha256>.exe` or `<sha256>.elf`, benign
ones too, so no signature can tell the two sides apart by name. The four cells
(malicious and benign, per guest) take turns, so any drift in the lab over a
day hits both sides alike. `--malicious` and `--benign` say how many jobs each
cell should hold in the state file, so an interrupted run is finished by
running the same command again.

What the report gives, per guest:

* each signature's hit rate on benign and on malicious runs. Next to it come
  its severity in the run and in this checkout (with the file:line to edit),
  whether the malscore counts its categories at all, and a hint:
  `noisy` (fires on benign about as often as on malware), `fp-driver` (scored,
  and present in benign runs that come out Suspicious or Malicious),
  `discriminative` (malware only), `unscored` (its severity cannot move the
  malscore);
* how well the malscore separates the two sides, as the run computed it and
  as it comes out with **the severities, confidences, weights and categories
  now in this checkout**. The second figure comes from rerunning CAPE's own
  `scoring.py` over the cached signature hits. Edit a severity, rerun
  `report`, and the numbers move without a new analysis. A change to what a
  signature *matches* still needs the runs reprocessed, because this replays
  scores, not traces. A field a signature sets at run time (falco_linux
  raises its severity to the alert's priority) keeps the run's value, and
  the report marks it;
* the benign runs that score Suspicious or Malicious, with the scored
  signatures that put them there.

Reports are fetched once through the API (`artifact.zip`, the AES-256
wrapper every download gets since 2026-11-14, read with `stream_unzip`), trimmed to the signature hits and what scoring
reads, and cached under `<workdir>/reports/`. `--refresh` fetches them again.
`--bazaar-state` adds the runs `bazaar-submit.py` recorded, labelled malicious.

Safety is `bazaar-submit.py`'s: samples are written only under `--workdir`
(0700, files 0600), never executed, never parsed past the header, and deleted
after the upload unless `--keep`. Archives are read member by member: nothing
is written under a name the archive chose.

Dependencies: `bazaar-submit.py`'s (`httpx`; `pyzipper` or `7z` for
MalwareBazaar's zip), `stream_unzip` for the platform's own wrapper, and
Python 3.14 for the zstd `data.tar` in jammy's packages. `platform/.venv` has
all of them (platform/requirements.in).
"""
from __future__ import annotations

import argparse
import ast
import csv
import getpass
import gzip
import hashlib
import importlib.util
import io
import json
import os
import random
import re
import shutil
import stat
import statistics
import sys
import tarfile
import tempfile
import time
import warnings
import zipfile
from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SIGNATURES_DIR = REPO / "sandboxd/data/cape-community/modules/signatures"
SCORING_PY = REPO / "sandboxd/postprocessing/plugins/cape_plugin/scoring.py"

OSES = ("ubuntu", "windows")          # report order: Linux first
LABELS = ("malicious", "benign")
GUEST_OF_FILE_TYPE = {"exe": "windows", "elf": "ubuntu"}   # MalwareBazaar's file_type
#: Where each guest's own signatures live in the community checkout; `all/`
#: is the fallback for a name defined there.
SIGNATURE_DIR_OF = {"ubuntu": "linux", "windows": "windows"}
RESULTS_NAME = "cape_results.json"
ARTIFACT_PASSWORD = "infected"        # packaging.py's, on every download
MAX_RESULTS_BYTES = 64 * 1024 * 1024  # the platform's own cap (cape.py)
FLAGGED = frozenset({"Suspicious", "Malicious"})
HTTP_HEADERS = {"User-Agent": "detection-eval/1.0 (+https://github.com/evilbootloader/drakvuf-multios-sandbox)"}

#: Sections of the Ubuntu archive whose packages ship programs that run
#: unattended. Libraries, headers, kernels, docs and language modules mostly
#: ship no program, and every package tried costs a download. Left out until
#: interaction is simulated (operator, 2026-11-13): the GUI sections (gnome,
#: x11, games, graphics, sound, video) and the ones made of programs that wait
#: for a person (editors, shells, interpreters, comm, math).
ARCHIVE_SECTIONS = frozenset({
    "admin", "database", "devel", "httpd", "mail", "misc", "net", "otherosfs",
    "text", "utils", "vcs", "web",
})
BIN_DIRS = ("usr/bin/", "usr/sbin/", "bin/", "sbin/")
#: Scoop's `main` bucket as one tarball: the whole index in one request,
#: without the GitHub API's rate limit. Re-read once it is a day old, because
#: manifests follow upstream releases and an old one points at a moved file.
SCOOP_BUCKET = "https://codeload.github.com/ScoopInstaller/Main/tar.gz/refs/heads/master"
SCOOP_MAX_AGE = 24 * 3600
HASH_ALGOS = ("sha256", "sha512", "sha1", "md5")   # what a Scoop `hash` may name
TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz", ".tbz2", ".tar.zst")

#: Hint thresholds. `noisy`: on at least this share of benign runs, and on
#: malicious runs less than twice as often. `discriminative`: on no benign
#: run and on at least this share (and two) of the malicious ones.
NOISY_RATE = 0.10
DISCRIMINATIVE_RATE = 0.05


def _load(name: str, path: Path):
    """A module by path. bazaar-submit.py's name has a hyphen, and scoring.py
    sits in a package whose __init__ wants all of sandboxd."""
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Before execution: bazaar's frozen dataclass resolves its postponed
    # annotations through sys.modules[cls.__module__].
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


bz = _load("bazaar_submit", HERE / "bazaar-submit.py")
log = bz.log


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- the pure parts, tested in sandboxd/tests/test_detection_eval.py ---------

class TooBig(Exception):
    """A file over --max-bytes: a fact about the source, recorded as a skip."""


@dataclass(frozen=True)
class ScoopApp:
    name: str
    version: str
    url: str
    digest: tuple[str, str]   # (hashlib name, hex)
    file_name: str            # what the download is, by Scoop's `#/name` or the URL's path
    program: str              # basename of the .exe the manifest's `bin` names


def _first_bin(value) -> str | None:
    """Scoop's `bin`: a path, a list of paths, or lists of [path, alias, args...]."""
    while isinstance(value, list):
        if not value:
            return None
        value = value[0]
    return value if isinstance(value, str) else None


def scoop_app(name: str, manifest: dict) -> ScoopApp | None:
    """One manifest as a single download whose program is known, or None.

    None for everything that is more than a download: install scripts, a
    dependency, several URLs assembled into one app, a `bin` that is a script
    shim, or a format this reads only with 7z or msiexec.
    """
    arch = manifest.get("architecture") or {}
    arch = arch.get("64bit") or arch.get("32bit") or {}
    if any(k in manifest or k in arch for k in ("installer", "pre_install", "post_install", "depends", "innosetup")):
        return None
    url, digest = arch.get("url", manifest.get("url")), arch.get("hash", manifest.get("hash"))
    program = _first_bin(arch.get("bin", manifest.get("bin")))
    if not (isinstance(url, str) and isinstance(digest, str) and program):
        return None
    program = _basename(program)
    if not program.lower().endswith(".exe"):
        return None
    base, _, fragment = url.partition("#")
    file_name = fragment.lstrip("/") if fragment.startswith("/") else base.split("?", 1)[0].rsplit("/", 1)[-1]
    lower = file_name.lower()
    if not (lower.endswith((".exe", ".zip")) or lower.endswith(TAR_SUFFIXES)):
        return None
    algo, _, hexd = digest.rpartition(":")
    algo = algo.lower() or "sha256"
    if algo not in HASH_ALGOS or not re.fullmatch(r"[0-9a-fA-F]+", hexd):
        return None
    return ScoopApp(name, str(manifest.get("version", "")), base, (algo, hexd.lower()), file_name, program)


def scoop_apps(bucket_tar: bytes) -> list[ScoopApp]:
    """Every usable app of a bucket, from its repository tarball's `bucket/*.json`."""
    out = []
    with tarfile.open(fileobj=io.BytesIO(bucket_tar), mode="r:*") as t:
        for m in t.getmembers():
            parts = m.name.split("/")
            if not (m.isreg() and len(parts) >= 2 and parts[-2] == "bucket" and parts[-1].endswith(".json")):
                continue
            try:
                manifest = json.load(t.extractfile(m))
            except ValueError:
                continue
            app = scoop_app(parts[-1][:-5], manifest) if isinstance(manifest, dict) else None
            if app:
                out.append(app)
    return sorted(out, key=lambda a: a.name)   # a seed draws the same apps whatever the tar's order


def _basename(name: str) -> str:
    return re.split(r"[\\/]", name)[-1]


def copy_capped(src, dest: Path, max_bytes: int) -> None:
    """Copy a stream into a new 0600 file, refusing past max_bytes."""
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
    n = 0
    with os.fdopen(fd, "wb") as out:
        while chunk := src.read(1 << 20):
            n += len(chunk)
            if n > max_bytes:
                raise TooBig(f"over {max_bytes} bytes once unpacked")
            out.write(chunk)


def extract_member(archive: Path, archive_name: str, member: str, dest: Path, max_bytes: int) -> str:
    """Copy the regular file whose basename is `member` from a zip or tar to dest.

    Returns its path inside the archive. Members are read, never extracted
    under their own names, so a `../` or absolute name goes nowhere. When a
    basename repeats, the shortest path wins: the top-level program, not a
    copy under `contrib/`.
    """
    lower = archive_name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as z:
            hits = sorted((i for i in z.infolist() if not i.is_dir() and _basename(i.filename) == member),
                          key=lambda i: len(i.filename))
            if not hits:
                raise LookupError(f"{archive_name} has no {member}")
            if hits[0].file_size > max_bytes:
                raise TooBig(f"{hits[0].file_size} bytes, over --max-bytes {max_bytes}")
            with z.open(hits[0]) as src:
                copy_capped(src, dest, max_bytes)
            return hits[0].filename
    if lower.endswith(TAR_SUFFIXES):
        with tarfile.open(archive, "r:*") as t:
            hits = sorted((m for m in t.getmembers() if m.isreg() and _basename(m.name) == member),
                          key=lambda m: len(m.name))
            if not hits:
                raise LookupError(f"{archive_name} has no {member}")
            if hits[0].size > max_bytes:
                raise TooBig(f"{hits[0].size} bytes, over --max-bytes {max_bytes}")
            copy_capped(t.extractfile(hits[0]), dest, max_bytes)
            return hits[0].name
    raise LookupError(f"{archive_name}: not a zip or tar")


def parse_packages(text: str) -> list[dict[str, str]]:
    """A Debian `Packages` index as one dict per stanza, first lines only."""
    out = []
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t") or ": " not in line:
                continue
            key, value = line.split(": ", 1)
            fields[key] = value
        if fields:
            out.append(fields)
    return out


def archive_candidates(packages: list[dict[str, str]], max_bytes: int) -> list[dict[str, str]]:
    """amd64 packages from sections that ship programs, no larger than max_bytes."""
    return [p for p in packages
            if p.get("Architecture") == "amd64"
            and p.get("Section", "").rsplit("/", 1)[-1] in ARCHIVE_SECTIONS
            and p.get("Filename") and p.get("SHA256")
            and p.get("Size", "").isdigit() and int(p["Size"]) <= max_bytes]


def deb_data(deb: bytes) -> tuple[str, bytes]:
    """The `data.tar.*` member of a .deb. A .deb is an ar(1) archive: an
    8-byte magic, then a 60-byte header per member, bodies padded to even."""
    if not deb.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    off = 8
    while off + 60 <= len(deb):
        header = deb[off:off + 60]
        name = header[:16].decode("ascii", "replace").strip().rstrip("/")
        size = int(header[48:58].decode("ascii").strip())
        if name.startswith("data.tar"):
            return name, deb[off + 60:off + 60 + size]
        off += 60 + size + (size & 1)
    raise LookupError("no data.tar member")


def in_bin_dir(path: str) -> bool:
    path = path.removeprefix("./")
    return any(path.startswith(d) and "/" not in path[len(d):] for d in BIN_DIRS)


def deb_program(deb: bytes, package: str, rng: random.Random, dest: Path, max_bytes: int) -> str | None:
    """Copy one x86/x86-64 ELF program of a .deb to dest; return its path, or None.

    The program named after the package is preferred, because it is the one
    the package exists for. Otherwise one is drawn at random from the
    executables directly under /usr/bin, /usr/sbin, /bin and /sbin.
    """
    _, data = deb_data(deb)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
        programs = [m for m in t.getmembers()
                    if m.isreg() and m.mode & 0o111 and in_bin_dir(m.name) and m.size <= max_bytes]
        named = [m for m in programs if _basename(m.name) == package]
        rest = [m for m in programs if m not in named]
        rng.shuffle(rest)
        for m in named + rest:
            fh = t.extractfile(m)
            if bz.target_for(bz.sniff(fh.read(4096))) != "ubuntu":
                continue
            fh.seek(0)
            copy_capped(fh, dest, max_bytes)
            return m.name.removeprefix("./")
    return None


# --- the signature checkout, read without importing it ------------------------

SIG_FIELDS = ("name", "severity", "confidence", "weight", "categories")


def _set_at_run_time(cls: ast.ClassDef) -> set[str]:
    """The fields a signature class assigns to `self.<field>` in its methods.

    Such a field is a function of the data at run time, e.g. falco_linux's
    `self.severity = max(self.severity, priority)`, so its class literal
    is a floor, not the value a run reported.
    """
    out = set()
    for node in ast.walk(cls):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] \
            if isinstance(node, (ast.AugAssign, ast.AnnAssign)) else []
        for t in targets:
            if (isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                    and t.value.id == "self" and t.attr in SIG_FIELDS):
                out.add(t.attr)
    return out


def signature_index(root: Path) -> dict[str, list[dict]]:
    """Each signature name to the class-level literals of the classes that
    define it, the fields it sets at run time, and the line to edit
    (`severity =`, else the class). The files are parsed with `ast`, never
    imported."""
    index: dict[str, list[dict]] = {}
    if not root.is_dir():
        return index
    for path in sorted(root.rglob("*.py")):
        parts = path.relative_to(root).parts
        if "deprecated" in parts or "__pycache__" in parts:
            continue
        try:
            with warnings.catch_warnings():
                # The community's regexes carry invalid escapes; parsing is all this does.
                warnings.simplefilter("ignore", SyntaxWarning)
                tree = ast.parse(path.read_bytes(), filename=str(path))
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            found, lines = {}, {}
            for stmt in node.body:
                if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1
                        and isinstance(stmt.targets[0], ast.Name) and stmt.targets[0].id in SIG_FIELDS):
                    try:
                        found[stmt.targets[0].id] = ast.literal_eval(stmt.value)
                    except (ValueError, TypeError):
                        continue
                    lines[stmt.targets[0].id] = stmt.lineno
            if isinstance(found.get("name"), str):
                index.setdefault(found.pop("name"), []).append(
                    {**found, "path": path, "line": lines.get("severity", node.lineno),
                     "dir": parts[0] if len(parts) > 1 else "", "dynamic": sorted(_set_at_run_time(node))})
    return index


def lookup(index: dict[str, list[dict]], name: str, os_name: str) -> dict | None:
    """The definition a guest runs: its own directory's, else `all/`'s."""
    entries = index.get(name) or []
    for want in (SIGNATURE_DIR_OF.get(os_name), "all"):
        for e in entries:
            if e["dir"] == want:
                return e
    return entries[0] if entries else None


def where(entry: dict | None) -> str:
    if entry is None:
        return ""
    try:
        return f"{entry['path'].relative_to(REPO)}:{entry['line']}"
    except ValueError:
        return f"{entry['path']}:{entry['line']}"


# --- one report, trimmed -----------------------------------------------------

def summarize(results: dict) -> dict:
    """What `report` keeps of one cape_results.json: the signature hits and
    what CAPE's `calc_scoring` reads, so a score can be replayed offline."""
    target = results.get("target") or {}
    tfile = target.get("file") or {}
    behavior = results.get("behavior") or {}
    signers = ((tfile.get("pe") or {}).get("guest_signers") or {})
    sigs = []
    for s in results.get("signatures") or []:
        if not isinstance(s, dict) or not isinstance(s.get("name"), str):
            continue
        sig = {"name": s["name"], "severity": s.get("severity", 1), "confidence": s.get("confidence", 0),
               "weight": s.get("weight", 0), "categories": list(s.get("categories") or []),
               "marks": len(s.get("data") or [])}
        if s.get("maximum") is not None:
            sig["maximum"] = s["maximum"]
        sigs.append(sig)
    return {
        "malscore": results.get("malscore"),
        "malstatus": results.get("malstatus"),
        "duration": (results.get("info") or {}).get("duration"),
        "processes": len(behavior.get("processes") or []),
        "signatures": sigs,
        "scoring_input": {
            "target": {"category": target.get("category"),
                       "file": {"type": tfile.get("type"),
                                "pe": {"guest_signers": {"aux_valid": bool(signers.get("aux_valid"))}},
                                "yara": [y.get("name") for y in tfile.get("yara") or [] if isinstance(y, dict)]}},
            "detections": results.get("detections") or [],
            "behavior": {"processtree": [{}] if behavior.get("processtree") else []},
            "suricata": {"alerts": [{"signature": a.get("signature"), "severity": a.get("severity")}
                                    for a in (results.get("suricata") or {}).get("alerts") or []
                                    if isinstance(a, dict)]},
        },
    }


# --- scoring and aggregation ------------------------------------------------

def score(scoring, summary: dict, sigs: list[dict]) -> tuple[float, str | None]:
    """CAPE's calc_scoring over copies: it writes `weight` into what it is given."""
    inp = json.loads(json.dumps(summary["scoring_input"]))
    score_, status = scoring.calc_scoring(inp, [dict(s) for s in sigs])
    return round(float(score_), 2), status


def with_checkout(sigs: list[dict], index: dict, os_name: str) -> list[dict]:
    """The hits with this checkout's literals in place of the run's, except
    for a field the signature sets at run time: there the run's value stands."""
    out = []
    for s in sigs:
        meta = lookup(index, s["name"], os_name) or {}
        dynamic = set(meta.get("dynamic", ()))
        out.append({**s, **{k: meta[k] for k in ("severity", "confidence", "weight", "categories")
                            if k in meta and k not in dynamic}})
    return out


def bucket(scoring, sig: dict) -> str:
    """Which malscore list a signature's categories fall in: `malicious`,
    `suspicious`, or `-` when its severity cannot move the score. Asked of
    scoring.py itself, which keeps both lists as locals."""
    probe = {"target": {"category": "file", "file": {"type": "executable"}}, "behavior": {"processtree": [{}]}}
    s, status = scoring.calc_scoring(probe, [{**sig, "severity": 3, "confidence": 100, "weight": 1}])
    return "malicious" if status == "Malicious" else "suspicious" if s > 0 else "-"


def _rate(hits: int, n: int) -> float | None:
    return hits / n if n else None


def analyse(runs: list[dict], index: dict, scoring, os_name: str) -> dict:
    """Everything the report says about one guest."""
    mine = [r for r in runs if r["os"] == os_name]
    scored = [r for r in mine if r.get("report") and r["report"]["processes"] > 0]
    n = Counter(r["label"] for r in scored)
    replay_mismatch = 0
    per_sig: dict[str, dict] = {}
    flagged_benign = []
    for r in scored:
        rep = r["report"]
        now_sigs = with_checkout(rep["signatures"], index, os_name)
        r["score_now"], r["status_now"] = score(scoring, rep, now_sigs)
        replay = score(scoring, rep, rep["signatures"])
        if rep.get("malscore") is not None and abs(replay[0] - float(rep["malscore"])) > 0.05:
            replay_mismatch += 1
        for s, s_now in zip(rep["signatures"], now_sigs):
            row = per_sig.setdefault(s["name"], {
                "name": s["name"], "hits": Counter(), "severity_run": Counter(), "now": s_now,
                "bucket": bucket(scoring, s_now), "in_flagged_benign": 0})
            row["hits"][r["label"]] += 1
            row["severity_run"][s["severity"]] += 1
        if r["label"] == "benign" and r["status_now"] in FLAGGED:
            parts = []
            for i, s in enumerate(now_sigs):
                b = per_sig[s["name"]]["bucket"]
                if b == "-":
                    continue
                per_sig[s["name"]]["in_flagged_benign"] += 1
                without = score(scoring, rep, now_sigs[:i] + now_sigs[i + 1:])
                parts.append({"name": s["name"], "severity": s["severity"], "bucket": b,
                              "delta": round(r["score_now"] - without[0], 2)})
            parts.sort(key=lambda p: (-p["delta"], -p["severity"], p["name"]))
            flagged_benign.append({"run": r, "signatures": parts})

    rows = []
    for name, row in per_sig.items():
        ben, mal = row["hits"]["benign"], row["hits"]["malicious"]
        ben_rate, mal_rate = _rate(ben, n["benign"]), _rate(mal, n["malicious"])
        meta = lookup(index, name, os_name)
        hints = []
        if row["bucket"] == "-":
            hints.append("unscored")
        if ben_rate is not None and ben_rate >= NOISY_RATE and (mal_rate or 0) < 2 * ben_rate:
            hints.append("noisy")
        if row["in_flagged_benign"]:
            hints.append("fp-driver")
        if ben == 0 and n["benign"] and mal >= 2 and (mal_rate or 0) >= DISCRIMINATIVE_RATE:
            hints.append("discriminative")
        sev_run = row["severity_run"]
        rows.append({
            "os": os_name, "signature": name, "scored": row["bucket"],
            "severity_run": "/".join(str(k) for k, _ in sev_run.most_common()),
            "severity_now": row["now"]["severity"], "confidence_now": row["now"]["confidence"],
            "categories_now": ",".join(row["now"]["categories"]),
            "benign_hits": ben, "benign_runs": n["benign"],
            "malicious_hits": mal, "malicious_runs": n["malicious"],
            "benign_rate": ben_rate, "malicious_rate": mal_rate,
            "in_flagged_benign": row["in_flagged_benign"], "hint": " ".join(hints),
            "set_at_run_time": ",".join(meta.get("dynamic", ())) if meta else "",
            "defined_at": where(meta) if meta else "(not in this checkout)",
        })

    def side(label: str) -> dict:
        rs = [r for r in scored if r["label"] == label]
        run_scores = [float(r["report"]["malscore"]) for r in rs if r["report"].get("malscore") is not None]
        return {
            "runs": len([r for r in mine if r["label"] == label]),
            "scored": len(rs),
            "never_ran": len([r for r in mine if r["label"] == label and r.get("report")
                              and r["report"]["processes"] == 0]),
            "no_report": len([r for r in mine if r["label"] == label and r.get("state") in bz.TERMINAL_STATES
                              and not r.get("report")]),
            "pending": len([r for r in mine if r["label"] == label and r.get("state") not in bz.TERMINAL_STATES]),
            "flagged_run": sum(r["report"].get("malstatus") in FLAGGED for r in rs),
            "flagged_now": sum(r["status_now"] in FLAGGED for r in rs),
            "malicious_run": sum(r["report"].get("malstatus") == "Malicious" for r in rs),
            "malicious_now": sum(r["status_now"] == "Malicious" for r in rs),
            "median_run": statistics.median(run_scores) if run_scores else None,
            "median_now": statistics.median([r["score_now"] for r in rs]) if rs else None,
            "status_run": Counter(r["report"].get("malstatus") or "-" for r in rs),
            "status_now": Counter(r["status_now"] or "-" for r in rs),
        }

    return {"os": os_name, "sides": {label: side(label) for label in LABELS}, "signatures": rows,
            "flagged_benign": flagged_benign, "replay_mismatch": replay_mismatch, "scored": scored}


# --- rendering ---------------------------------------------------------------

def _frac(hits: int, n: int) -> str:
    return f"{hits}/{n} ({100 * hits / n:.0f}%)" if n else "—"


def _num(x: float | None) -> str:
    return "—" if x is None else f"{x:.1f}"


def _md(text: object) -> str:
    """Report text in a table cell: sample-derived names stay inert."""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("<", "&lt;")


def render(a: dict, top: int) -> str:
    os_name, ben, mal = a["os"], a["sides"]["benign"], a["sides"]["malicious"]
    out = [f"## {os_name}: {mal['scored']} malicious and {ben['scored']} benign runs scored", ""]
    left = []
    for label, s in (("malicious", mal), ("benign", ben)):
        for k, what in (("never_ran", "never started the sample"), ("no_report", "ended without a report"),
                        ("pending", "still running")):
            if s[k]:
                left.append(f"{s[k]} {label} {what}")
    if left:
        out += ["Not counted: " + ", ".join(left) + ".", ""]
    if a["replay_mismatch"]:
        out += [f"**{a['replay_mismatch']} run(s) replay to a malscore other than the one they "
                "reported**: the trimmed report misses something scoring reads, so the "
                "\"now\" column is approximate for them.", ""]
    out += ["| | malicious | benign |", "|---|---|---|",
            f"| Suspicious or Malicious, as run | {_frac(mal['flagged_run'], mal['scored'])} | {_frac(ben['flagged_run'], ben['scored'])} |",
            f"| Suspicious or Malicious, with this checkout | {_frac(mal['flagged_now'], mal['scored'])} | {_frac(ben['flagged_now'], ben['scored'])} |",
            f"| Malicious, as run | {_frac(mal['malicious_run'], mal['scored'])} | {_frac(ben['malicious_run'], ben['scored'])} |",
            f"| Malicious, with this checkout | {_frac(mal['malicious_now'], mal['scored'])} | {_frac(ben['malicious_now'], ben['scored'])} |",
            f"| median malscore, as run → now | {_num(mal['median_run'])} → {_num(mal['median_now'])} | {_num(ben['median_run'])} → {_num(ben['median_now'])} |",
            ""]
    statuses = sorted(set(mal["status_now"]) | set(ben["status_now"]) | set(mal["status_run"]) | set(ben["status_run"]))
    out += ["| status (as run → now) | " + " | ".join(statuses) + " |", "|---" * (len(statuses) + 1) + "|"]
    for label, s in (("malicious", mal), ("benign", ben)):
        out.append(f"| {label} | " + " | ".join(f"{s['status_run'][k]} → {s['status_now'][k]}" for k in statuses) + " |")
    out.append("")

    def table(rows: list[dict]) -> list[str]:
        lines = ["| signature | severity run → now | scored | benign | malicious | in flagged benign | hint | defined at |",
                 "|---|---|---|---|---|---|---|---|"]
        for r in rows:
            mark = "*" if "severity" in r["set_at_run_time"] else ""
            lines.append(f"| `{r['signature']}` | {r['severity_run']} → {r['severity_now']}{mark} | {r['scored']} | "
                         f"{_frac(r['benign_hits'], r['benign_runs'])} | {_frac(r['malicious_hits'], r['malicious_runs'])} | "
                         f"{r['in_flagged_benign'] or ''} | {r['hint']} | {r['defined_at']} |")
        return lines

    sigs = a["signatures"]
    on_benign = sorted((r for r in sigs if r["benign_hits"]),
                       key=lambda r: (-r["in_flagged_benign"], -(r["benign_rate"] or 0), r["malicious_rate"] or 0, r["signature"]))
    mal_only = sorted((r for r in sigs if not r["benign_hits"] and r["malicious_hits"]),
                      key=lambda r: (-(r["malicious_rate"] or 0), r["signature"]))
    out += [f"### Signatures that fire on benign runs ({len(on_benign)}; top {min(top, len(on_benign))})", ""]
    out += table(on_benign[:top]) + [""]
    out += [f"### Signatures only on malicious runs ({len(mal_only)}; top {min(top, len(mal_only))})", ""]
    out += table(mal_only[:top]) + [""]
    out += ["\\* sets its severity at run time (from what it matched): the replay keeps the run's value, "
            "so the class literal is a floor and editing it does not move these figures.", ""]
    if a["flagged_benign"]:
        out += [f"### Benign runs Suspicious or Malicious with this checkout ({len(a['flagged_benign'])})", "",
                "Scored signatures with their severity, and how far the score drops without each one "
                "alone where it does (the Suspicious clamp at 6.0 hides a drop when the rest still "
                "reaches it).", "",
                "| sample | job | as run → now | scored signatures (severity, drop) |", "|---|---|---|---|"]
        for f in a["flagged_benign"]:
            r = f["run"]
            sigs_text = ", ".join(f"`{p['name']}` ({p['severity']}" + (f", −{p['delta']:.1f})" if p["delta"] > 0 else ")")
                                  for p in f["signatures"])
            out.append(f"| {_md(r['name'])} | `{r['job_id'][:8]}` | {r['report'].get('malstatus')} "
                       f"{_num(r['report'].get('malscore'))} → {r['status_now']} {_num(r['score_now'])} | {sigs_text} |")
        out.append("")
    return "\n".join(out)


def write_csv(path: Path, rows: list[dict]) -> None:
    if not rows:
        path.write_text("")
        return
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            w.writerow({k: (f"{v:.3f}" if isinstance(v, float) else v) for k, v in r.items()})


# --- sources ------------------------------------------------------------------

@dataclass
class Prepared:
    sid: str           # the source's key in the state file
    entry: dict
    path: Path
    sniffed: object    # bazaar_submit.Sniff
    sha256: str
    dir: Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def download(client, url: str, dest: Path, max_bytes: int, digest: tuple[str, str] | None) -> None:
    """GET url into a new 0600 file, refusing past max_bytes or on a wrong (algo, hex) digest."""
    h = hashlib.new(digest[0] if digest else "sha256")
    with client.stream("GET", url) as r:
        if r.status_code != 200:
            raise LookupError(f"{url}: HTTP {r.status_code}")
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
        n = 0
        with os.fdopen(fd, "wb") as out:
            for chunk in r.iter_bytes():
                n += len(chunk)
                if n > max_bytes:
                    raise TooBig(f"{url}: over {max_bytes} bytes")
                h.update(chunk)
                out.write(chunk)
    if digest and h.hexdigest() != digest[1].lower():
        raise ValueError(f"{url}: {digest[0]} {h.hexdigest()}, the index says {digest[1]}")


def family_of(row: dict) -> str:
    return (row.get("signature") or "").strip()


def by_family(rows: list[dict], taken: Counter, rng: random.Random) -> list[dict]:
    """The rows reordered so families take turns: one of each before a second
    of any, the families with the fewest jobs so far first. Within a family
    the given order holds. Rows without a family are one family, the last."""
    groups: dict[str, list[dict]] = {}
    for row in rows:
        groups.setdefault(family_of(row), []).append(row)
    names = list(groups)
    rng.shuffle(names)
    names.sort(key=lambda n: (n == "", taken[n]))
    out = []
    for i in range(max(map(len, groups.values()), default=0)):
        out += [groups[n][i] for n in names if i < len(groups[n])]
    return out


def bazaar_info(mb, key: str, sha256: str) -> dict | None:
    """MalwareBazaar's record of one file, or None when it has none."""
    body = bz._mb_post(mb, key, {"query": "get_info", "hash": sha256}).json()
    status = body.get("query_status")
    if status == "ok":
        return (body.get("data") or [{}])[0]
    if status in ("hash_not_found", "no_results"):
        return None
    raise SystemExit(f"MalwareBazaar refused get_info: {status}")


def known_to_bazaar(mb, key: str, sha256: str) -> str | None:
    """MalwareBazaar's name for a file it has, or None. A benign sample it
    has is not benign enough to measure false positives with."""
    info = bazaar_info(mb, key, sha256)
    return None if info is None else info.get("signature") or "no signature"


def run_elsewhere(paths: list[Path]) -> dict[str, str]:
    """sha256 -> where, for every job in bazaar-submit.py's state files."""
    out = {}
    for path in paths:
        for sha, e in bz.load_state(path).items():
            if e.get("job_id") and e.get("state") != "failed":
                out[sha] = f"job {e['job_id']} in {path}"
    return out


class Feeder:
    """The candidate streams of one `submit` run, and the state they write."""

    def __init__(self, args, state: dict, save, rng: random.Random, workdir: Path):
        import httpx
        self.args, self.state, self.save, self.rng, self.workdir = args, state, save, rng, workdir
        self.http = httpx.Client(timeout=300, follow_redirects=True, headers=HTTP_HEADERS)
        #: MalwareBazaar client and key for the benign lookup; None skips it.
        self.mb, self.key = None, None
        self.exclude = re.compile(args.benign_exclude) if args.benign_exclude else None
        #: sha256 -> source of every sample with a job: the same file from two
        #: sources (or twice in MalwareBazaar's listing) is submitted once.
        self.submitted = {e["sha256"]: sid for sid, e in state.items() if e.get("job_id") and e.get("sha256")}
        self.submitted.update(run_elsewhere([Path(p).expanduser() for p in args.bazaar_state]))
        #: Set once logged in; None (a dry run) leaves the platform unasked.
        self.platform = None
        #: (guest, family) -> malicious jobs, for the turns and --per-family.
        self.taken = Counter((e["target_os"], e.get("name") or "") for e in state.values()
                             if e.get("job_id") and e["label"] == "malicious")
        #: get_info answers of this run, shared by both guests' streams.
        self.described: dict[str, dict | None] = {}
        self.lookups = 0
        self.download_cap = 2 * args.max_bytes   # an archive may be bigger than the program in it

    # -- bookkeeping

    def skip(self, sid: str, entry: dict, why: str) -> None:
        log(f"skip {entry.get('label')} {entry.get('target_os')} {entry.get('name') or sid}: {why}")
        entry["skipped"] = why
        self.state[sid] = entry
        self.save()

    def new_dir(self, sid: str) -> Path:
        stem = re.sub(r"[^A-Za-z0-9]", "-", sid.split(":", 1)[-1])[-24:]
        return Path(tempfile.mkdtemp(prefix=f"{stem}-", dir=self.workdir))

    def done_with(self, sample_dir: Path) -> None:
        if not self.args.keep:
            shutil.rmtree(sample_dir, ignore_errors=True)

    def on_platform(self, sha256: str) -> str | None:
        """The job the platform already has for this file, or None. It answers
        for the caller's jobs and the public ones; a failed job is not a run."""
        if self.platform is None:
            return None
        r = self.platform._call("GET", "/api/v1/jobs", params={"sha256": sha256, "limit": 50})
        if r.status_code != 200:
            raise SystemExit(f"the platform refused the sha256 lookup: {r.status_code} {r.text[:200]}")
        for job in r.json():
            if job.get("state") != "failed":
                return f"job {job['id']} on the platform ({job.get('state')})"
        return None

    def describe(self, mb, key: str, row: dict) -> dict | None:
        """A recent_detections row with MalwareBazaar's file type, size and tags
        added, or None when --lookups is spent or the file is gone."""
        sha = row["sha256_hash"]
        if sha not in self.described:
            if self.lookups >= self.args.lookups:
                return None
            self.lookups += 1
            self.described[sha] = bazaar_info(mb, key, sha)
        info = self.described[sha]
        return None if info is None else {**info, **{k: v for k, v in row.items() if v}}

    def excluded(self, name: str) -> bool:
        """--benign-exclude: a run option, so not recorded in the state file."""
        return bool(self.exclude and self.exclude.search(name))

    def cached_index(self, url: str, cache: Path, max_age: float | None) -> bytes:
        """An index file, downloaded once and again after max_age seconds (never when None)."""
        if not cache.exists() or (max_age is not None and time.time() - cache.stat().st_mtime > max_age):
            tmp = cache.with_suffix(".part")
            tmp.unlink(missing_ok=True)
            download(self.http, url, tmp, 256 << 20, None)
            tmp.replace(cache)
        return cache.read_bytes()

    def prepare(self, sid: str, entry: dict, path: Path, os_name: str, sample_dir: Path) -> Prepared | None:
        """The checks every sample passes whatever its source: size, header, guest,
        duplicate, and for a benign one, MalwareBazaar not knowing it."""
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        size = path.stat().st_size
        entry["size_bytes"] = size
        if size > self.args.max_bytes:
            self.skip(sid, entry, f"{size} bytes, over --max-bytes {self.args.max_bytes}")
            return None
        with open(path, "rb") as fh:
            s = bz.sniff(fh.read(4096))
        target = bz.target_for(s)
        if target != os_name:
            self.skip(sid, entry, "not x86/x86_64 or not runnable" if target is None
                      else f"a {target} program, wanted for {os_name}")
            return None
        sha = sha256_file(path)
        ran = self.submitted.get(sha) or self.on_platform(sha)
        if ran:
            self.skip(sid, entry, f"already run: {ran}")
            return None
        if entry["label"] == "benign" and self.mb is not None:
            known = known_to_bazaar(self.mb, self.key, sha)
            if known:
                self.skip(sid, entry, f"MalwareBazaar has it, as {known}")
                return None
        entry.update({"sha256": sha, "arch": s.arch})
        return Prepared(sid, entry, path, s, sha, sample_dir)

    # -- malicious: MalwareBazaar, through bazaar-submit.py

    def malicious(self, os_name: str, mb, key: str, rows: list[dict]) -> Iterator[Prepared]:
        cap = self.args.per_family
        taken = Counter({f: n for (o, f), n in self.taken.items() if o == os_name})
        for row in by_family(rows, taken, self.rng):
            sha = row["sha256_hash"]
            sid = f"mb:{sha}"
            family = family_of(row)
            if sid in self.state or sha in self.submitted:
                continue
            if cap and family and self.taken[(os_name, family)] >= cap:
                continue
            if "file_type" not in row:   # recent_detections: a hash and a family
                if sha not in self.described and self.lookups >= self.args.lookups:
                    log(f"malicious {os_name}: --lookups {self.args.lookups} spent")
                    return
                row = self.describe(mb, key, row)
                if row is None or GUEST_OF_FILE_TYPE.get(row.get("file_type")) != os_name:
                    continue
            entry = {"label": "malicious", "target_os": os_name, "source": "malwarebazaar",
                     "name": family, "file_type": row.get("file_type"),
                     "tags": row.get("tags"), "first_seen": row.get("first_seen"), "seen_at": now_iso()}
            if bz.too_big(row, self.args.max_bytes):
                self.skip(sid, entry, f"{row.get('file_size')} bytes, over --max-bytes {self.args.max_bytes}")
                continue
            ran = self.on_platform(sha)   # before the download, not after it
            if ran:
                self.skip(sid, entry, f"already run: {ran}")
                continue
            sample_dir = self.new_dir(sid)
            try:
                # A refusal from MalwareBazaar is a SystemExit there, and ends
                # the run here as it does there.
                zip_path = sample_dir / f"{sha}.zip"
                zip_path.write_bytes(bz.mb_download(mb, key, sha))
                os.chmod(zip_path, stat.S_IRUSR | stat.S_IWUSR)
                prep = self.prepare(sid, entry, bz.extract_sample(zip_path, sample_dir), os_name, sample_dir)
                if prep:
                    self.taken[(os_name, family)] += 1
                    yield prep
            finally:
                self.done_with(sample_dir)

    # -- benign, Windows: Scoop's main bucket

    def benign_scoop(self) -> Iterator[Prepared]:
        url = self.args.scoop_bucket
        cache = self.workdir / f"scoop-{hashlib.sha256(url.encode()).hexdigest()[:12]}.tar.gz"
        try:
            apps = scoop_apps(self.cached_index(url, cache, SCOOP_MAX_AGE))
        except Exception as exc:   # noqa: BLE001 - the cell reports itself out of candidates
            log(f"no Scoop bucket this run: {exc}")
            return
        log(f"benign windows: {len(apps)} single-download apps in the Scoop bucket")
        self.rng.shuffle(apps)
        for app in apps:
            sid = f"scoop:{app.name}@{app.version}"
            if sid in self.state or self.excluded(app.name):
                continue
            entry = {"label": "benign", "target_os": "windows", "source": "scoop",
                     "name": f"{app.name} {app.version} {app.program}", "url": app.url, "seen_at": now_iso()}
            sample_dir = self.new_dir(sid)
            try:
                try:
                    dl = sample_dir / "download"
                    if app.file_name.lower().endswith(".exe"):
                        download(self.http, app.url, dl, self.args.max_bytes, app.digest)
                        path = dl
                    else:
                        download(self.http, app.url, dl, self.download_cap, app.digest)
                        path = sample_dir / "sample"
                        entry["member"] = extract_member(dl, app.file_name, app.program, path, self.args.max_bytes)
                except TooBig as exc:
                    self.skip(sid, entry, str(exc))
                    continue
                except Exception as exc:   # noqa: BLE001 - a moved file, a wrong hash: logged, retried next run
                    log(f"pass over {entry['name']}: {exc}")
                    continue
                prep = self.prepare(sid, entry, path, "windows", sample_dir)
                if prep:
                    yield prep
            finally:
                self.done_with(sample_dir)

    # -- benign, Ubuntu: the archive of the guest's release

    def archive_index(self) -> list[dict[str, str]]:
        """Each component's Packages index, cached for good: a release pocket
        never changes after release day. An `-updates` dist does, so delete
        the cached files to pick up newer ones."""
        a = self.args
        out = []
        for component in a.ubuntu_components.split(","):
            url = f"{a.ubuntu_mirror}/dists/{a.ubuntu_dist}/{component}/binary-amd64/Packages.gz"
            raw = self.cached_index(url, self.workdir / f"ubuntu-{a.ubuntu_dist}-{component}-amd64-Packages.gz", None)
            for p in archive_candidates(parse_packages(gzip.decompress(raw).decode("utf-8", "replace")), a.max_bytes):
                out.append({**p, "component": component})
        return out

    def benign_archive(self) -> Iterator[Prepared]:
        a = self.args
        try:
            packages = self.archive_index()
        except Exception as exc:   # noqa: BLE001 - the cell reports itself out of candidates
            log(f"no Ubuntu archive this run: {exc}")
            return
        log(f"benign ubuntu: {len(packages)} packages in {a.ubuntu_dist} {a.ubuntu_components} to draw from")
        self.rng.shuffle(packages)
        for p in packages:
            sid = f"ubuntu:{p['Filename']}"
            if sid in self.state or self.excluded(p["Package"]):
                continue
            entry = {"label": "benign", "target_os": "ubuntu", "source": f"ubuntu:{a.ubuntu_dist}/{p['component']}",
                     "name": f"{p['Package']} {p.get('Version', '')}", "seen_at": now_iso()}
            sample_dir = self.new_dir(sid)
            try:
                try:
                    deb = sample_dir / "package.deb"
                    download(self.http, f"{a.ubuntu_mirror}/{p['Filename']}", deb, self.args.max_bytes,
                             ("sha256", p["SHA256"]))
                    path = sample_dir / "sample"
                    program = deb_program(deb.read_bytes(), p["Package"], self.rng, path, self.args.max_bytes)
                except Exception as exc:   # noqa: BLE001 - one package is not the run
                    log(f"pass over {p['Package']}: {exc}")
                    continue
                if program is None:
                    self.skip(sid, entry, "no x86/x86_64 program directly under /usr/bin, /usr/sbin, /bin or /sbin")
                    continue
                entry["name"] += f" /{program}"
                prep = self.prepare(sid, entry, path, "ubuntu", sample_dir)
                if prep:
                    yield prep
            finally:
                self.done_with(sample_dir)


# --- the platform ----------------------------------------------------------------

def connect(args):
    email = args.email or input("platform account email: ").strip()
    password = os.environ.get("SANDBOX_PASSWORD") or getpass.getpass("platform password: ")
    platform = bz.Platform(args.platform, args.cacert, email, password, None)
    log(f"logged in to {args.platform}")
    return platform


def fetch(platform, job_id: str) -> dict:
    """One job's state and, once it has ended with a report, the trimmed report."""
    d = platform.job(job_id)
    out = {"state": d.get("state"), "fetched_at": now_iso()}
    if d.get("failure_reason"):
        out["failure"] = f"{d.get('failure_stage')}: {d.get('failure_reason')}"
    if out["state"] not in bz.TERMINAL_STATES:
        return out
    if RESULTS_NAME not in (d.get("artifacts") or {}):
        out["report"] = None
        out["why"] = "expired" if d.get("artifacts_expired") else f"no {RESULTS_NAME}"
        return out
    r = platform._call("GET", f"/api/v1/jobs/{job_id}/artifact.zip", params={"name": RESULTS_NAME})
    if r.status_code != 200:
        raise LookupError(f"artifact.zip answered {r.status_code}: {r.text[:120]}")
    # The directory is not encrypted: the standard library reads the size,
    # and stream_unzip the AES member (zipfile reads ZipCrypto, not AES)
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        info = z.infolist()[0]   # the wrapper of one artifact holds that artifact
        if info.file_size > MAX_RESULTS_BYTES:
            out["report"], out["why"] = None, f"{RESULTS_NAME} over {MAX_RESULTS_BYTES} bytes"
            return out
    from stream_unzip import stream_unzip
    raw = b""
    for _name, _size, chunks in stream_unzip([r.content], password=ARTIFACT_PASSWORD):
        raw = b"".join(chunks)
        break
    out["report"] = summarize(json.loads(raw))
    return out


# --- the commands ------------------------------------------------------------------

@dataclass
class Cell:
    label: str
    os: str
    need: int
    stream: Iterator[Prepared]
    done: int = 0


class OutOfBalance(Exception):
    pass


def submit_one(platform, prep: Prepared, args, bounds, rng, state: dict, save, in_flight: dict,
               submitted: dict) -> bool:
    """Hand one sample to the platform as bazaar-submit.py does; True once admitted."""
    target = bz.target_for(prep.sniffed)
    seconds = bz.pick_seconds(bounds, rng)
    filename = bz.sample_filename(prep.sha256, prep.sniffed)
    entry = prep.entry
    entry.update({"target_os": target, "seconds": seconds})
    what = f"{entry['label']} {filename} ({entry.get('name')}, {prep.sniffed.arch}) to {target}, {seconds} s"
    if args.dry_run:
        log(f"would submit {what}")
        return True
    plugins = args.plugins.split(",") if args.plugins else bz.default_plugins(target)
    bal = platform.balance()
    if bal <= 0:
        raise OutOfBalance(f"balance is {bal} s: the platform refuses new jobs")
    log(f"submit {what}, {len(plugins)} plugins")
    detail = platform.submit(prep.path, filename, target, seconds, plugins, args.egress)
    job_id = detail["id"] if "id" in detail else detail.get("job_id")
    entry.update({"job_id": job_id, "state": detail.get("state"), "submitted_at": now_iso()})
    state[prep.sid] = entry
    submitted[prep.sha256] = prep.sid
    save()
    if entry["state"] in bz.TERMINAL_STATES:
        log(f"job {job_id} {entry['state']} at admission: {detail.get('failure_reason')}")
        bz.finish(platform, job_id, entry, args.private)
        save()
        return False
    log(f"job {job_id} {entry['state']}; {args.platform}/ui/jobs/{job_id}")
    in_flight[job_id] = entry
    return True


def cmd_submit(args) -> int:
    try:
        bounds = bz.parse_seconds(args.seconds)
    except ValueError as exc:
        raise SystemExit(str(exc))
    if args.max_bytes <= 0 or args.concurrent < 1 or args.malicious < 0 or args.benign < 0:
        raise SystemExit("--max-bytes and --concurrent must be positive, the counts not negative")
    rng = random.Random(args.seed)
    workdir = Path(args.workdir).expanduser()
    workdir.mkdir(parents=True, exist_ok=True)
    os.chmod(workdir, stat.S_IRWXU)
    state_path = Path(args.state) if args.state else workdir / "state.json"
    state = bz.load_state(state_path)

    def save() -> None:
        bz.save_state(state_path, state)

    oses = OSES if args.os == "both" else (args.os,)
    have = Counter((e["label"], e["target_os"]) for e in state.values() if e.get("job_id"))
    need = {(label, o): max(0, quota - have[(label, o)])
            for o in oses for label, quota in (("malicious", args.malicious), ("benign", args.benign))}
    for (label, o), k in need.items():
        log(f"{label} {o}: {have[(label, o)]} in {state_path}, {k} to submit")
    if not any(need.values()):
        return 0

    feeder = Feeder(args, state, save, rng, workdir)
    cells: list[Cell] = []
    want_malicious = any(k for (label, _), k in need.items() if label == "malicious")
    want_benign = any(k for (label, _), k in need.items() if label == "benign")
    if want_malicious or (want_benign and not args.no_mb_check):
        import httpx
        key = (os.environ.get("ABUSECH_AUTH_KEY") or getpass.getpass("abuse.ch Auth-Key: ")).strip()
        if not key:
            raise SystemExit("an abuse.ch Auth-Key is required (https://auth.abuse.ch/)"
                             + ("" if want_malicious else "; --no-mb-check submits benign samples unchecked"))
        mb = httpx.Client(timeout=300, follow_redirects=False)
        if want_benign:
            feeder.mb, feeder.key = mb, key
    elif want_benign:
        log("--no-mb-check: benign samples are not looked up in MalwareBazaar")
    if want_malicious:
        log(f"asking MalwareBazaar for {args.query}, up to {args.limit} per query")
        kind, _, hours = args.query.partition(":")
        if kind == "detections":
            # No file type in these rows: both guests get them all, and the
            # stream asks get_info which guest each one is for.
            rows = bz.mb_query(mb, key, query="recent_detections", hours=hours or "48")
            log(f"{len(rows)} detections of {len({family_of(r) for r in rows})} families")
        else:
            rows = bz.candidates(mb, key, args.query, args.limit)
        for o in oses:
            mine = rows if kind == "detections" else [r for r in rows if GUEST_OF_FILE_TYPE.get(r.get("file_type")) == o]
            log(f"malicious {o}: {len(mine)} candidates")
            if need[("malicious", o)]:
                cells.append(Cell("malicious", o, need[("malicious", o)], feeder.malicious(o, mb, key, mine)))
    benign_source = {"ubuntu": feeder.benign_archive, "windows": feeder.benign_scoop}
    for o in oses:
        if need[("benign", o)]:
            cells.append(Cell("benign", o, need[("benign", o)], benign_source[o]()))
    # Interleaved, so the lab's conditions over the run fall on both sides.
    order = sorted(cells, key=lambda c: (OSES.index(c.os), LABELS.index(c.label)))

    platform = feeder.platform = None if args.dry_run else connect(args)
    if platform:
        log(f"balance {platform.balance()} s")
    in_flight: dict[str, dict] = {}
    queue = deque(order)
    try:
        while queue:
            cell = queue.popleft()
            # Before the download, so no sample sits in the workdir waiting for a slot.
            bz.wait_for_room(platform, in_flight, args.concurrent, args.poll, args.private, save)
            prep = next(cell.stream, None)
            if prep is None:
                log(f"{cell.label} {cell.os}: out of candidates at {cell.done}/{cell.need}")
                continue
            try:
                cell.done += submit_one(platform, prep, args, bounds, rng, state, save, in_flight, feeder.submitted)
            finally:
                feeder.done_with(prep.dir)
            if cell.done < cell.need:
                queue.append(cell)
    except OutOfBalance as exc:
        log(f"{exc}; stopping")
    except (Exception, SystemExit) as exc:
        # As in bazaar-submit.py: a refusal ends the run, but the jobs already
        # running still get their results recorded and published.
        log(f"stopping: {exc}")
        bz.wait_for_room(platform, in_flight, 1, args.poll, args.private, save)
        raise
    finally:
        for c in order:
            c.stream.close()
    bz.wait_for_room(platform, in_flight, 1, args.poll, args.private, save)
    for c in order:
        log(f"{c.label} {c.os}: {c.done} submitted this run")
    log(f"state in {state_path}; next: {Path(sys.argv[0]).name} report --platform {args.platform}")
    return 0


def collect_runs(state: dict, bazaar_states: list[Path]) -> list[dict]:
    """Every job to report on, labelled: ours, then bazaar-submit.py's as malicious."""
    runs: dict[str, dict] = {}
    for sid, e in state.items():
        if e.get("job_id"):
            runs[e["job_id"]] = {"job_id": e["job_id"], "label": e["label"], "os": e["target_os"],
                                 "name": e.get("name") or sid, "sha256": e.get("sha256", ""),
                                 "source": e.get("source", ""), "state": e.get("state")}
    for path in bazaar_states:
        for sha, e in bz.load_state(path).items():
            if e.get("job_id") and e["job_id"] not in runs and e.get("target_os") in OSES:
                runs[e["job_id"]] = {"job_id": e["job_id"], "label": "malicious", "os": e["target_os"],
                                     "name": e.get("signature") or "", "sha256": sha,
                                     "source": "malwarebazaar (bazaar-submit)", "state": e.get("state")}
    return list(runs.values())


def cmd_report(args) -> int:
    workdir = Path(args.workdir).expanduser()
    state_path = Path(args.state) if args.state else workdir / "state.json"
    runs = collect_runs(bz.load_state(state_path), [Path(p).expanduser() for p in args.bazaar_state])
    oses = OSES if args.os == "both" else (args.os,)
    runs = [r for r in runs if r["os"] in oses]
    if not runs:
        raise SystemExit(f"no jobs in {state_path}" + (" or the --bazaar-state files" if args.bazaar_state else ""))
    cache = workdir / "reports"
    cache.mkdir(parents=True, exist_ok=True)
    os.chmod(cache, stat.S_IRWXU)

    platform, unfetched = None, 0
    for r in runs:
        cached = cache / f"{r['job_id']}.json"
        if cached.exists() and not args.refresh:
            r.update(json.loads(cached.read_text()))
            continue
        if not args.platform:
            unfetched += 1
            continue
        platform = platform or connect(args)
        try:
            got = fetch(platform, r["job_id"])
        except Exception as exc:   # noqa: BLE001 - one job's trouble is a line, not the report
            log(f"job {r['job_id']}: {exc}")
            continue
        r.update(got)
        if got["state"] in bz.TERMINAL_STATES:
            cached.write_text(json.dumps(got))
    if unfetched:
        log(f"{unfetched} job(s) not cached yet and no --platform to fetch them from: left out")

    index = signature_index(Path(args.signatures_dir))
    if not index:
        log(f"no signatures under {args.signatures_dir}: \"now\" equals \"as run\"")
    scoring = _load("cape_scoring", SCORING_PY)
    analyses = [analyse(runs, index, scoring, o) for o in oses]

    out = Path(args.out).expanduser() if args.out else workdir / "report"
    out.mkdir(parents=True, exist_ok=True)
    text = "\n".join([f"# Detection evaluation, {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", "",
                      f"Runs from `{state_path}`" + "".join(f", `{p}`" for p in args.bazaar_state)
                      + f"; signatures from `{args.signatures_dir}`. \"As run\" is the malscore each run "
                      "reported; \"now\" replays CAPE's `scoring.py` over the same hits with this "
                      "checkout's severity, confidence, weight and categories.", ""]
                     + [render(a, args.top) for a in analyses])
    (out / "report.md").write_text(text)
    write_csv(out / "signatures.csv", [row for a in analyses for row in a["signatures"]])
    write_csv(out / "runs.csv", [
        {"job_id": r["job_id"], "os": r["os"], "label": r["label"], "name": r["name"], "sha256": r["sha256"],
         "source": r["source"], "state": r.get("state"), "processes": (r.get("report") or {}).get("processes"),
         "malscore_run": (r.get("report") or {}).get("malscore"), "status_run": (r.get("report") or {}).get("malstatus"),
         "malscore_now": r.get("score_now"), "status_now": r.get("status_now"),
         "signatures": ";".join(s["name"] for s in (r.get("report") or {}).get("signatures", [])),
         "why": r.get("why") or r.get("failure") or ""}
        for r in runs])
    print(text)
    log(f"written {out / 'report.md'}, {out / 'signatures.csv'}, {out / 'runs.csv'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("\n\n", 1)[1])
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--cacert", help="CA file for a platform reached by its LAN address")
    common.add_argument("--email", help="platform account; asked for if absent (the password: $SANDBOX_PASSWORD or a prompt)")
    common.add_argument("--workdir", default=os.path.expanduser("~/.cache/detection-eval"),
                        help="samples, the state file and the report cache, 0700; never a shared directory")
    common.add_argument("--state", default=None, help="state file (default: <workdir>/state.json)")
    common.add_argument("--os", choices=["both", *OSES], default="both")
    sub = ap.add_subparsers(dest="command", required=True)

    s = sub.add_parser("submit", parents=[common], help="fetch labelled samples and submit them",
                       description="Fetch benign and malicious samples and run them with bazaar-submit.py's options.")
    s.add_argument("--platform", required=True, help="the platform's URL, e.g. https://sandbox.example.com")
    s.add_argument("--malicious", type=int, default=10, help="malicious jobs per guest the state file should hold (default 10)")
    s.add_argument("--benign", type=int, default=10, help="benign jobs per guest the state file should hold (default 10)")
    s.add_argument("--concurrent", type=int, default=2,
                   help="jobs in flight at once (default 2); the next sample waits for one to end")
    s.add_argument("--seconds", default="120-1200",
                   help=f"trace length per job: a number, or MIN-MAX drawn per sample, within "
                        f"{bz.SECONDS_MIN}-{bz.SECONDS_MAX} (default 120-1200)")
    s.add_argument("--query", default="types:exe,elf",
                   help="MalwareBazaar candidates: types:exe,elf (default), recent, tag:NAME, sig:NAME, "
                        "detections[:HOURS] (files given a family in the last HOURS, default 48, at most "
                        "168); exe rows go to windows, elf rows to ubuntu")
    s.add_argument("--per-family", type=int, default=3,
                   help="malicious jobs one MalwareBazaar family gets per guest, counting the state file's "
                        "(default 3; 0 for no cap). Samples without a family are not capped")
    s.add_argument("--lookups", type=int, default=500,
                   help="get_info lookups a detections query may spend finding exe and elf (default 500)")
    s.add_argument("--bazaar-state", action="append", metavar="PATH",
                   default=[p for p in [os.path.expanduser("~/.cache/bazaar-submit/state.json")] if os.path.exists(p)],
                   help="a bazaar-submit.py state file whose jobs are not submitted again; repeatable "
                        "(default: that script's own, when it exists)")
    s.add_argument("--limit", type=int, default=1000,
                   help="candidates per MalwareBazaar query, up to 1000 (default 1000: most ELF there is "
                        "ARM or MIPS, and the x86 ones are few)")
    s.add_argument("--max-bytes", type=int, default=bz.MAX_BYTES_DEFAULT,
                   help=f"skip samples larger than this (default {bz.MAX_BYTES_DEFAULT}, under the Cloudflare "
                        f"tunnel's 100 MB request-body cap)")
    s.add_argument("--egress", choices=["offline", "simulated", "tor"], default=None,
                   help="egress mode; absent means the platform's default, offline")
    s.add_argument("--plugins", help="comma-separated plugin names instead of the submit page's defaults")
    s.add_argument("--ubuntu-mirror", default="https://archive.ubuntu.com/ubuntu")
    s.add_argument("--ubuntu-dist", default="jammy", help="the guest's release (default jammy: the golden image is 22.04)")
    s.add_argument("--ubuntu-components", default="main,universe",
                   help="archive components to draw benign Ubuntu programs from (default main,universe)")
    s.add_argument("--scoop-bucket", default=SCOOP_BUCKET,
                   help="tarball of the Scoop bucket to draw benign Windows programs from (default: main, "
                        "command-line programs only)")
    s.add_argument("--benign-exclude", metavar="REGEX",
                   help="leave out benign packages or apps whose name matches, e.g. '^(nmap|socat|netcat)'")
    s.add_argument("--no-mb-check", action="store_true",
                   help="do not look benign samples up in MalwareBazaar (then no abuse.ch key is needed "
                        "for a benign-only run)")
    s.add_argument("--poll", type=int, default=20, help="seconds between job polls")
    s.add_argument("--private", action="store_true",
                   help="leave each analysis readable by this account only; by default it is published once it ends")
    s.add_argument("--keep", action="store_true", help="keep the samples and downloads after upload")
    s.add_argument("--dry-run", action="store_true", help="fetch and sniff, submit nothing")
    s.add_argument("--seed", type=int, default=None, help="for a reproducible choice of samples and --seconds")

    r = sub.add_parser("report", parents=[common], help="fetch the reports and rank the signatures",
                       description="Which signatures fire on benign and on malicious runs, and how the malscore separates them.")
    r.add_argument("--platform", help="the platform's URL; needed for runs not in the cache yet")
    r.add_argument("--bazaar-state", action="append", default=[], metavar="PATH",
                   help="a bazaar-submit.py state file whose jobs count as malicious; repeatable")
    r.add_argument("--signatures-dir", default=str(SIGNATURES_DIR),
                   help="the community checkout's modules/signatures, for the \"now\" severities and file:line")
    r.add_argument("--out", help="where report.md, signatures.csv and runs.csv go (default <workdir>/report)")
    r.add_argument("--top", type=int, default=30, help="rows per table in report.md (the CSV has all)")
    r.add_argument("--refresh", action="store_true", help="fetch every report again, cached or not")

    args = ap.parse_args(argv)
    return cmd_submit(args) if args.command == "submit" else cmd_report(args)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted; the state file has what was submitted", file=sys.stderr)
        sys.exit(130)
