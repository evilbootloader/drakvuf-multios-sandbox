#!/usr/bin/env python3
"""Feed the lab from MalwareBazaar: x86 and x86-64 samples, two analyses at a time.

Runs on a workstation that reaches both abuse.ch and the platform's web API. It
asks for the abuse.ch Auth-Key and the platform login, pulls candidate samples
from MalwareBazaar, keeps the ones whose headers say x86 or x86-64, hands each
to the platform the way the submit page does (create, upload to the object
store, mark uploaded), and keeps `--concurrent` jobs in flight: with that many
running, it touches the next sample only once one has reached a terminal state.

    scripts/bazaar-submit.py --platform https://sandbox.example.com --count 5 --seconds 120-1200

What goes where:

* **PE executables** (MalwareBazaar `file_type` `exe`, machine i386 or x86-64,
  not a DLL) go to the Windows guest; **ELF** (`file_type` `elf`, machine i386
  or x86-64, an executable or PIE) to the Ubuntu guest. Everything else --
  ARM and MIPS ELF, DLLs, scripts, documents -- is skipped and recorded.
* The trace length per job is `--seconds`: one number, or `MIN-MAX` for a
  value drawn per sample, within 120 and the platform's cap of 1200.
* Egress is the platform's default, offline, unless `--egress` says otherwise.
  Never `direct` from here: that is a per-host decision, not a submitter's.
* Each analysis is published once it has finished, whatever the outcome: every
  account on the platform can then read it, sample and extracted files
  included. The sample is public on MalwareBazaar already, and a run that
  bailed is a finding too. `--private` leaves it to the submitting account.
* Samples over `--max-bytes` are skipped before they are downloaded, from the
  `file_size` MalwareBazaar reports, and again after extraction from the real
  size. The default is just under 100 MB: the platform's own cap is 1 GiB, but
  the upload goes to a URL signed for the public hostname, so it crosses the
  Cloudflare tunnel, which caps a request body at 100 MB on the free plan and
  answers an HTML 413 rather than anything the platform could explain. A lab
  that uploads over the LAN can raise it as far as `MAX_SAMPLE_BYTES`.

Safety, because the files this handles are live malware:

* Samples are written only under `--workdir` (mode 0700, files 0600), never
  executed, never opened by anything but the header sniff, and deleted after
  the upload unless `--keep`. The zip from abuse.ch is AES-encrypted with the
  password `infected`; it is decrypted with `pyzipper` when importable, or
  with `7z` when installed, and refused otherwise -- `unzip` cannot.
* Nothing here runs on Dom0 or on the platform DomU. The platform never
  executes a sample either; the clone on Dom0 does.

The state file (`--state`) remembers every sha256 seen and the job it became,
so a second run never submits the same sample twice and `--count` counts new
submissions only.

Dependencies: `httpx` (both of the repository's virtualenvs have it) and, for
the zip, `pyzipper` or a `7z` binary. `platform/.venv/bin/pip install pyzipper`
is the one-line way; it is deliberately not in the platform's pinned
requirements, which install on the DomU, where this never runs.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import random
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

MB_API = "https://mb-api.abuse.ch/api/v1/"
MB_ZIP_PASSWORD = b"infected"
#: The platform's cap (`catalogue.MAX_TRACE_TIMEOUT`) and the floor this feeder
#: keeps: below two minutes a Windows sample has barely finished its loader.
SECONDS_MIN, SECONDS_MAX = 120, 1200
#: Cloudflare's 100 MB request-body cap on the free plan, less room for the
#: multipart envelope around the file (the presigned POST's policy fields).
#: Decimal, as Cloudflare states it; the platform's cap is 1 GiB.
MAX_BYTES_DEFAULT = 99 * 1000 * 1000
TERMINAL_STATES = frozenset({"completed", "rejected", "cancelled", "failed", "interrupted"})
API_HEADERS = {"X-Sandbox-Request": "1"}   # the CSRF marker the API wants on every call


# --- the pure parts, tested in sandboxd/tests/test_bazaar_submit.py --------

@dataclass(frozen=True)
class Sniff:
    kind: str      # "pe" or "elf"
    arch: str      # "x86" or "x86_64"
    runnable: bool  # PE: not a DLL; ELF: ET_EXEC or ET_DYN


def sniff(data: bytes) -> Sniff | None:
    """What the first bytes say the file is, or None for anything else.

    Reads the ELF and COFF headers only; nothing is mapped, parsed further or
    run. A truncated or malformed header is "anything else".
    """
    if data[:4] == b"\x7fELF" and len(data) >= 20:
        endian = "<" if data[5] == 1 else ">"
        e_type, e_machine = struct.unpack(endian + "HH", data[16:20])
        arch = {0x03: "x86", 0x3E: "x86_64"}.get(e_machine)
        if arch is None:
            return None
        return Sniff("elf", arch, e_type in (2, 3))
    if data[:2] == b"MZ" and len(data) >= 0x40:
        (off,) = struct.unpack("<I", data[0x3C:0x40])
        if off + 24 > len(data) or data[off:off + 4] != b"PE\0\0":
            return None
        machine, _, _, _, _, _, characteristics = struct.unpack("<HHIIIHH", data[off + 4:off + 24])
        arch = {0x14C: "x86", 0x8664: "x86_64"}.get(machine)
        if arch is None:
            return None
        return Sniff("pe", arch, not characteristics & 0x2000)
    return None


def target_for(s: Sniff | None) -> str | None:
    """The guest a sniffed file goes to, or None to skip it."""
    if s is None or not s.runnable:
        return None
    return {"pe": "windows", "elf": "ubuntu"}[s.kind]


def sample_filename(sha256: str, s: Sniff) -> str:
    """`<sha256>.exe` or `<sha256>.elf`: what the guest launches by name, so a
    PE must end in `.exe`; the submitted name the platform shows and stores."""
    return f"{sha256}.{'exe' if s.kind == 'pe' else 'elf'}"


def parse_seconds(spec: str) -> tuple[int, int]:
    """`N` or `MIN-MAX`, digits only, both within [SECONDS_MIN, SECONDS_MAX]."""
    if "-" in spec:
        lo, hi = spec.split("-", 1)
    else:
        lo = hi = spec
    if not (lo.isdigit() and hi.isdigit()):
        raise ValueError(f"seconds must be N or MIN-MAX, got {spec!r}")
    lo_i, hi_i = int(lo), int(hi)
    if not (SECONDS_MIN <= lo_i <= hi_i <= SECONDS_MAX):
        raise ValueError(f"seconds must lie within {SECONDS_MIN}-{SECONDS_MAX}, got {spec!r}")
    return lo_i, hi_i


def pick_seconds(bounds: tuple[int, int], rng: random.Random) -> int:
    lo, hi = bounds
    return lo if lo == hi else rng.randint(lo, hi)


def too_big(row: dict, max_bytes: int) -> bool:
    """True when the `file_size` MalwareBazaar reports for a row exceeds max_bytes.

    A row without a usable size is not refused here: the real size is checked
    after the download, before anything is uploaded.
    """
    size = row.get("file_size")
    if isinstance(size, str) and size.isdigit():
        size = int(size)
    return isinstance(size, int) and size > max_bytes


def session_lost(status: int, location: str | None) -> bool:
    """Whether a response says the platform no longer knows the session.

    An absent or expired access cookie is answered with a 303 to the login
    page (`auth.caller_identity`), the shape a browser needs, and by the auth
    routes with a 401. Any other redirect is something else and is left alone.
    """
    if status == 401:
        return True
    return status in (302, 303, 307) and urlsplit(location or "").path.rstrip("/") == "/ui/login"


def default_plugins(target_os: str) -> list[str]:
    """The submit page's pre-ticked set, from the platform's own catalogue.

    Imported from `platform/`, which only needs its enums; the script's
    location fixes the path, so the checkout can live anywhere.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "platform"))
    from sandbox_platform.catalogue import defaults_for  # noqa: E402
    from sandbox_platform.enums import TargetOs  # noqa: E402
    return sorted(defaults_for(TargetOs(target_os)) | {"hidsim"})


# --- MalwareBazaar -----------------------------------------------------------

MB_HEADERS = {"User-Agent": "bazaar-submit/1.0 (+https://github.com/evilbootloader/drakvuf-multios-sandbox)"}


def _mb_post(client, key: str, form: dict):
    """One POST to the API, with the body shown on anything but 200.

    abuse.ch answers a missing key with 401 and a refused one with 403, both
    with a short JSON body, and labels even its JSON `application/octet-stream`
    -- so errors are told apart by status and content, never by content type.
    """
    r = client.post(MB_API, data=form, headers={**MB_HEADERS, "Auth-Key": key})
    if r.status_code != 200:
        raise SystemExit(f"MalwareBazaar answered {r.status_code} to {form.get('query')}: "
                         f"{r.text[:200].strip() or '(no body)'}"
                         + (" -- the Auth-Key was refused; it is the key from https://auth.abuse.ch/, "
                            "pasted whole" if r.status_code in (401, 403) else ""))
    return r


def mb_query(client, key: str, **form) -> list[dict]:
    body = _mb_post(client, key, form).json()
    status = body.get("query_status")
    if status == "no_results":
        return []
    if status != "ok":
        raise SystemExit(f"MalwareBazaar refused {form.get('query')}: {status}")
    return body["data"]


def mb_download(client, key: str, sha256: str) -> bytes:
    r = _mb_post(client, key, {"query": "get_file", "sha256_hash": sha256})
    if not r.content.startswith(b"PK"):
        # Not a zip: a JSON refusal such as file_not_found, served as octet-stream.
        try:
            status = r.json().get("query_status")
        except ValueError:
            status = r.text[:100]
        raise SystemExit(f"MalwareBazaar has no file for {sha256}: {status}")
    return r.content


def candidates(client, key: str, query: str, limit: int) -> list[dict]:
    """Newest first. `types:exe,elf` (the default), `recent`, `tag:NAME`, `sig:NAME`."""
    kind, _, arg = query.partition(":")
    rows: list[dict] = []
    if kind == "types":
        for ft in (arg or "exe,elf").split(","):
            rows += mb_query(client, key, query="get_file_type", file_type=ft.strip(), limit=limit)
    elif kind == "recent":
        rows = mb_query(client, key, query="get_recent", selector="100")
    elif kind == "tag":
        rows = mb_query(client, key, query="get_taginfo", tag=arg, limit=limit)
    elif kind == "sig":
        rows = mb_query(client, key, query="get_siginfo", signature=arg, limit=limit)
    else:
        raise SystemExit(f"unknown --query {query!r}: types:..., recent, tag:..., sig:...")
    seen: set[str] = set()
    out = []
    for row in sorted(rows, key=lambda r: r.get("first_seen", ""), reverse=True):
        if row["sha256_hash"] not in seen:
            seen.add(row["sha256_hash"])
            out.append(row)
    return out


def extract_sample(zip_path: Path, out_dir: Path) -> Path:
    """The one member of abuse.ch's AES zip, written 0600 under out_dir."""
    try:
        import pyzipper  # type: ignore
    except ImportError:
        pyzipper = None
    if pyzipper is not None:
        with pyzipper.AESZipFile(zip_path) as z:
            z.setpassword(MB_ZIP_PASSWORD)
            names = [n for n in z.namelist() if not n.endswith("/")]
            if len(names) != 1:
                raise SystemExit(f"{zip_path.name}: expected one member, found {names}")
            target = out_dir / Path(names[0]).name
            with z.open(names[0]) as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
    else:
        exe = shutil.which("7z") or shutil.which("7zz") or shutil.which("7za")
        if exe is None:
            raise SystemExit("no way to open an AES zip: pip install pyzipper into this "
                             "interpreter's venv, or install 7z (p7zip-full)")
        subprocess.run([exe, "x", "-y", f"-p{MB_ZIP_PASSWORD.decode()}", f"-o{out_dir}",
                        str(zip_path)], check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        members = [p for p in out_dir.iterdir() if p.is_file() and p != zip_path]
        if len(members) != 1:
            raise SystemExit(f"{zip_path.name}: expected one member, found {[m.name for m in members]}")
        target = members[0]
    os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    return target


# --- the platform --------------------------------------------------------------

class Platform:
    """The web API as the submit page uses it, with the session cookies httpx keeps.

    The access cookie lasts an hour and a run lasts a day, so every call that
    comes back logged out is retried once after `_renew`: a refresh while the
    refresh cookie lives (a day, rotated on every use, so it slides for as long
    as the run keeps calling), a fresh login once it is gone.
    """

    def __init__(self, base: str, cacert: str | None, email: str, password: str, totp: str | None):
        import httpx
        self.c = httpx.Client(base_url=base.rstrip("/"), verify=cacert or True,
                              timeout=120, headers=API_HEADERS, follow_redirects=False)
        self.email, self.password, self.totp = email, password, totp
        self.login()

    def login(self) -> None:
        payload = {"email": self.email, "password": self.password}
        if self.totp:
            payload["totp"] = self.totp
        r = self.c.post("/api/v1/auth/login", json=payload)
        # The platform's 401 for a proved password without its second factor
        # says so; a wrong password gets a different one and no prompt.
        if r.status_code == 401 and "second-factor" in r.text and not self.totp:
            self.totp = input("second factor (TOTP or recovery code): ").strip()
            payload["totp"] = self.totp
            r = self.c.post("/api/v1/auth/login", json=payload)
        if r.status_code != 204:
            raise SystemExit(f"login refused: {r.status_code} {r.text[:200]}")

    def _renew(self) -> None:
        if self.c.post("/api/v1/auth/refresh").status_code == 204:
            log("access cookie renewed")
            return
        log("the session ended; logging in again")
        self.totp = None   # one-time codes: a kept one is spent, so ask again
        self.login()

    def _call(self, method: str, path: str, **kw):
        r = self.c.request(method, path, **kw)
        if session_lost(r.status_code, r.headers.get("location")):
            self._renew()
            r = self.c.request(method, path, **kw)
        return r

    def balance(self) -> int:
        r = self._call("POST", "/api/v1/account/balance")
        r.raise_for_status()
        return int(r.json())

    def submit(self, path: Path, filename: str, target_os: str, seconds: int,
               plugins: list[str], egress: str | None) -> dict:
        data = path.read_bytes()
        req = {"target_os": target_os, "filename": filename, "size_bytes": len(data),
               "plugins": plugins, "timeout": seconds}
        if egress:
            req["egress_mode"] = egress
        r = self._call("POST", "/api/v1/jobs", json=req)
        if r.status_code != 201:
            raise SystemExit(f"create refused: {r.status_code} {r.text[:300]}")
        created = r.json()
        # Straight to the object store, the policy fields first and the file
        # last, exactly as the browser's FormData does it.
        up = self.c.post(created["upload_url"], data=created["upload_fields"],
                         files={"file": (filename, data, "application/octet-stream")},
                         headers={})
        if up.status_code not in (200, 201, 204):
            raise SystemExit(f"upload refused by the object store: {up.status_code} {up.text[:300]}")
        r = self._call("POST", f"/api/v1/jobs/{created['job_id']}/uploaded")
        if r.status_code != 200:
            raise SystemExit(f"mark-uploaded refused: {r.status_code} {r.text[:300]}")
        return r.json()

    def job(self, job_id: str) -> dict:
        r = self._call("GET", f"/api/v1/jobs/{job_id}")
        r.raise_for_status()
        return r.json()

    def publish(self, job_id: str) -> str | None:
        """The job's visibility after asking for `public`, or None with the refusal
        logged. The platform publishes a job in any terminal state and nothing
        before, so this is called once the poll has seen one; publishing twice
        is not an error there. A refusal is not worth losing the run over: the
        job id is in the state file, and the UI has the same button."""
        r = self._call("POST", f"/api/v1/jobs/{job_id}/publish")
        if r.status_code != 200:
            log(f"job {job_id}: publish refused: {r.status_code} {r.text[:200]}")
            return None
        return r.json().get("visibility")


# --- the loop ----------------------------------------------------------------------

def log(msg: str) -> None:
    print(f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def load_state(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def save_state(path: Path, state: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    tmp.replace(path)


def finish(platform, job_id: str, entry: dict, private: bool) -> None:
    """Publish a job that has ended, unless the run is `--private`."""
    if private:
        return
    entry["visibility"] = platform.publish(job_id)
    if entry["visibility"]:
        log(f"job {job_id} {entry['visibility']}")


def wait_for_room(platform, in_flight: dict[str, dict], limit: int, poll: int,
                  private: bool, save) -> None:
    """Poll until fewer than `limit` jobs are in flight, finishing each that ends.

    `in_flight` maps a job id to its entry in the state file, so what is written
    here is what `save` persists. `limit=1` waits for all of them.
    """
    while len(in_flight) >= limit:
        time.sleep(poll)
        for job_id, entry in list(in_flight.items()):
            d = platform.job(job_id)
            last = d.get("state")
            if last != entry["state"]:
                entry["state"] = last
                log(f"job {job_id} {last}")
            if last in TERMINAL_STATES:
                if d.get("failure_reason"):
                    entry["failure"] = f"{d.get('failure_stage')}: {d.get('failure_reason')}"
                    log(f"job {job_id} {last}: {entry['failure']}")
                finish(platform, job_id, entry, private)
                del in_flight[job_id]
                save()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--platform", required=True, help="the platform's URL, e.g. https://sandbox.example.com")
    ap.add_argument("--cacert", help="CA file for a platform reached by its LAN address")
    ap.add_argument("--email", help="platform account; asked for if absent")
    ap.add_argument("--count", type=int, default=5, help="new submissions to make (default 5)")
    ap.add_argument("--concurrent", type=int, default=2,
                    help="jobs in flight at once (default 2); the next sample waits for one to end")
    ap.add_argument("--seconds", default="120-1200",
                    help=f"trace length per job: a number, or MIN-MAX for a random value drawn per sample, "
                         f"within {SECONDS_MIN}-{SECONDS_MAX}; the default draws between 120 and 1200")
    ap.add_argument("--query", default="types:exe,elf",
                    help="candidates: types:exe,elf (default), recent, tag:NAME, sig:NAME")
    ap.add_argument("--limit", type=int, default=100, help="candidates fetched per query, up to 1000")
    ap.add_argument("--max-bytes", type=int, default=MAX_BYTES_DEFAULT,
                    help=f"skip samples larger than this (default {MAX_BYTES_DEFAULT}, under the "
                         f"Cloudflare tunnel's 100 MB request-body cap; the platform itself allows 1 GiB)")
    ap.add_argument("--os", choices=["both", "windows", "ubuntu"], default="both")
    ap.add_argument("--egress", choices=["offline", "simulated", "tor"], default=None,
                    help="egress mode; absent means the platform's default, offline")
    ap.add_argument("--plugins", help="comma-separated plugin names instead of the submit page's defaults")
    ap.add_argument("--workdir", default=os.path.expanduser("~/.cache/bazaar-submit"),
                    help="where samples are written, 0700; never a shared directory")
    ap.add_argument("--state", default=None, help="state file (default: <workdir>/state.json)")
    ap.add_argument("--poll", type=int, default=20, help="seconds between job polls")
    ap.add_argument("--private", action="store_true",
                    help="leave each analysis readable by this account only; by default it is "
                         "published once it has finished, to every account on the platform")
    ap.add_argument("--keep", action="store_true", help="keep the extracted samples after upload")
    ap.add_argument("--dry-run", action="store_true", help="select and sniff, submit nothing")
    ap.add_argument("--seed", type=int, default=None, help="for a reproducible --seconds draw")
    args = ap.parse_args(argv)

    try:
        bounds = parse_seconds(args.seconds)
    except ValueError as exc:
        ap.error(str(exc))
    if args.max_bytes <= 0:
        ap.error("--max-bytes must be positive")
    if args.concurrent < 1:
        ap.error("--concurrent must be at least 1")
    rng = random.Random(args.seed)

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    os.chmod(workdir, stat.S_IRWXU)
    state_path = Path(args.state) if args.state else workdir / "state.json"
    state = load_state(state_path)

    key = (os.environ.get("ABUSECH_AUTH_KEY") or getpass.getpass("abuse.ch Auth-Key: ")).strip()
    if not key:
        ap.error("an abuse.ch Auth-Key is required (https://auth.abuse.ch/)")

    import httpx
    mb = httpx.Client(timeout=300, follow_redirects=False)

    platform = None
    if not args.dry_run:
        email = args.email or input("platform account email: ").strip()
        password = os.environ.get("SANDBOX_PASSWORD") or getpass.getpass("platform password: ")
        platform = Platform(args.platform, args.cacert, email, password, None)
        log(f"logged in to {args.platform}; balance {platform.balance()} s")

    log(f"asking MalwareBazaar for {args.query}, up to {args.limit} per query")
    rows = candidates(mb, key, args.query, args.limit)
    log(f"{len(rows)} candidates, {sum(1 for r in rows if r['sha256_hash'] in state)} seen before")

    def save() -> None:
        save_state(state_path, state)

    submitted = 0
    in_flight: dict[str, dict] = {}
    for row in rows:
        if submitted >= args.count:
            break
        sha = row["sha256_hash"]
        if sha in state:
            continue
        entry = {"first_seen": row.get("first_seen"), "file_type": row.get("file_type"),
                 "signature": row.get("signature"), "tags": row.get("tags"),
                 "size_bytes": row.get("file_size"),
                 "seen_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}

        def skip(why: str) -> None:
            log(f"skip {sha[:12]} ({row.get('file_type')}, {row.get('signature')}): {why}")
            entry["skipped"] = why
            state[sha] = entry
            save_state(state_path, state)

        # Before the download: the size abuse.ch reports is enough to refuse on.
        if too_big(row, args.max_bytes):
            skip(f"{row.get('file_size')} bytes, over --max-bytes {args.max_bytes}")
            continue
        # Before the download, so no live sample sits in the workdir waiting for a slot.
        wait_for_room(platform, in_flight, args.concurrent, args.poll, args.private, save)
        sample_dir = Path(tempfile.mkdtemp(prefix=sha[:12] + "-", dir=workdir))
        try:
            zip_path = sample_dir / f"{sha}.zip"
            zip_path.write_bytes(mb_download(mb, key, sha))
            os.chmod(zip_path, stat.S_IRUSR | stat.S_IWUSR)
            sample = extract_sample(zip_path, sample_dir)
            size = sample.stat().st_size
            entry["size_bytes"] = size
            if size > args.max_bytes:
                # The listing's size was missing or wrong; the real one decides.
                skip(f"{size} bytes, over --max-bytes {args.max_bytes}")
                continue
            with open(sample, "rb") as fh:
                head = fh.read(4096)
            s = sniff(head)
            target = target_for(s)
            if target is None or (args.os != "both" and target != args.os):
                skip("not x86/x86_64 or not runnable" if target is None else f"{target}, not wanted")
                continue
            seconds = pick_seconds(bounds, rng)
            filename = sample_filename(sha, s)
            entry.update({"target_os": target, "arch": s.arch, "seconds": seconds})
            if args.dry_run:
                log(f"would submit {filename} ({row.get('signature')}) to {target}, {seconds} s")
                submitted += 1
                continue
            plugins = (args.plugins.split(",") if args.plugins else default_plugins(target))
            bal = platform.balance()
            if bal <= 0:
                log(f"balance is {bal} s: the platform refuses new jobs; stopping")
                break
            if bal < seconds:
                log(f"balance {bal} s is below this job's {seconds} s; the platform still admits it and the balance goes negative")
            log(f"submit {filename} ({row.get('signature')}, {s.arch}) to {target}, {seconds} s, {len(plugins)} plugins")
            detail = platform.submit(sample, filename, target, seconds, plugins, args.egress)
            job_id = detail["id"] if "id" in detail else detail.get("job_id")
            entry.update({"job_id": job_id, "state": detail.get("state"),
                          "submitted_at": datetime.now(timezone.utc).isoformat(timespec="seconds")})
            state[sha] = entry
            save_state(state_path, state)
            last = entry["state"]
            if last in TERMINAL_STATES:
                log(f"job {job_id} {last} at admission: {detail.get('failure_reason')}")
                finish(platform, job_id, entry, args.private)
                save()
            else:
                submitted += 1
                log(f"job {job_id} {last}; {args.platform}/ui/jobs/{job_id}")
                in_flight[job_id] = entry
        except (Exception, SystemExit) as exc:
            # A refusal or a failed download ends the run, as it always did, but
            # a job already running still gets its result recorded and published.
            # Not KeyboardInterrupt: that one asks to leave now.
            log(f"stopping: {exc}")
            wait_for_room(platform, in_flight, 1, args.poll, args.private, save)
            raise
        finally:
            if not args.keep:
                shutil.rmtree(sample_dir, ignore_errors=True)
    wait_for_room(platform, in_flight, 1, args.poll, args.private, save)
    log(f"{submitted} submission(s) this run; state in {state_path}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted; the state file has what was submitted", file=sys.stderr)
        sys.exit(130)
