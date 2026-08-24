#!/usr/bin/env python3
"""Walk the submitter side of the protocol. Uploads one file, analyses nothing.

Issue #36 (DRAFT-043). The counterpart to `fake_worker.py`: that one is Dom0's
half of the protocol, this is the browser's. Together they close the loop with
neither a UI (#38) nor a Xen host, which is what makes a platform fault
diagnosable on its own.

It is **not** a test client for the web page. It is the reference for what the
page must do, in the order it must do it -- create, upload, admit -- and it is
what a failing page gets compared against.

    python submit.py --api https://192.168.1.10:8443 --target-os ubuntu \\
        --file ./hello.txt --cacert ca.crt \\
        --cert fake-worker.crt --key fake-worker.key --watch

Through the Cloudflare tunnel instead of the LAN, which is the path a browser
takes -- no internal CA and no client certificate, because both ends present
public certificates and the identity is the Access token:

    python submit.py --api https://sandbox.evilbootloader.com \\
        --target-os ubuntu --file ./hello.txt \\
        --access-token "$(cloudflared access token -app=https://sandbox.evilbootloader.com)"

**Never point this at a real sample.** It uploads whatever it is given to a
store that a worker will fetch and execute.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

import httpx

from client_tls import ssl_context

TERMINAL = {"completed", "failed", "rejected", "cancelled"}


class Submitter:
    def __init__(self, api: str, cacert: str | None = None,
                 client_cert: tuple[str, str] | None = None,
                 access_token: str | None = None):
        self.api = api.rstrip("/")
        # The Access token goes on the API client ONLY. It authenticates a
        # person to Cloudflare, and the object store is not behind Access --
        # sending it there would hand a session credential to a server that
        # has no use for it. Same reasoning as the certificate split below.
        headers = {"cf-access-token": access_token} if access_token else {}
        self.http = httpx.Client(base_url=self.api, timeout=60.0,
                                 headers=headers,
                                 verify=ssl_context(cacert, client_cert))
        # The object store is a separate client, exactly as in fake_worker.py:
        # the presigned POST carries its own authorisation in the policy, so
        # nothing else should travel with it. Here it also matters that no
        # client certificate is presented -- a browser has none, and this
        # script is the reference for what a browser does.
        self.s3 = httpx.Client(timeout=300.0, verify=ssl_context(cacert))

    def create(self, target_os: str, filename: str, size: int) -> dict:
        """Reserve a job row and get an upload capability for it.

        `size_bytes` is a declaration, not a measurement, and the server treats
        it as one: it signs the policy with min(declared, server cap), so
        under-declaring shrinks your own allowance rather than raising it.
        """
        r = self.http.post("/api/v1/jobs", json={
            "target_os": target_os, "filename": filename, "size_bytes": size,
        })
        r.raise_for_status()
        return r.json()

    def upload(self, created: dict, path: pathlib.Path) -> None:
        """POST the file to the object store under the signed policy.

        The policy fields must precede the file part -- S3 stops reading at
        the file, so anything after it is not seen. httpx emits `data=` before
        `files=`, which is the order that matters here.
        """
        r = self.s3.post(
            created["upload_url"],
            data=created["upload_fields"],
            files={"file": (path.name, path.read_bytes())},
        )
        if r.status_code not in (200, 201, 204):
            raise SystemExit(f"upload rejected: {r.status_code}\n{r.text[:800]}")

    def admit(self, job_id: str) -> dict:
        """Tell the API the object is there, which is where admission happens.

        Everything that decides whether this job is analysable runs now, on the
        server, against the stored object rather than against anything the
        client said: real size, SHA-256, libmagic type, and the ETag that later
        proves the bytes did not change between admission and execution.
        """
        r = self.http.post(f"/api/v1/jobs/{job_id}/uploaded")
        r.raise_for_status()
        return r.json()

    def get(self, job_id: str) -> dict:
        r = self.http.get(f"/api/v1/jobs/{job_id}")
        r.raise_for_status()
        return r.json()

    def watch(self, job_id: str, timeout: float) -> dict:
        """Follow the job over SSE until it reaches a terminal state.

        Reads the same stream the web page will. Keepalive frames arrive as
        SSE comments (`: keepalive`) and are skipped -- they exist so that a
        proxy does not close a quiet connection, which would look exactly like
        a stalled analysis.
        """
        deadline = time.monotonic() + timeout
        with self.http.stream("GET", f"/api/v1/jobs/{job_id}/events") as r:
            r.raise_for_status()
            for line in r.iter_lines():
                if time.monotonic() > deadline:
                    raise SystemExit(f"timed out after {timeout}s")
                if not line.startswith("data: "):
                    continue
                event = json.loads(line[6:])
                print(f"  -> {event['state']}")
                if event["state"] in TERMINAL:
                    return self.get(job_id)
        raise SystemExit("event stream closed before a terminal state")

    def poll(self, job_id: str, timeout: float) -> dict:
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            job = self.get(job_id)
            if job["state"] != last:
                print(f"  -> {job['state']}")
                last = job["state"]
            if job["state"] in TERMINAL:
                return job
            time.sleep(1.0)
        raise SystemExit(f"timed out after {timeout}s in state {last}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--file", required=True, type=pathlib.Path)
    ap.add_argument("--target-os", required=True,
                    choices=["ubuntu", "android", "windows"])
    ap.add_argument("--cacert",
                    help="CA bundle that signed the API and MinIO certificates")
    ap.add_argument("--cert", help="client certificate, if the API requires one")
    ap.add_argument("--key", help="private key for --cert")
    ap.add_argument("--watch", action="store_true",
                    help="follow the job over SSE instead of polling")
    ap.add_argument("--wait", type=float, default=0.0, metavar="SECONDS",
                    help="wait for a terminal state; 0 exits after admission")
    ap.add_argument("--declare-size", type=int, metavar="BYTES",
                    help="declare a size other than the file's own, to check "
                         "that the server measures rather than believes")
    ap.add_argument("--access-token", metavar="JWT",
                    help="Cloudflare Access token for the tunnel path. Get one "
                         "with: cloudflared access token -app=<api url>")
    args = ap.parse_args()

    if bool(args.cert) != bool(args.key):
        ap.error("--cert and --key go together")
    if not args.file.is_file():
        ap.error(f"{args.file} is not a file")

    s = Submitter(args.api, args.cacert,
                  (args.cert, args.key) if args.cert else None,
                  access_token=args.access_token)

    real = args.file.stat().st_size
    created = s.create(args.target_os, args.file.name,
                       args.declare_size or real)
    job_id = created["job_id"]
    print(f"created {job_id} for {args.file.name} ({real} bytes)")

    s.upload(created, args.file)
    print(f"uploaded to {created['upload_url']}")

    job = s.admit(job_id)
    print(f"admitted: state={job['state']} sha256={job['sha256']} "
          f"type={job['detected_type']!r}")
    if job["state"] == "rejected":
        print(f"rejected: {job['failure_reason']}")
        return 1

    if args.wait:
        job = s.watch(job_id, args.wait) if args.watch \
            else s.poll(job_id, args.wait)

    print(json.dumps(job, indent=2))
    return 0 if job["state"] in ("queued", "completed") else 1


if __name__ == "__main__":
    sys.exit(main())