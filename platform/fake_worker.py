#!/usr/bin/env python3
"""A worker that speaks the protocol and analyses nothing.

Issue #36 (DRAFT-043). **A deliverable, not test scaffolding.**

It exists to prove the worker channel closes before `sandboxd` exists, and it
stays useful afterwards as the thing that tells a platform bug apart from a
Dom0 bug: if this drives a job to `completed` and `sandboxd` does not, the
fault is on Dom0.

It is deliberately NOT a simulator. It makes no clone, allocates no VLAN and
runs nothing -- it walks the state machine and uploads placeholder artifacts.
Anything here that started modelling Xen would be a second implementation of
the thing it is meant to check.

    python fake_worker.py --api http://127.0.0.1:8000 --token dev --once

Against a deployed API, which requires a client certificate at the TLS layer
(`--ssl-cert-reqs 2`), it needs an identity of its own -- not Dom0's:

    python fake_worker.py --api https://192.168.1.10:8443 \
        --cacert ca.crt --cert fake-worker.crt --key fake-worker.key \
        --token "$WORKER_TOKEN" --once
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time

import httpx

from client_tls import ssl_context

STAGES = ["preparing", "executing", "collecting", "cleaning"]
ARTIFACTS = {
    "trace.log": b"fake worker: no analysis was performed\n",
    # Zero bytes on purpose, and a real case rather than a lazy placeholder: a
    # sample that made no network traffic produces an empty pcap, which is why
    # #37's upload policy starts its content-length-range at 0.
    "capture.pcap": b"",
}


def manifest() -> dict:
    """The DRAFT-018 shape.

    `sandboxd` will build this the same way -- from what it actually uploaded,
    with the digest it computed on the way out. Keeping this honest is part of
    what the fake worker is for: a placeholder manifest that did not satisfy
    the real contract would prove the channel closes while leaving the one
    payload with a schema untested end to end.
    """
    return {
        "schema_version": 1,
        "artifacts": [
            {"name": name,
             "size_bytes": len(body),
             "sha256": hashlib.sha256(body).hexdigest()}
            for name, body in ARTIFACTS.items()
        ],
        "notes": "fake worker: no analysis was performed",
    }


class FakeWorker:
    def __init__(self, api: str, token: str, worker_id: str, free_mib: int,
                 cacert: str | None = None,
                 client_cert: tuple[str, str] | None = None):
        self.api = api.rstrip("/")
        self.worker_id = worker_id
        self.free_mib = free_mib
        self.http = httpx.Client(
            base_url=self.api,
            headers={"Authorization": f"Bearer {token}",
                     "X-Worker-Id": worker_id},
            timeout=60.0,
            verify=ssl_context(cacert, client_cert),
        )
        # The object store gets a SEPARATE client, carrying neither the bearer
        # token nor the client certificate. A presigned URL is already
        # authorised by the signature in its query string, so sending either
        # one spends a credential on a request that does not need it -- and
        # the worker token in particular has no business reaching MinIO.
        # It still verifies, because the internal store is signed by our CA.
        self.s3 = httpx.Client(timeout=60.0, verify=ssl_context(cacert))

    def _post(self, path: str, **kw) -> httpx.Response:
        r = self.http.post(path, **kw)
        r.raise_for_status()
        return r

    def register(self, pipelines: dict[str, int]) -> None:
        self._post("/api/v1/worker/register", json={
            "worker_id": self.worker_id,
            "total_mib": self.free_mib,
            "total_vlans": 8,
            "total_slots": 2,
            "pipelines": [{"os": k, "required_mib": v}
                          for k, v in pipelines.items()],
        })

    def reconcile(self) -> None:
        # Empty list: this process holds nothing, so anything the platform
        # thinks it owns died with a previous run. Sent BEFORE the first claim,
        # which is what makes the lease TTL safe.
        self._post("/api/v1/worker/reconcile", json={
            "worker_id": self.worker_id, "live_job_ids": [],
        })

    def claim(self) -> dict | None:
        body = self._post("/api/v1/worker/claim", json={
            "worker_id": self.worker_id, "free_mib": self.free_mib,
            "free_vlans": 6, "free_slots": 2,
        }).json()

        if body["status"] == "leased":
            return body
        if body["status"] == "reserved":
            # NOT an error, and must never be logged as one. A job too large
            # for current capacity is holding its place rather than being
            # starved by smaller ones behind it.
            print(f"reserved: job {body['blocking_job_id']} needs "
                  f"{body['need_mib']} MiB, this worker offers {self.free_mib}")
        return None

    def run_job(self, lease: dict) -> None:
        job_id = lease["job_id"]
        print(f"leased {job_id} ({lease['target_os']}) "
              f"{lease['submitted_filename']!r} attempt {lease['attempt']}")

        # Fetch the sample the way sandboxd will: a presigned GET, no
        # credential of any kind. Discarded immediately -- this worker has no
        # business keeping malware on disk any more than the platform does.
        sample = self.s3.get(lease["sample_url"])
        sample.raise_for_status()
        print(f"  fetched {len(sample.content)} bytes")

        for stage in STAGES:
            if self._heartbeat(job_id):
                print("  cancel requested; tearing down")
                self._state(job_id, "cleaning", cleanup_status="cancelled")
                # No artifacts, and the cancellation is NOT recorded in the
                # manifest: `cleanup_status` above already carries it, and the
                # manifest describes what a run produced. Two places saying
                # "cancelled" is two places free to disagree.
                self._post(f"/api/v1/worker/jobs/{job_id}/complete",
                           json={"manifest": {"schema_version": 1,
                                              "notes": "cancelled before upload"}})
                return
            self._state(job_id, stage)
            print(f"  -> {stage}")

        # Declare each size, because the API binds it into the upload policy
        # (issue #37). The files already exist by now -- that is the whole
        # reason artifacts can be size-capped where the draft assumed not.
        tickets = self._post(
            f"/api/v1/worker/jobs/{job_id}/artifacts",
            json={"artifacts": {n: len(b) for n, b in ARTIFACTS.items()}},
        ).json()
        for name, ticket in tickets.items():
            # Policy fields BEFORE the file part: S3 stops reading at the file,
            # so anything after it is not seen. httpx emits `data=` before
            # `files=`, which is the ordering that matters. Same as submit.py.
            self.s3.post(
                ticket["url"],
                data=ticket["fields"],
                files={"file": (name, ARTIFACTS[name])},
            ).raise_for_status()
        print(f"  uploaded {len(tickets)} artifacts")

        # Terminal, and the reason publication is atomic: the artifacts are
        # already in the store, but nothing serves them as finished until this
        # row commits.
        self._post(f"/api/v1/worker/jobs/{job_id}/complete",
                   json={"manifest": manifest()})
        print("  -> completed")

    def _state(self, job_id: str, state: str, **extra) -> None:
        self._post(f"/api/v1/worker/jobs/{job_id}/state",
                   json={"state": state, **extra})

    def _heartbeat(self, job_id: str) -> bool:
        """Extend the lease; return whether a cancellation is waiting.

        The response is the only channel by which a running job learns it was
        cancelled, because Dom0 has no inbound listener.
        """
        return self._post(f"/api/v1/worker/jobs/{job_id}/heartbeat").json()[
            "cancel_requested"
        ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--token", required=True)
    ap.add_argument("--worker-id", default="fake-worker")
    ap.add_argument("--free-mib", type=int, default=12082)
    ap.add_argument("--once", action="store_true",
                    help="take one job and exit, instead of looping")
    ap.add_argument("--cacert",
                    help="CA bundle that signed the API and MinIO certificates")
    ap.add_argument("--cert",
                    help="client certificate presented to the API; the "
                         "deployed listener requires one")
    ap.add_argument("--key", help="private key for --cert")
    args = ap.parse_args()

    if bool(args.cert) != bool(args.key):
        ap.error("--cert and --key go together")

    w = FakeWorker(
        args.api, args.token, args.worker_id, args.free_mib,
        cacert=args.cacert,
        client_cert=(args.cert, args.key) if args.cert else None,
    )
    w.register({"ubuntu": 2198, "android": 2198, "windows": 6294})
    w.reconcile()
    print(f"registered as {args.worker_id}, offering {args.free_mib} MiB")

    while True:
        lease = w.claim()
        if lease:
            w.run_job(lease)
            if args.once:
                return 0
        elif args.once:
            print("nothing to do")
            return 0
        else:
            time.sleep(1.0)


if __name__ == "__main__":
    sys.exit(main())
