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
"""

from __future__ import annotations

import argparse
import sys
import time

import httpx

STAGES = ["preparing", "executing", "collecting", "cleaning"]
ARTIFACTS = {
    "trace.log": b"fake worker: no analysis was performed\n",
    "capture.pcap": b"",
    "manifest.json": b'{"note": "fake worker"}',
}


class FakeWorker:
    def __init__(self, api: str, token: str, worker_id: str, free_mib: int):
        self.api = api.rstrip("/")
        self.worker_id = worker_id
        self.free_mib = free_mib
        self.http = httpx.Client(
            base_url=self.api,
            headers={"Authorization": f"Bearer {token}",
                     "X-Worker-Id": worker_id},
            timeout=60.0,
        )

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
        sample = httpx.get(lease["sample_url"], timeout=60.0)
        sample.raise_for_status()
        print(f"  fetched {len(sample.content)} bytes")

        for stage in STAGES:
            if self._heartbeat(job_id):
                print("  cancel requested; tearing down")
                self._state(job_id, "cleaning", cleanup_status="cancelled")
                self._post(f"/api/v1/worker/jobs/{job_id}/complete",
                           json={"manifest": {"cancelled": True}})
                return
            self._state(job_id, stage)
            print(f"  -> {stage}")

        urls = self._post(f"/api/v1/worker/jobs/{job_id}/artifacts",
                          json={"names": list(ARTIFACTS)}).json()
        for name, url in urls.items():
            httpx.put(url, content=ARTIFACTS[name], timeout=60.0).raise_for_status()
        print(f"  uploaded {len(urls)} artifacts")

        # Terminal, and the reason publication is atomic: the artifacts are
        # already in the store, but nothing serves them as finished until this
        # row commits.
        self._post(f"/api/v1/worker/jobs/{job_id}/complete",
                   json={"manifest": {"artifacts": list(ARTIFACTS)}})
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
    args = ap.parse_args()

    w = FakeWorker(args.api, args.token, args.worker_id, args.free_mib)
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
