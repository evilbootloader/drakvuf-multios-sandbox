"""The worker channel: sandboxd's side of the platform API.

Issue #41 (DRAFT-060). `platform/fake_worker.py` walks this whole protocol and
is the reference; where this differs from it, the difference is deliberate and
says so.

**Dom0 never listens.** Every exchange here is outbound, which is the property
that lets the analysis host sit behind a firewall with no inbound rule at all.
Two consequences worth stating rather than rediscovering:

  * A cancellation cannot be pushed. The heartbeat RESPONSE is the only channel
    by which a running job learns it was cancelled.
  * A worker that stops heartbeating stops learning, which is correct -- its
    lease then lapses and the platform marks the record interrupted.

**Two clients, and the split is a credential boundary.** The worker channel
carries the bearer token and Dom0's client certificate. The object store gets a
separate client carrying NEITHER: a presigned URL is already authorised by the
signature in its query string, so sending the token spends a credential on a
request that does not need it, and the worker token has no business reaching
MinIO. It still verifies the CA, because the internal store is signed by ours.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .tls import ssl_context

# The API long-polls /claim (20s in production) so an idle worker is not a
# busy-loop. The client timeout must exceed that or every idle claim looks
# like a network failure.
CLAIM_TIMEOUT = 90.0
DEFAULT_TIMEOUT = 60.0

# A transient network fault must not end the daemon: Dom0 and the platform VM
# are separate machines and one of them restarting is ordinary. A 4xx is NOT
# retried -- it means this client and that server disagree about the protocol,
# and repeating the request cannot fix a disagreement.
RETRY_BACKOFF = (1.0, 2.0, 5.0, 10.0)


class ProtocolError(RuntimeError):
    """The server refused the request itself: 4xx.

    Distinct from a transport failure because the responses differ. This is a
    bug in one side or the other and repeating it is pointless; a transport
    failure is worth waiting out.
    """


@dataclass(frozen=True)
class Lease:
    job_id: str
    target_os: str
    submitted_filename: str
    required_mib: int
    attempt: int
    sample_url: str
    sha256: str | None
    lease_expires_at: str


@dataclass(frozen=True)
class Reserved:
    """**Not an error, and must never be logged as one.**

    A job too large for this worker's current free memory is holding its place
    at the head of the queue rather than being starved by smaller ones behind
    it. Logging it as a failure is how an operator comes to believe the queue
    is broken when it is working exactly as designed.
    """

    blocking_job_id: str
    need_mib: int


@dataclass(frozen=True)
class Idle:
    pass


@dataclass(frozen=True)
class Heartbeat:
    lease_expires_at: str
    cancel_requested: bool


@dataclass(frozen=True)
class Ticket:
    url: str
    fields: dict
    expires_in: int


class WorkerAPI:
    def __init__(
        self,
        base_url: str,
        token: str,
        worker_id: str,
        *,
        cacert: str | None = None,
        client_cert: tuple[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        store_transport: httpx.BaseTransport | None = None,
    ):
        self.worker_id = worker_id
        self._base = base_url.rstrip("/")

        # `transport` is for tests only. It is a separate parameter rather than
        # a mode flag so that production code cannot select it by accident: a
        # daemon with no transport argument builds a real TLS client.
        common: dict[str, Any] = {"timeout": DEFAULT_TIMEOUT}
        if transport is None:
            common["verify"] = ssl_context(cacert, client_cert)

        self._http = httpx.Client(
            base_url=self._base,
            headers={"Authorization": f"Bearer {token}",
                     "X-Worker-Id": worker_id},
            transport=transport,
            **common,
        )

        # Neither the token nor the certificate. See the module docstring.
        store_kw: dict[str, Any] = {"timeout": DEFAULT_TIMEOUT}
        if store_transport is None and transport is None:
            store_kw["verify"] = ssl_context(cacert)
        self._store = httpx.Client(
            transport=store_transport or transport, **store_kw
        )

    def close(self) -> None:
        self._http.close()
        self._store.close()

    def __enter__(self) -> WorkerAPI:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- request bodies, built as pure functions ---------------------------
    #
    # Separated so a test can check them against the SERVER's own pydantic
    # models without a running server. If RegisterRequest or ClaimRequest
    # changes shape, sandboxd's tests fail rather than the daemon failing at
    # 3am against a platform that was upgraded.

    def register_body(self, *, total_mib: int, total_vlans: int,
                      total_slots: int, pipelines: dict[str, int]) -> dict:
        return {
            "worker_id": self.worker_id,
            "total_mib": total_mib,
            "total_vlans": total_vlans,
            "total_slots": total_slots,
            # Derived on Dom0 from misc/<os>_sandbox.cfg plus this host's
            # overhead -- see resources.required_mib. Computing it on the
            # platform instead would recreate the two-files-free-to-disagree
            # failure platform.env exists to prevent.
            "pipelines": [{"os": os_, "required_mib": mib}
                          for os_, mib in sorted(pipelines.items())],
        }

    def claim_body(self, *, free_mib: int, free_vlans: int,
                   free_slots: int) -> dict:
        return {"worker_id": self.worker_id, "free_mib": free_mib,
                "free_vlans": free_vlans, "free_slots": free_slots}

    def reconcile_body(self, live_job_ids: list[str]) -> dict:
        return {"worker_id": self.worker_id, "live_job_ids": list(live_job_ids)}

    # -- calls --------------------------------------------------------------

    def register(self, *, total_mib: int, total_vlans: int, total_slots: int,
                 pipelines: dict[str, int]) -> None:
        """Announce what this host can afford. Upsert; safe on every restart."""
        self._post("/api/v1/worker/register", json=self.register_body(
            total_mib=total_mib, total_vlans=total_vlans,
            total_slots=total_slots, pipelines=pipelines))

    def reconcile(self, live_job_ids: list[str]) -> list[str]:
        """Tell the platform what is genuinely still running here.

        **Sent before the first claim, and after a sweep the list is empty.**
        That is what makes the lease TTL safe: the TTL expires bookkeeping,
        while reading Dom0's real state is what decides -- and sandboxd's real
        state after a sweep is that it holds nothing.

        Returns the ids the platform consequently marked interrupted, which is
        worth logging: it is the only record that work was lost.
        """
        r = self._post("/api/v1/worker/reconcile",
                       json=self.reconcile_body(live_job_ids))
        return [str(i) for i in r.json().get("interrupted", [])]

    def claim(self, *, free_mib: int, free_vlans: int,
              free_slots: int) -> Lease | Reserved | Idle:
        r = self._post(
            "/api/v1/worker/claim",
            json=self.claim_body(free_mib=free_mib, free_vlans=free_vlans,
                                 free_slots=free_slots),
            timeout=CLAIM_TIMEOUT,
        )
        body = r.json()
        status = body.get("status")
        if status == "leased":
            return Lease(
                job_id=str(body["job_id"]),
                target_os=body["target_os"],
                submitted_filename=body["submitted_filename"],
                required_mib=body["required_mib"],
                attempt=body["attempt"],
                sample_url=body["sample_url"],
                sha256=body.get("sha256"),
                lease_expires_at=body["lease_expires_at"],
            )
        if status == "reserved":
            return Reserved(blocking_job_id=str(body["blocking_job_id"]),
                            need_mib=body["need_mib"])
        if status == "idle":
            return Idle()
        raise ProtocolError(f"unknown claim status {status!r}")

    def report_state(self, job_id: str, state: str, **extra) -> None:
        """A worker sends what it LEARNED, not the whole row.

        Every field is optional server-side, so omitting one leaves the
        existing value alone -- which is why a later state report cannot erase
        an earlier diagnostic.
        """
        payload = {"state": state}
        payload.update({k: v for k, v in extra.items() if v is not None})
        self._post(f"/api/v1/worker/jobs/{job_id}/state", json=payload)

    def heartbeat(self, job_id: str) -> Heartbeat:
        """Extend the lease, and learn whether a cancellation is waiting.

        The response is the ONLY way a running job hears about cancellation.
        Dom0 has no inbound listener, so there is nowhere to push to.
        """
        body = self._post(f"/api/v1/worker/jobs/{job_id}/heartbeat").json()
        return Heartbeat(lease_expires_at=body["lease_expires_at"],
                         cancel_requested=bool(body["cancel_requested"]))

    def artifact_tickets(self, job_id: str,
                         sizes: dict[str, int]) -> dict[str, Ticket]:
        """Size-capped presigned POSTs, one per name.

        The size is declared because the API binds it into the upload policy
        (#37): the files exist on disk by now, so a ticket that could accept
        any number of bytes would be an unbounded write capability issued for
        no gain.
        """
        body = self._post(f"/api/v1/worker/jobs/{job_id}/artifacts",
                          json={"artifacts": sizes}).json()
        return {name: Ticket(url=t["url"], fields=t["fields"],
                             expires_in=t["expires_in"])
                for name, t in body.items()}

    def complete(self, job_id: str, manifest: dict) -> None:
        """Terminal. **This one call is what makes publication atomic** -- the
        artifacts are already in the store, but nothing serves them as finished
        until this row commits."""
        self._post(f"/api/v1/worker/jobs/{job_id}/complete",
                   json={"manifest": manifest})

    # -- the object store ---------------------------------------------------

    def fetch_sample(self, url: str, dest: Path,
                     *, timeout: float | None = None) -> int:
        """Download the sample to a Dom0 path, streaming.

        **It has to reach disk**, and that is worth saying plainly because
        `fake_worker` says the opposite: `injector -m writefile -B` takes a
        Dom0 *path* and there is no stdin form. So the honest arrangement is a
        known staging directory that the startup sweep empties, not a claim
        that malware never touches this host's filesystem.

        Streamed rather than held in memory: a sample is bounded by the API's
        upload cap, not by anything here, and this process also holds every
        clone's bookkeeping.
        """
        dest.parent.mkdir(parents=True, exist_ok=True)
        written = 0
        with self._store.stream("GET", url,
                                 timeout=timeout or DEFAULT_TIMEOUT) as r:
            r.raise_for_status()
            with open(dest, "wb") as fh:
                for chunk in r.iter_bytes():
                    fh.write(chunk)
                    written += len(chunk)
        return written

    def upload_artifact(self, ticket: Ticket, name: str, path: Path) -> None:
        """POST one artifact into the store with its signed policy.

        **Policy fields before the file part.** S3 stops reading at the file,
        so any field after it is not seen and the upload is rejected for a
        missing policy. httpx emits `data=` before `files=`, which is the
        ordering that matters -- the same constraint `submit.py` documents.
        """
        with open(path, "rb") as fh:
            r = self._store.post(ticket.url, data=ticket.fields,
                                 files={"file": (name, fh)})
        r.raise_for_status()

    # -- transport ----------------------------------------------------------

    def _post(self, path: str, *, json: dict | None = None,
              timeout: float | None = None) -> httpx.Response:
        """POST with backoff on transport failures, none on 4xx.

        The distinction is the point. A connection error means the platform VM
        is restarting or the link flapped, and waiting is the right response. A
        4xx means this client and that server disagree about the protocol, and
        repeating the request cannot resolve a disagreement -- it just turns a
        loud bug into a quiet loop.
        """
        last: Exception | None = None
        for attempt, delay in enumerate((0.0, *RETRY_BACKOFF)):
            if delay:
                time.sleep(delay)
            try:
                r = self._http.post(path, json=json, timeout=timeout
                                    or DEFAULT_TIMEOUT)
            except httpx.TransportError as exc:
                last = exc
                continue
            if 400 <= r.status_code < 500:
                raise ProtocolError(
                    f"{path} refused with {r.status_code}: {r.text[:400]}"
                )
            if r.status_code >= 500:
                # The platform is up but unhappy -- a restarting worker pool, a
                # database that has not finished coming back. Worth waiting out.
                last = ProtocolError(f"{path} returned {r.status_code}")
                continue
            return r
        raise ProtocolError(
            f"{path} failed after {len(RETRY_BACKOFF) + 1} attempts: {last}"
        ) from last