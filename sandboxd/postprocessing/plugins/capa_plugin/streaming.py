"""capa's DRAKVUF extractor, reading calls from disk instead of holding them.

capa's own `DrakvufExtractor.from_report` turns every call of the sample's
processes into a pydantic model before matching starts -- 1.7 KiB per record,
measured 2026-09-18 -- and keeps all of them for the whole pass. On a
20-minute trace that list was most of the 6.7 GiB the daemon held when the
kernel killed it (TROUBLESHOOTING, "`sandboxd` disappears after a long
trace"). The operator's rule is that every line is still parsed, so the fix
is not to read less but to keep less: this extractor holds an INDEX -- for
every thread, the byte offsets of its calls in each log, 8 bytes per call --
and builds a call's model only while capa extracts that call's features. The
model is garbage the moment capa moves to the next call.

Feature extraction itself is capa's, unchanged: the per-scope functions in
`capa.features.extractors.drakvuf.{call,process,file,global_}` are called
with the same handles capa's extractor would give them, so a rule matches
here exactly when it matches under `DrakvufExtractor` --
`test_postprocess_child.py` checks the two against each other.

What this cannot shrink is capa's own matching state
(`capa/capabilities/dynamic.py`): under every feature it keeps the address of
every call that had it, per thread and again per process. That is
proportional to the calls of the busiest process, not to the trace, and it is
capa's to change. The process-level filter (`ProcessFilter`, applied by the
caller) still bounds it to the sample's own processes.

Two passes over the logs, and both parse every line: the index pass to learn
which thread each call belongs to, the extraction pass to build each call
when capa asks for it.
"""

from __future__ import annotations

import heapq
import logging
from array import array
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Sequence, Set, Tuple, Union

import capa.features.extractors.drakvuf.call
import capa.features.extractors.drakvuf.file
import capa.features.extractors.drakvuf.global_
import capa.features.extractors.drakvuf.process
import orjson
from capa.features.address import (NO_ADDRESS, Address, AbsoluteVirtualAddress,
                                   DynamicCallAddress, ProcessAddress,
                                   ThreadAddress, _NoAddress)
from capa.features.common import Feature
from capa.features.extractors.base_extractor import (CallHandle,
                                                     DynamicFeatureExtractor,
                                                     ProcessHandle,
                                                     SampleHashes,
                                                     ThreadHandle)
from capa.features.extractors.drakvuf.models import (Call, DrakvufReport,
                                                     LoadedDLL, SystemCall,
                                                     WinApiCall)

logger = logging.getLogger(__name__)

#: `(file index, offsets)` per thread: one `array('q')` of byte offsets per
#: log the thread has calls in, in file order.
_ThreadIndex = List[Tuple[int, array]]


class StreamingDrakvufExtractor(DynamicFeatureExtractor):
    def __init__(self, analysis_dir: Path, logs: Sequence[str],
                 normalise: Callable[[dict], None],
                 pids: Optional[Set[int]] = None) -> None:
        super().__init__(
            # DRAKVUF yields no hash of the sample, as in capa's own extractor.
            hashes=SampleHashes(md5="", sha1="", sha256="")
        )
        self._files: List[Path] = [analysis_dir / n for n in logs
                                   if (analysis_dir / n).exists()]
        # The caller's per-record normalisation (`capa_processor.normalise_record`):
        # relabels libmon as apimon, strips what capa must not see as an
        # argument, and unwraps DRAKVUF's string syntax. Applied to every
        # record in both passes, so the index and the models agree.
        self._normalise = normalise
        self._pids = pids
        self._index: Dict[ProcessAddress, Dict[ThreadAddress, _ThreadIndex]] = {}
        self._process_names: Dict[ProcessAddress, str] = {}
        self._loaded_dlls: List[LoadedDLL] = []
        #: Calls the index pass found (after the PID filter), for the report.
        self.records = 0
        #: Records that parsed as JSON but not as a capa model, and so are
        #: not calls capa sees. capa's own reader raises out of the whole
        #: pass on the first of these; here it is a count and a debug line.
        self.rejected = 0
        self._build_index()
        # A report holding only what the file and global scopes read:
        # `loaded_dlls` for imports; the global features ignore its content.
        self._report = DrakvufReport(loaded_dlls=self._loaded_dlls)
        self.global_features = list(
            capa.features.extractors.drakvuf.global_.extract_features(self._report))

    # -- the index pass -------------------------------------------------------

    def _wanted(self, rec: dict) -> bool:
        if self._pids is not None and "PID" in rec and rec["PID"] not in self._pids:
            return False
        return True

    @staticmethod
    def _is_call(rec: dict) -> bool:
        plugin = rec.get("Plugin")
        if plugin == "syscall":
            return True
        return plugin == "apimon" and rec.get("Event") == "api_called"

    def _build_index(self) -> None:
        for fi, path in enumerate(self._files):
            with path.open("rb") as f:
                offset = 0
                for line in f:
                    start, offset = offset, offset + len(line)
                    try:
                        rec = orjson.loads(line)
                    except orjson.JSONDecodeError:
                        logger.debug("bad drakvuf log line in %s at %d", path.name, start)
                        continue
                    if not isinstance(rec, dict) or not self._wanted(rec):
                        continue
                    self._normalise(rec)
                    if self._is_call(rec):
                        self._index_call(rec, fi, start)
                    elif rec.get("Plugin") == "apimon" and rec.get("Event") == "dll_loaded":
                        try:
                            self._loaded_dlls.append(LoadedDLL(**rec))
                        except Exception:  # noqa: BLE001 - pydantic's ValidationError
                            self.rejected += 1
                            logger.debug("dll_loaded record rejected in %s at %d",
                                         path.name, start)

    def _index_call(self, rec: dict, fi: int, start: int) -> None:
        pid, ppid, tid = rec.get("PID"), rec.get("PPID"), rec.get("TID")
        if not all(isinstance(v, int) for v in (pid, ppid, tid)):
            self.rejected += 1
            return
        if pid == 0:
            # As capa's `index_calls`: the idle process is never the sample,
            # and capa's addresses do not take a null pid.
            return
        proc_addr = ProcessAddress(pid=pid, ppid=ppid)
        thread_addr = ThreadAddress(process=proc_addr, tid=tid)
        threads = self._index.setdefault(proc_addr, {})
        if proc_addr not in self._process_names:
            # capa names a process after its first call's `ProcessName`.
            name = rec.get("ProcessName")
            self._process_names[proc_addr] = name if isinstance(name, str) else ""
        per_file = threads.setdefault(thread_addr, [])
        if not per_file or per_file[-1][0] != fi:
            per_file.append((fi, array("q")))
        per_file[-1][1].append(start)
        self.records += 1

    # -- the extraction pass --------------------------------------------------

    def _calls_in(self, fi: int, offsets: array) -> Iterator[Tuple[str, Call]]:
        """`(timestamp, model)` for each offset, in file order."""
        with self._files[fi].open("rb") as f:
            for start in offsets:
                f.seek(start)
                line = f.readline()
                try:
                    rec = orjson.loads(line)
                except orjson.JSONDecodeError:
                    continue
                self._normalise(rec)
                try:
                    model = (SystemCall(**rec) if rec.get("Plugin") == "syscall"
                             else WinApiCall(**rec))
                except Exception:  # noqa: BLE001 - pydantic's ValidationError
                    self.rejected += 1
                    logger.debug("call rejected in %s at %d", self._files[fi].name, start)
                    continue
                yield model.timestamp, model

    def get_base_address(self) -> Union[AbsoluteVirtualAddress, _NoAddress, None]:
        return NO_ADDRESS

    def extract_global_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from self.global_features

    def extract_file_features(self) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.drakvuf.file.extract_features(self._report)

    def get_processes(self) -> Iterator[ProcessHandle]:
        for proc_addr in self._index:
            yield ProcessHandle(proc_addr,
                                inner={"process_name": self._process_names[proc_addr]})

    def extract_process_features(self, ph: ProcessHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.drakvuf.process.extract_features(ph)

    def get_process_name(self, ph: ProcessHandle) -> str:
        return ph.inner["process_name"]

    def get_threads(self, ph: ProcessHandle) -> Iterator[ThreadHandle]:
        for thread_addr in self._index[ph.address]:
            yield ThreadHandle(address=thread_addr, inner={})

    def extract_thread_features(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from []

    def get_calls(self, ph: ProcessHandle, th: ThreadHandle) -> Iterator[CallHandle]:
        # capa sorts a thread's calls by their timestamp string; each log is
        # chronological on its own, so a merge of the per-log streams gives
        # the same order without holding the thread.
        streams = [self._calls_in(fi, offsets)
                   for fi, offsets in self._index[ph.address][th.address]]
        merged = heapq.merge(*streams, key=lambda item: item[0])
        for i, (_, call) in enumerate(merged):
            yield CallHandle(address=DynamicCallAddress(thread=th.address, id=i),
                             inner=call)

    def get_call_name(self, ph: ProcessHandle, th: ThreadHandle, ch: CallHandle) -> str:
        call: Call = ch.inner
        return "{}({}){}".format(
            call.name,
            ", ".join(f"{k}={v}" for k, v in call.arguments.items()),
            f" -> {getattr(call, 'return_value', '')}",
        )

    def extract_call_features(self, ph: ProcessHandle, th: ThreadHandle,
                              ch: CallHandle) -> Iterator[Tuple[Feature, Address]]:
        yield from capa.features.extractors.drakvuf.call.extract_features(ph, th, ch)
