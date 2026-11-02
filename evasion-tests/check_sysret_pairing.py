#!/usr/bin/env python3
"""Check that DRAKVUF's sysret records close the syscall records of the same thread.

Reads the log of the syscalls plugin written with `-o json`. Per thread (PID, TID)
the open calls are kept as a stack. A sysret record should close the innermost open
call with the same syscall number and module:

  innermost    it closes the most recent open call of the thread, as expected
  outer        it closes an older call, the calls above it never got a sysret: either
               they don't return (NtContinue, NtCallbackReturn, NtTerminateThread, ...)
               or their sysret was lost or matched to the wrong call
  unmatched    there is no open call for it on the thread, normally a call that was in
               progress when DRAKVUF started
  open         calls without a sysret when the log ends, normally still in progress

With --csv it prints `innermost,outer,abandoned,unmatched,open,cross_vcpu` instead of
the report, --report FILE writes the report to FILE.
"""

import argparse
import collections
import json
import sys


def check(path):
    stacks = collections.defaultdict(list)  # (pid, tid) -> [((num, module), method, vcpu)]
    counts = collections.Counter()
    abandoned = collections.Counter()  # calls left open by a sysret of an outer call, by name
    unmatched = collections.Counter()  # sysrets without an open call, by name

    with open(path, errors="replace") as log:
        for line in log:
            # Cheap filter first, logs have hundreds of thousands of lines
            if not line.startswith('{"Plugin":"sys'):
                continue
            try:
                record = json.loads(line)
            except ValueError:
                counts["unparsed"] += 1
                continue

            plugin = record.get("Plugin")
            if plugin not in ("syscall", "sysret"):
                continue

            thread = (record.get("PID"), record.get("TID"))
            call = (record.get("Syscall"), record.get("Module"))
            method = record.get("Method") or "#{}".format(call[0])
            vcpu = record.get("vCPU")
            stack = stacks[thread]

            if plugin == "syscall":
                counts["syscall"] += 1
                stack.append((call, method, vcpu))
                continue

            counts["sysret"] += 1
            for index in range(len(stack) - 1, -1, -1):
                if stack[index][0] == call:
                    break
            else:
                counts["unmatched"] += 1
                unmatched[method] += 1
                continue

            if index == len(stack) - 1:
                counts["innermost"] += 1
            else:
                counts["outer"] += 1
                for _, left_open, _ in stack[index + 1:]:
                    counts["abandoned"] += 1
                    abandoned[left_open] += 1

            if stack[index][2] != vcpu:
                counts["cross_vcpu"] += 1
            del stack[index:]

    still_open = collections.Counter()  # calls without a sysret at the end, by name
    for stack in stacks.values():
        for _, method, _ in stack:
            still_open[method] += 1
    counts["open"] = sum(still_open.values())
    return counts, abandoned, unmatched, still_open


def percent(part, whole):
    return "{:.2f}%".format(100.0 * part / whole) if whole else "-"


def top(counter, limit=10):
    return ", ".join("{} {}".format(name, count) for name, count in counter.most_common(limit)) or "-"


def report(path, counts, abandoned, unmatched, still_open):
    sysret = counts["sysret"]
    matched = counts["innermost"] + counts["outer"]
    lines = [
        "log:                                   {}".format(path),
        "syscall records:                       {}".format(counts["syscall"]),
        "sysret records:                        {}".format(sysret),
        "  close the innermost open call:       {} ({})".format(counts["innermost"], percent(counts["innermost"], sysret)),
        "  close an older open call:            {} ({})".format(counts["outer"], percent(counts["outer"], sysret)),
        "    calls left open by those:          {}".format(counts["abandoned"]),
        "    by name:                           {}".format(top(abandoned)),
        "  without an open call on the thread:  {} ({})".format(counts["unmatched"], percent(counts["unmatched"], sysret)),
        "    by name:                           {}".format(top(unmatched)),
        "calls still open at the end:           {}".format(counts["open"]),
        "    by name:                           {}".format(top(still_open)),
        "returns on another vCPU than the call: {} ({} of matched)".format(
            counts["cross_vcpu"], percent(counts["cross_vcpu"], matched)),
    ]
    if counts["unparsed"]:
        lines.append("unparsed lines:                        {}".format(counts["unparsed"]))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("log", help="syscalls plugin log written with -o json")
    parser.add_argument("--csv", action="store_true", help="print innermost,outer,abandoned,unmatched,open,cross_vcpu")
    parser.add_argument("--report", metavar="FILE", help="write the report to FILE")
    args = parser.parse_args()

    counts, abandoned, unmatched, still_open = check(args.log)
    text = report(args.log, counts, abandoned, unmatched, still_open)

    if args.report:
        with open(args.report, "w") as out:
            out.write(text)
    if args.csv:
        print(",".join(str(counts[key]) for key in
                       ("innermost", "outer", "abandoned", "unmatched", "open", "cross_vcpu")))
    elif not args.report:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
