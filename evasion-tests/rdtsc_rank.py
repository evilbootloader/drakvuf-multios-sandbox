#!/usr/bin/env python3
"""Ranks the variants of one or more rdtsc_search.sh result directories: first by the share of
detector runs that returned true, then by how stable the guest stayed, i.e. how close the detector
runs (false + true) per configuration run came to DRAKVUF_TIMEOUT / WORKLOAD_DELAY (55 / 5 = 11;
a healthy guest reaches 10). A guest the variant slows runs it 1-3 times.

Usage: rdtsc_rank.py RESULTS_DIR... [--expected 11] [--min-runs 8]
"""
import argparse
import csv
import os
import statistics

CONFIGS = ('dev-syscalls', 'dev-all')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('dirs', nargs='+')
    ap.add_argument('--expected', type=float, default=55 / 5)
    ap.add_argument('--min-runs', type=int, default=8)
    args = ap.parse_args()

    rows = []
    for d in args.dirs:
        variants = {}
        with open(os.path.join(d, 'variants.csv')) as f:
            for v in csv.DictReader(f):
                variants[v['variant']] = v['result']
        with open(os.path.join(d, 'results.csv')) as f:
            results = list(csv.DictReader(f))
        for name, result in variants.items():
            rs = [r for r in results if r['variant'] == name]
            if not rs:
                rows.append(((-2, 0), name, result, 0, 0, 0, {}, 0, None, os.path.basename(d)))
                continue
            tests = sorted({int(r['test']) for r in rs})
            none = sum(1 for t in tests
                       if any(r['verdict'] == 'none' for r in rs if int(r['test']) == t))
            count = lambda r: int(r['detector_false']) + int(r['detector_true'])
            runs = {c: [count(r) for r in rs if r['config'] == c] for c in CONFIGS}
            trues = {c: sum(int(r['detector_true']) for r in rs if r['config'] == c) for c in CONFIGS}
            stable = 0
            first_slow = None
            for t in tests:
                tr = [count(r) for r in rs if int(r['test']) == t]
                if tr and min(tr) >= args.min_runs:
                    stable += 1
                elif first_slow is None:
                    first_slow = t
            detected = sum(trues.values())
            every = [count(r) for r in rs]
            share = detected / max(1, sum(every))
            score = statistics.mean(min(x, args.expected) / args.expected for x in every)
            rows.append(((-share, score), name, result, len(tests), none, detected,
                         (runs, trues), stable, first_slow, os.path.basename(d)))

    print('Detector runs per configuration run (expected %g; slow = fewer than %d)'
          % (args.expected, args.min_runs))
    print('%-28s %-12s %5s %4s %4s | %-21s | %-21s | %6s %9s %5s  %s'
          % ('variant', 'result', 'tests', 'none', 'true', 'syscalls true/runs min',
             'all true/runs min', 'stable', 'firstslow', 'score', 'run'))
    for key, name, result, ntests, none, detected, runs, stable, first_slow, run in sorted(rows, reverse=True):
        score = key[1]
        if key[0] == -2:
            print('%-28s %-12s %5s %4s %4s | %-21s | %-21s | %6s %9s %5s  %s'
                  % (name, result, 0, 0, '-', '-', '-', '-', '-', '-', run))
            continue
        runs, trues = runs
        cols = []
        for c in CONFIGS:
            l = runs.get(c) or [0]
            cols.append('%4d/%-4d min %-2d' % (trues.get(c, 0), sum(l), min(l)))
        print('%-28s %-12s %5d %4d %4d | %-21s | %-21s | %5.0f%% %9s %5.2f  %s'
              % (name, result, ntests, none, detected, cols[0], cols[1], 100 * stable / ntests,
                 first_slow if first_slow is not None else '-', score, run))


if __name__ == '__main__':
    main()
