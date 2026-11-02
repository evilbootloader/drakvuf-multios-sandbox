#!/usr/bin/env python3
"""Ranks the variants of an alkhaser_search.sh run by the al-khaser checks that found the
sandbox in any of their runs (the union: fewer is better): checks that detected it, checks that
did not return in time (blocked), checks a run hung in (no progress for longer than the watchdog's
120 s) and those it ran out of time in (al-khaser had not finished when DRAKVUF stopped). Then by runs that did not finish or crashed. Lists each check with its name and how
often, per configuration, and what changed against the first variant of the run (the baseline).

Usage: alkhaser_rank.py <alkhaser-search/<timestamp> directory>
"""
import csv
import os
import sys
from collections import Counter, OrderedDict, defaultdict

CATEGORIES = {
    1: 'TLS', 2: 'DEBUG', 3: 'INJECTION', 4: 'GEN_SANDBOX', 5: 'VBOX', 6: 'VMWARE', 7: 'VPC',
    8: 'QEMU', 9: 'XEN', 10: 'KVM', 11: 'WINE', 12: 'PARALLELS', 13: 'HYPERV', 14: 'TIMING',
    15: 'ANALYSIS_TOOLS', 16: 'HUMAN_INTERACTION',
}
# Verdicts of the runs in which al-khaser ran
RAN = ('clean', 'detected', 'unfinished', 'crashed')


def check_name(code, names):
    category = CATEGORIES.get(code // 1000, '?')
    if code % 1000 == 0:
        return '%s, outside any check: %s' % (category, names.get(code, ''))
    return '%s #%d: %s' % (category, code % 1000, names.get(code, '(no name in the trace)'))


def codes(field):
    return [int(c) for c in field.split() if c.isdigit()]


def main(directory):
    names = {}
    path = os.path.join(directory, 'codes.tsv')
    if os.path.exists(path):
        with open(path, encoding='utf-8', errors='replace') as f:
            for line in f:
                code, _, name = line.rstrip('\n').partition('\t')
                if code.isdigit() and name:
                    names[int(code)] = name

    variants = OrderedDict()
    with open(os.path.join(directory, 'results.csv'), newline='') as f:
        for row in csv.DictReader(f):
            v = variants.setdefault(row['variant'], {
                'verdicts': Counter(), 'ran': Counter(), 'found': defaultdict(Counter)})
            v['verdicts'][row['verdict']] += 1
            if row['verdict'] not in RAN:
                continue
            config = row['config']
            v['ran'][config] += 1
            for code in codes(row['detected']):
                v['found'][(code, 'detected')][config] += 1
            for code in codes(row['blocked']):
                v['found'][(code, 'blocked')][config] += 1
            if row['verdict'] in ('unfinished', 'crashed') and row['last_started'].isdigit():
                # Ran out of time in a check, or hung in it: no mark for longer than the watchdog's 120 s
                idle = int(row['idle']) if row.get('idle', '').isdigit() else 0
                if row['verdict'] == 'crashed':
                    kind = 'crashed in'
                else:
                    kind = 'hung in' if idle > 150 else 'out of time'
                v['found'][(int(row['last_started']), kind)][config] += 1
    if not variants:
        print('No results yet')
        return

    def key(item):
        name, v = item
        return (not v['ran'], len(v['found']), v['verdicts']['unfinished'] + v['verdicts']['crashed'], name)

    print('%-28s %6s %6s %5s %5s %5s %5s  %s' % (
        'variant', 'checks', 'clean', 'det', 'unfin', 'crash', 'none', 'runs per configuration'))
    for name, v in sorted(variants.items(), key=key):
        c = v['verdicts']
        print('%-28s %6d %6d %5d %5d %5d %5d  %s' % (
            name, len(v['found']), c['clean'], c['detected'], c['unfinished'], c['crashed'], c['none'],
            ' '.join('%s=%d' % kv for kv in sorted(v['ran'].items()))))

    baseline_name, baseline = next(iter(variants.items()))
    for name, v in variants.items():
        print('\n===== %s: %d checks found the sandbox' % (name, len(v['found'])))
        for code, kind in sorted(v['found']):
            per_config = ' '.join('%s %d/%d' % (config, v['found'][(code, kind)][config], v['ran'][config])
                                  for config in sorted(v['ran']))
            print('  %5d %-10s %-62s %s' % (code, kind, check_name(code, names)[:62], per_config))
        if not v['ran']:
            print('  al-khaser ran in no configuration run: nothing to compare')
        elif name != baseline_name and baseline['ran']:
            gone = sorted(set(baseline['found']) - set(v['found']))
            new = sorted(set(v['found']) - set(baseline['found']))
            print('  against %s: gone %s; new %s' % (
                baseline_name, ' '.join('%d %s' % k for k in gone) or '-',
                ' '.join('%d %s' % k for k in new) or '-'))


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
