# Falco rules over the Linux trace

`sandboxd/postprocessing/falco/` evaluates Falco's rule language against the
records DRAKVUF writes, as the postprocessing plugin `falco_analysis`, and
`get_falco_info` puts the result in `report.json` (`falco`,
`falco_coverage`). The Overview tab lists the findings; the Network tab lists
the ones tagged `network`, beside the connections.

**Linux guests only** (Ubuntu, Android). Falco's rules describe Linux
syscalls; Windows has no row in `falco_analysis.FALCO_PROFILES`.

## Why not Falco itself

Falco reads libscap events from a kernel driver or a capture file and keeps
its own process and file-descriptor state in libsinsp. A converter from
DRAKVUF's JSON to that capture format would still lack what DRAKVUF does not
record, and would hide which of Falco's fields were guesses. So the rule
language is evaluated directly, and every field says where it comes from.

## What it reads

| Log | Plugin | Gives |
|---|---|---|
| `procmon.log` | procmon | processes: running at start, clones, execs, exits. An exec record comes from a return hook on `begin_new_exec`, the point of no return, so each one is a successful exec |
| `syscall.log` | syscalls | each call's arguments at entry |
| `sysret.log` | syscalls | each call's result, paired by thread and syscall number. **Correct only from drakvuf `44b6a19`**; before it every Linux result was `0x0` |
| `filetracer.log` | filetracer | a second reading of the path under the same `EventUID`, which wins |
| `libmon.log` | libmon | library calls: the `libmon` rule source, and -- when sysret is off -- the result of a syscall a libc wrapper made |
| `unixsocketmon.log` | unixsocketmon | both ends of a socket for its connect and sends (drakvuf `e58c13a`) |
| `inject.log` | -- | the sample's process: the scope is it and its descendants |

Records are read, filtered to the sample's processes (`scope: sample`, the
default) and sorted by `EventUID`, one counter across every plugin. procmon is
read for every process, because a rule asks about ancestors.

**What a job needs for the rules to have data:** procmon (every exec rule),
syscall returns (every file rule: `fd.num >= 0`), procmon's environment list
(`--procmon-envs-list`, which `argv_trace` passes with procmon) and
unixsocketmon (every network rule).

## Three-valued evaluation

Falco reads a field it cannot extract as false. Over a DRAKVUF trace far more
is unknowable, and `not proc.pname in (...)` would then be true for every
process whose parent the trace never saw. So:

- a field returns a value, **None** (it exists and is empty here -- a
  container field on a VM; every comparison is false, as in Falco) or
  **UNKNOWN** (this trace cannot say);
- `and`, `or` and `not` follow Kleene's logic;
- only a definite True is an alert. An UNKNOWN is counted against the rule as
  undetermined, with the fields that made it so (`falco-rules.json`).

A field with several values (`proc.aname`, `fd.ip`, `proc.env`) is true when
any value matches. One whose values are known to be partial -- an ancestry
that runs into a process the trace never saw -- decides only a match. For
`proc.env`, a `contains` check for a variable on procmon's list is decided
both ways: the variable would have been printed had it been set.

## Fields

| Field | From | Unknown when |
|---|---|---|
| `evt.type`, `evt.num`, `evt.time` | the record | -- |
| `evt.rawres`, `evt.res`, `evt.failed` | sysret; libmon's return value without sysret | no return was recorded |
| `evt.arg.*` | the syscall's arguments, renamed to Falco's (`linux.EVENT_ARGS`) and rendered as Falco renders them (`O_WRONLY|O_CREAT`, `S_ISUID`, `PTRACE_ATTACH`) | the argument was not printed |
| `evt.is_open_read/write/create` | the open flags | -- |
| `proc.name` | the thread's `comm`; after an exec, the basename of the file executed | -- |
| `proc.exe`, `proc.args`, `proc.cmdline` | the exec's `CommandLine` | the process was running before the trace |
| `proc.exepath` | the exec's `ImagePathName` | as above |
| `proc.p*`, `proc.a*[n]` | the process table | the parent was not seen |
| `proc.env`, `proc.env[NAME]` | the exec's `Environment` | NAME is not on procmon's list |
| `proc.cwd` | the exec's `PWD`, then `chdir`/`fchdir` | never seen |
| `user.uid`, `user.name` | `UserId`; names from `FALCO_PROFILES` (Debian's static base-passwd uids, and the golden image's 1000) | a uid not in that map |
| `fd.*` (files) | the fd table: opens, `dup*`, `fcntl`, `close`, inherited on clone, `O_CLOEXEC` dropped on exec | a descriptor opened before the trace |
| `fd.sip`, `fd.sport`, `fd.l4proto`, ... | unixsocketmon | unixsocketmon did not run |
| `container.id`, `container.name` | always `host` | -- |
| `container.*`, `k8s.*` | always None | -- |
| `proc.tty`, `thread.cap_*`, `user.loginuid`, `group.*`, `fd.*ip.name` | -- | always |

A field in none of these is not supported: the rule that uses it is marked
`unsupported` with the reason, never silently skipped.

## Rules

- `sandboxd/data/falco-rules`: falcosecurity/rules, a submodule at
  `falco-rules-5.2.0`. Stable and incubating are loaded (56 rules, all
  compile; `test_every_vendored_rule_compiles` keeps it so). The sandbox file
  is not: noisier, and mostly about containers.
- `sandboxd/data/falco-rules-local/*.yaml`, loaded after them in name order.
  `libmon.yaml` holds rules of source `libmon` over libmon's calls: `evt.type`
  is the function, `api.arg[Name]` an argument by the hook list's name,
  `api.ret` the return value.
- **The clone's own /24 is the only local network.** `falco_analysis`
  replaces `rfc_1918_addresses` with the job's `egress.vlan_subnet(vlan)`, so a
  sample reaching any other private address counts as outbound.

Tuning goes in the local directory as Falco tunes: `append` or `override` a
list, macro or rule (`override: {items: append}`), or set `enabled: false`.

## Checked against

- unit tests: `sandboxd/tests/test_falco.py`;
- the 2026-10-23 Ubuntu benchmark trace, all plugins: 41k events in the
  workload's scope, 3.6 s, no alerts; over every process, no alerts but the
  desktop's Wayland memfds, now excepted in `libmon.yaml`;
- a benign workload that does one thing per rule (`workload-falco-linux.sh`
  beside the benchmark): all 12 rules it targets fire, attributed to its
  processes, and the open of `/etc/shadow` it makes as a user -- which fails --
  does not.