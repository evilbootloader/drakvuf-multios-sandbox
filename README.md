# DRAKVUF Multi-OS Sandbox

Automation for a DRAKVUF malware-analysis laboratory.

```
Xen Dom0 on bare metal + DRAKVUF/LibVMI
├── Ubuntu analysis guest        (HVM, disposable clone per sample)
├── Android/BlissOS analysis guest
├── Windows analysis guest
└── platform                     (PVH DomU: Postgres, Garage, the web API)
```

A sample is analysed under DRAKVUF inside a disposable clone of the guest for
its target OS, and the clone is destroyed afterwards. **There is one way in:**
a sample is uploaded through the web UI, queued in Postgres, and claimed by
`sandboxd` on Dom0 over mutual TLS.

## Installing the lab

The install is `make`-driven and runs **as root on Dom0, from the checkout**.
`docs/runbooks/18-deploy-with-makefile.md` is the step-by-step, run top to
bottom on 2026-11-04 with every step's output: what each target does, what
its output looks like, and what to do when it refuses. This is the summary.
The `stable` branch of this repository, and of the `drakvuf` and `libvmi`
forks it pins, marks what that run deployed; `master` and the forks'
`develop` and `feature/vcpu-parallel-events` move ahead of it.

### What the host needs first

None of this is done by a target.

- **An Intel CPU with VT-x and EPT.** DRAKVUF's altp2m needs EPT, and the
  RDTSC compensation is VMX code. There is nothing to run on AMD.
- **RAM.** The boot line fixes Dom0 at 8192 MiB; the platform takes 4096 and
  each analysis guest 8192. The lab has 32 GiB.
- **Ubuntu Server 24.04**, on bare metal.
- **LVM, laid out for the Makefile.** A volume group named **`vg-root`** (the
  name is hardcoded in every `lvcreate` and every guest config), root on a
  **thick** LV, `/boot` on a **plain partition** (GRUB multiboots Xen from it,
  and the evasion searches need `grub-reboot`, which cannot clear its one-shot
  entry on LVM), and the rest of the VG **left free**: `make web_vm` creates the
  thin pool from 90 % of it. `lvm2`, `thin-provisioning-tools` and
  `lvm2-monitor` enabled, autoextend configured. Runbook 12 §B0 has the layout
  this host was built with.
- **Two bridges.** `xenbr0`, a Linux bridge carrying the uplink NIC with Dom0's
  address, set up in netplan (apply it with `netplan try`: it carries your ssh
  session). `xenbr1`, an Open vSwitch bridge, created once:
  `apt install -y openvswitch-switch && ovs-vsctl add-br xenbr1`. `sandboxd`
  configures the per-VLAN analysis networks on it at every start and refuses
  to run without it, but does not create it.
- **Root's ssh key on Dom0, without a passphrase.** The Makefile reaches the
  platform DomU as root with it, hundreds of lines deep.
- **A DNS name** for the browser-facing side, and a Cloudflare account for the
  tunnel (below).
- **Disk on `/`** for the ISOs (2.1 GB Ubuntu server, 6.7 GB Windows 11) and the
  Xen and DRAKVUF builds; `misc/iso/` is in `.gitignore`.

### `Makefile.local`

Host values live in an **untracked** `Makefile.local` at the repository root.
The Makefile reads it first and every default yields to it. Four are required:

```make
RSA_KEY := ssh-ed25519 AAAA... root@dom0   # Dom0 root's PUBLIC key, one line: goes into the DomU and the Ubuntu guest
SANDBOX_WEB := sandbox.example.com         # the browser-facing name: TLS SANs, BROWSER_ORIGIN, api.env
ANALYSIS_VM_USER := user                   # the analysis guests' user; also SANDBOXD_ANALYSIS_USERNAME
ANALYSIS_VM_PASS := ...                    # the analysis guests' password
# Only when the Makefile's defaults are wrong for this host:
#VMADDR := 192.168.1.12/24                 # the platform DomU's address, written into it and dialled afterwards
#VMROUTE := 192.168.1.1                    # its gateway
#SANDBOXDIP := 192.168.1.6                 # Dom0's address: a SAN of the dom0-lab certificate
#S3_QUOTA := 400                           # GiB: the object store's layout and bucket quota
#S3_RETENTION := 30                        # days
#INSTALLERS_MIRROR := https://192.168.1.12:9100/win-installers   # where win_installers looks first; empty disables it
```

`scripts/check-secrets.sh` does not read Makefiles. The file being untracked
is what keeps the password out of history; never commit it.

### The sequence

Three places. **Dom0 (no Xen)** is the plain Ubuntu kernel, the only boot
`make xen` may run on; on an existing Dom0 the switch is `evasion-tests/README.md`
§7.7. **Dom0** is Dom0 booted on Xen, as root, in the checkout. **VNC** is a
guest's console on Dom0's loopback: `ssh -L 5900:127.0.0.1:5900 root@dom0`
from your machine, then a viewer on `localhost:5900`. The platform DomU is
reached by the Makefile itself, over ssh as root.

```bash
# DOM0 (no Xen), as root
git clone --recursive -b stable https://github.com/evilbootloader/drakvuf-multios-sandbox.git /root/drakvuf-multios-sandbox
cd /root/drakvuf-multios-sandbox
test -f /root/.ssh/id_ed25519.pub || ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_ed25519
$EDITOR Makefile.local                 # the block above; RSA_KEY is the content of /root/.ssh/id_ed25519.pub
make xen                               # builds Xen with the patches and the host's identity, installs it, makes it the GRUB default
# On a CPU that crashes the toolchain under a full build (the lab's i9-13900KF does):
#   taskset -c 16-31 make xen           -- docs/TROUBLESHOOTING.md, "make xen -- internal compiler error"
reboot

# DOM0 (Xen), as root
cd /root/drakvuf-multios-sandbox
xl dmesg | grep RDTSC_POC              # "compensation enabled"; xen-rdtsc-poc.service fails otherwise
make web_vm                            # the platform DomU from nothing. Asks for its root password. REFUSES to run over an existing one
make web_sandbox                       # Postgres, migrations, Garage, TLS, the API, nginx. Re-runnable: keeps what exists.
                                       # It checks out THIS checkout's HEAD on the DomU from GitHub, so that commit must be pushed
make sandboxd                          # libvmi + DRAKVUF, tor + FakeNet-NG, Dom0's certificates, the daemon's venv and env file. Re-runnable

make windows_analysis_vm               # win_installers first: 8 installers fetched once -- from the lab's mirror, or from the vendor when
                                       # the mirror has none -- and verified against automation/win-installers.list; a mismatch refuses the build.
                                       # Then the modified ISO and the installer booted. VNC: wait for the desktop, shut down from inside
make win_installers_mirror             # once the eight files verified: publish them to the platform's mirror (nginx on 9100, LAN only),
                                       # so a vendor's next release changes nothing until someone re-pins on purpose
make modify_windows                    # boots it again to tune (Defender, updates, ...); shut down from inside
make setup_hooks_windows               # guest DOWN first. Profiles, the sandbox snapshot, boots it, records explorer.exe's PID
#   Leave it running AT LEAST 20 MINUTES: every clone restores with this uptime, and a two-minute uptime is a sandbox tell.
#   Do not restart it (the PID is the running explorer.exe). Then, by hand:
xl save windows_analysis_sandbox state/windows_sandbox.bak misc/xen-vms/windows_sandbox.cfg

make ubuntu_analysis_vm                # autoinstall from the server ISO; the guest powers itself off when done. Watch it over VNC
make modify_ubuntu                     # optional: boot it, check the desktop logs in; shut down from inside
make setup_hooks_ubuntu                # guest DOWN first. linux.json from the debug kernel, the snapshot, boots it, anchor PID 1
#   Same 20 minutes, then by hand:
xl save ubuntu_analysis_sandbox state/ubuntu_sandbox.bak misc/xen-vms/ubuntu_sandbox.cfg

# DOM0 (Xen), as root, in tmux: the daemon runs in the foreground and has no systemd unit
set -a; . /etc/sandboxd/sandboxd.env; set +a
.venv-sandboxd/bin/python -m sandboxd.daemon
```

Then back up `state/` (the saved guests and the identity) and `profiles/`:
none of it is tracked, and the identity cannot be drawn again.

Feeding it from MalwareBazaar, from a workstation that reaches both abuse.ch
and the platform: `scripts/bazaar-submit.py` asks for the abuse.ch Auth-Key
and the platform login, pulls recent `exe` and `elf` samples, keeps the ones
whose headers say x86 or x86-64, submits each to the matching guest with a
trace length drawn at random between 120 and 1200 seconds, waits for the job
to end, and publishes it, readable by every account on the platform, before
the next; `--private` leaves each analysis to the submitting account. Samples
over `--max-bytes` are skipped, by default
just under 100 MB: the upload crosses the Cloudflare tunnel, whose free plan
stops a request body there, well before the platform's own 1 GiB cap. Samples
live only under its `--workdir`, are never executed there, and are deleted
after upload. Needs `pyzipper` or a `7z` binary for abuse.ch's AES zips.

```bash
# WORKSTATION
platform/.venv/bin/pip install pyzipper          # once; not in the pinned requirements, which install on the DomU
platform/.venv/bin/python scripts/bazaar-submit.py --platform https://sandbox.example.com --count 5
platform/.venv/bin/python scripts/bazaar-submit.py --platform https://sandbox.example.com --os ubuntu --seconds 600 --dry-run
```

Creating users when registration is not active:
```
# PLATFORM DOMU, as root
ssh <PLATFORM_VM_IP>
cd /opt/platform/src/platform
sudo -u platform DATABASE_URL=postgresql:///sandbox_platform \
  .venv/bin/python create_user.py you@example.com --balance 100000  # balance is in seconds
```

### Cloudflare tunnel on WEB SANDBOX

Everything in this block runs on the platform DomU, as root.

```
# PLATFORM DOMU, as root
ssh <PLATFORM_VM_IP>

sed 's/TRUSTED_CLIENT_IP_HEADER=/TRUSTED_CLIENT_IP_HEADER=CF-Connecting-IP/g' -i /etc/sandbox_platform/api.env

curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg \
  -o /usr/share/keyrings/cloudflare-main.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main" \
  > /etc/apt/sources.list.d/cloudflared.list
apt-get update && apt-get install -y cloudflared

cloudflared tunnel login
cloudflared tunnel create sandbox-platform
cloudflared tunnel route dns sandbox-platform <SANDBOX_DOMAIN>

install -d -m 750 /etc/cloudflared
mv ~/.cloudflared/<UUID>.json /etc/cloudflared/
chmod 600 /etc/cloudflared/<UUID>.json

useradd --system --no-create-home --shell /usr/sbin/nologin cloudflared || true
cp /etc/sandbox_platform/tls/ca.crt /etc/cloudflared/ca.crt
chown -R cloudflared:cloudflared /etc/cloudflared

cat > /etc/systemd/system/cloudflared.service <<EOF
[Unit]
Description=Cloudflare Tunnel (browser-facing ingress)
After=network-online.target sandbox-api.service
Wants=network-online.target

[Service]
Type=notify
User=cloudflared
Group=cloudflared
ExecStart=/usr/bin/cloudflared --no-autoupdate --config /etc/cloudflared/config.yml tunnel run
Restart=on-failure
RestartSec=5
TimeoutStartSec=0

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload

cat > /etc/cloudflared/config.yml <<EOF
tunnel: UUID
credentials-file: /etc/cloudflared/UUID.json
# /etc/cloudflared/config.yml
ingress:
  # bucket FIRST -- cloudflared matches in order
  - hostname: SANDBOX_DOMAIN
    path: ^/analysis(/|$)
    service: https://VM_IP:9000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - hostname: SANDBOX_DOMAIN
    path: ^/api/v1/worker(/|$)
    service: http_status:404
  - hostname: SANDBOX_DOMAIN
    service: https://VM_IP:8000
    originRequest:
      caPool: /etc/cloudflared/ca.crt
  - service: http_status:404
EOF
chown cloudflared:cloudflared /etc/cloudflared/config.yml
cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate
systemctl enable --now cloudflared
systemctl status cloudflared --no-pager | head -5
```

Until 2026-08-28 this ran nested inside Proxmox, three layers deep. Proxmox was
erased in the bare-metal migration; documents naming `pve1`, VM 101 or CT 102
predate it. `docs/CURRENT-STATE.md` §2a lists what that invalidated.

The original path — dropping a file into `/malware_incoming/<os>/` for a per-OS
`dirwatch` watcher to pick up — was **removed on 2026-09-15**, along with the
shell and C pipeline behind it. See
`docs/architecture/automation-files.md` for what each of those files did and
what replaced it.

## The components

| | |
|---|---|
| **`automation/`** | host provisioning and deployment assets — `network-setup.sh` (the per-VLAN isolated networks), `platform.env`, the egress configs, and the Xen patch and GRUB config `make xen` installs. Not the pipeline; that is `sandboxd/` |
| **`sandboxd/`** | the Dom0 orchestrator. Claims jobs from the platform, admits them against real host capacity, runs the pipeline, uploads artifacts, and reports state. Python; runs in the foreground with **no systemd unit** |
| **`platform/`** | the web tier: FastAPI, Postgres job queue, Garage object store (MinIO until 2026-10-02), server-rendered UI, a Cloudflare tunnel at the edge and an internal CA inward. Runs in its own PVH DomU and **never executes a sample** — that asymmetry is what the whole trust boundary rests on |

Dom0 opens every connection and has no inbound listener; the platform answers
requests and never makes them.

## The OS targets

All three are current, at different stages:

| Target | State |
|---|---|
| **Ubuntu** | Evidenced end to end, including through the platform |
| **Android/BlissOS** | Automation complete, in `sandboxd/guests.py`. **Both sample kinds evidenced through the platform** — native ELF, and APK install + `am start` |
| **Windows** | Evidenced end to end with a transcript on 2026-11-04 (`docs/runbooks/18-deploy-with-makefile.md` §6b), on the image the Makefile builds; before that, one operator-confirmed run on 2026-09-05. **No per-plugin validation yet**: a job completing does not mean every plugin produced what it should |

## Running it

Every repository-owned asset resolves from the invoking code's own location,
so the checkout works at any path — the Dom0 checkout happens to be at
`/root/drakvuf-multios-sandbox`, but nothing requires that.

Analyses are submitted through the platform's web UI. On Dom0, `sandboxd` is
started in the foreground with its environment file sourced first; it exits
immediately without `SANDBOXD_API`, `WORKER_TOKEN` and `SANDBOXD_TOTAL_MIB`,
because there is no safe default for how much memory a Dom0 may hand to clones.
`docs/CURRENT-STATE.md` §1.2 has the exact invocation.

Host configuration lives in `sandboxd/config.py`, which is the source of truth;
`scripts/gen-xen-configs.py` pushes its values into `automation/platform.env`
and `misc/*.cfg`, which cannot import Python.

A fresh checkout also needs a LibVMI profile in `profiles/` and a saved
guest state in `state/`; neither is git-tracked. See `profiles/README.md`,
`state/README.md`, and `docs/runbooks/02-deploy-repo-relative-paths.md`.

## Repository layout

- `automation/` — host provisioning and deployment assets: `network-setup.sh`
  (executed by `sandboxd` at every daemon start), host-global `platform.env`,
  the egress configs (`torrc`, `fakenet.*`, `drakvuf-egress.target`) that
  `make sandboxd` installs, and the Xen patches, unit and GRUB config that
  `make xen` installs (`xen-altp2m-pause-vcpu.patch`, `xen-rdtsc-poc.patch`,
  `xen-guest-identity.patch`, `xen-rdtsc-poc.service`, `xen-grub.cfg`). The
  shell and C pipeline that used to live here was deleted 2026-09-15 — see
  `docs/architecture/automation-files.md`.
- `sandboxd/` — the Dom0 orchestrator and its tests. **This is the analysis
  pipeline**: clone, isolate, preconfigure, trace, collect, destroy, shared
  across all three OS targets and driven by the platform's queue, with
  host-global admission control instead of fixed clone slots. See
  `docs/architecture/analysis-pipeline.md`.
- `platform/` — the FastAPI service, SQL migrations, Garage provisioning
  (`platform/garage/`), the server-rendered UI, and its tests. See
  `docs/architecture/platform.md`.
- `misc/xen-vms/` — the Xen configs the Makefile writes and `sandboxd` reads:
  `platform.cfg` (the PVH domain the web tier runs in), the golden guests'
  `ubuntu.cfg` / `windows.cfg`, their `*_sandbox.cfg` clone templates, and
  `autounattend.xml`. A second set, `misc/*.cfg`, is where
  `scripts/gen-xen-configs.py` writes the CPU partition; the two disagree, and
  reconciling them is an open item (`docs/runbooks/18-deploy-with-makefile.md`,
  "Open questions").
- `evasion-tests/` — the RDTSC and al-khaser searches: do the guests give the
  sandbox away under DRAKVUF, and which Xen build hides it best. Run from a
  second machine, because they reboot Dom0. See below, and
  `evasion-tests/README.md`.
- `scripts/` — repository tooling: the suite-enforced generators
  (`gen-current-state.py`, `gen-doc-index.py`, `gen-xen-configs.py`),
  `check-refs.py`, `check-secrets.sh`, `xen-identity.py` (the guests'
  hardware identity, used by `make xen` and the guest targets) and
  `windows-symbol-profiles.py`.
- `profiles/` — LibVMI/DRAKVUF kernel profiles: `linux.json`, `windows.json`
  and the Windows DLL profiles, written by `make setup_hooks_*`. **Not
  git-tracked**: tens of MB of `dwarf2json`/`pdbconv` output per kernel build.
  `profiles/README.md`.
- `state/` — Xen `xl save` memory images for the sandbox templates, named after
  the origin domain, plus `xen-identity.json` and `firmware/`, this
  deployment's hardware identity. **None git-tracked.** Back them up: the
  identity is drawn at random on the first `make xen` and cannot be recovered.
- `docs/INDEX.md` — generated index of every heading in `docs/`, as
  `path:line — heading`. Start here when looking for where a topic is covered.
- `docs/CURRENT-STATE.md` — what the lab actually is right now, with a
  confirmed date per fact and a superseded-facts table. **Read before asserting
  any deployment fact.**
- `docs/roadmap/` — milestones, dependency graph, risk register, architecture
  decisions still needing experiments.
- `docs/architecture/` — the analysis pipeline, the platform, networking, the
  live console, result schema, upstream-DRAKVUF strategy, licensing.
- `docs/checklists/` — per-OS implementation checklists with execution
  evidence. These track what has been done, distinct from the roadmap.
- `docs/runbooks/` — dated execution transcripts from real Dom0 work, numbered
  oldest to newest. Append-only evidence: annotate, never edit in place.
  **01–10 describe the nested Proxmox lab** that was erased on 2026-08-28.
- `docs/reviews/` — dated whole-project assessments.
- `docs/workflow-ci.md` — the CI design: a GitHub-hosted static tier
  (implemented, `.github/workflows/static-checks.yml`) and a self-hosted Xen
  integration tier (DRAFT-026b, not implemented).
- `docs/Project-definition.txt`,
  `docs/drakvuf-on-xen-nested-within-proxmox.md`, `docs/android_setup.md` —
  the original infrastructure setup guides. Historical provenance, kept
  verbatim and not synced with later renames or fixes — see `CLAUDE.md`.
- `.github/issue-drafts/` — locally-drafted GitHub issues, reviewed before
  anything is published with `gh`.

## Development lifecycle

This project uses a `PLAN → CREATE → TEST → DEPLOY` lifecycle with human
review gates. See `CONTRIBUTING.md`.

## Testing

```bash
bash -n SCRIPT       # shell scripts
dash -n SCRIPT       # they execute under dash in production — see CLAUDE.md
shellcheck SCRIPT
make -n TARGET       # the Makefile: expands a recipe without running it

platform/.venv/bin/python -m pytest sandboxd/tests -q   # sandboxd; needs no infrastructure
scripts/dev-services.sh                                  # bring up Postgres + MinIO locally
cd platform && .venv/bin/python -m pytest -q             # platform; needs both
```

The Makefile's targets run only on Dom0, so `make -n` is all a development
container can do with them. Running them for real, in order, with what to
expect from each, is `docs/runbooks/18-deploy-with-makefile.md`, run top to
bottom on 2026-11-04.

**Never run the platform suite against the deployment.** Its `conn` fixture
truncates the jobs table. `TEST_DATABASE_URL` defaults to
`sandbox_platform_test`, which is why it is safe in a development container and
destructive anywhere else.

`shellcheck` exits 0 as of DRAFT-031 (2026-08-11) — run it bare, without a
severity flag, since it reads `.shellcheckrc` automatically and that is the
command CI runs. The baseline disables **one** code (SC1091) over one file,
recorded in `.shellcheckrc` with the issue that owns removing it. SC2086 and
SC2009 were retired on 2026-09-15 with the scripts that carried their findings,
so both are live again — read that file before reading a clean run as clean
code.

`dash -n` matters as much as `bash -n`: `automation/network-setup.sh` declares
`#!/bin/sh` and is interpreted by `dash` in production, so `bash -n` alone
accepts bashisms that fail silently there. The `evasion-tests/` scripts are
bash and say so.

## Infrastructure boundary

Commands targeting Xen, LVM, OVS, the Android sandbox, or malware samples
must be presented for manual execution on the real Xen Dom0 host — they are
never assumed runnable in a generic development environment. See
`CLAUDE.md` for the full list of commands this applies to and the current
Ubuntu/Android naming conventions.

## Working with Claude Code on this repo

This project is developed with Claude Code. `CLAUDE.md` carries the
project-specific rules; see Anthropic's
[Claude Code best practices](https://code.claude.com/docs/en/best-practices)
for general guidance on the tool itself.


## Evasion tests — RDTSC and al-khaser

`evasion-tests/` holds two searches that run a detection program inside the
analysis guests while DRAKVUF traces them, and record whether it found the
sandbox. `rdtsc_search.sh` runs `detector.c` in the Ubuntu guest: a red pill,
`sidt; rdtsc; sidt; rdtsc`, detected when the two reads are more than 100
cycles apart, which is the test Xen's RDTSC compensation was built and
measured against. `alkhaser_search.sh` runs
[al-khaser](https://github.com/ayoubfaouzi/al-khaser) in the Windows guest with
a patch that gives every check a code, so the trace names each detection.
Each search walks a list of Xen **variants**, values for the compensation's
`#define`s, and for each one builds and installs that Xen on Dom0, reboots
into it, runs the tests, and puts Dom0 back as `make xen` left it when it
ends.

`evasion-tests/README.md` is the procedure. `docs/architecture/rdtsc-poc.md`
is what the compensation does, its known gaps, and how to operate it;
`docs/architecture/guest-identity.md` is what al-khaser measured.

**What `make xen` already gives you.** Xen boots with `rdtsc-poc=1` and
`xen-rdtsc-poc.service` turns the compensation on once per boot. Check it:
`xl dmesg | grep RDTSC_POC` must show `compensation enabled`. The unit fails
otherwise, and `sandboxd` warns at startup when the boot line asks for it and
the line is missing.

**What the searches need beyond the install above:**

- **A second machine.** They reboot Dom0 twice per variant and run for hours;
  run them in `tmux` there, with root ssh to Dom0 by key. The platform DomU is
  down while they run.
- `make xen` and `make sandboxd` run **from Dom0's checkout**, the guests
  installed and saved, and **the same commit on both checkouts**: the search
  compares the Xen patch and the `drakvuf` submodule and refuses to run on a
  difference.
- `/boot` on a plain partition: `grub-probe --target=abstraction
  /boot/grub/grubenv` on Dom0 must print nothing.
- **`sandboxd` stopped.** Two orchestrators never share a host, and every
  reboot would kill its clones. The search checks with `fuser`, from
  `psmisc`, which `make sandboxd` installs; it refuses to start without it.
- Host values in `evasion-tests/site.conf`, untracked; copy
  `site.conf.example` and fill it in. Point `REMOTE_OUT_BASE` at a disk with
  room: an al-khaser test writes tens of GB.
- For al-khaser: LLVM and [xwin](https://github.com/Jake-Shadle/xwin) on your
  machine to cross-build it, which means accepting Microsoft's SDK license.

**First run**, in this order; `docs/runbooks/18-deploy-with-makefile.md` §7
records it, with a `baseline` pass on 2026-11-04:

```bash
# DOM0 (Xen), as root
#   1. prove Dom0 boots both ways unattended         -- evasion-tests/README.md §7.7
#   2. one Xen cfg per test VM, onto thin snapshots    -- §3.2. NEVER restore onto the golden volume
#   3. one benchmark by hand, 30 s of DRAKVUF           -- §3.5 step 2
cd /root/drakvuf-multios-sandbox/evasion-tests &&
GUEST=linux CFG=/root/evasion-tests/ubuntu_test1.cfg CLONE_NAME=ubuntu_sandbox-test1 \
    CONFIGS=dev-syscalls DRAKVUF_TIMEOUT=30 ./benchmark_drakvuf.sh

# YOUR MACHINE, in evasion-tests/, in tmux. Reboots Dom0 twice
TESTS=1 ONLY=baseline ./rdtsc_search.sh
```

Results land in `<RESULTS_BASE>/rdtsc-search/<timestamp>/`: `results.csv`
(one row per run: `pass`, `fail`, `unstable`, `none`), `ranking.txt`,
`WINNERS.txt`. The full DRAKVUF logs stay on Dom0 under `REMOTE_OUT_BASE`.

**The limits are in TSC cycles.** `RDTSC_USER_CLOSE` and
`RDTSC_USER_LAG_MAX` were measured at about 3 GHz. On a CPU with a clearly
different TSC rate (`xl info | grep cpu_mhz`), scale both and test around them;
`evasion-tests/README.md` §7 is about adapting the rest to other hardware.
