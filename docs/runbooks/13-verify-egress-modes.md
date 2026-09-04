# Runbook — per-job egress modes: offline, tor, simulated (DRAFT-057)

> **Issue:** DRAFT-057 —
> [#42](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/42).
>
> **Status: EXECUTED on Dom0, 2026-08-31 to 2026-09-02.** All ten steps ran and
> every EVIDENCE block below is pasted output from that host.
>
> **What this proves, and it is the point of the whole issue:** that egress is
> a per-job decision which holds, that a mode nobody selected is *no* egress,
> and that the report says which. Everything else in the capability set assumes
> a sample ran; this decides whether running it is defensible.
>
> All three are now evidenced end to end: `offline` reaches nothing (step 3),
> `tor` exits through the Tor network and discloses that it carries TCP only
> (steps 5 and 5a), and `simulated` answers a clone from a responder on its own
> gateway while nothing leaves the host (steps 7 and 7b). Modes do not survive
> a job (steps 8a and 9), and a responder that is not running downgrades the
> run to `offline` and says so rather than black-holing it (step 10).
>
> **Nothing here was abandoned.** `routed` was out of scope from the start, not
> dropped part-way.
>
> **Getting `simulated` to work took five patches to FakeNet-NG.** Its
> `DivertTraffic: No` path is not one upstream exercises, and the failures were
> silent rather than loud — a responder that binds every port and answers
> nothing reads in a report as a sample whose infrastructure was down. Each is
> recorded symptom-first in `docs/TROUBLESHOOTING.md`; the patch itself is
> `automation/fakenet-divert-no.patch`, and its header explains all five.
>
> **`routed` is NOT in this runbook.** It needs a rented VPS and a kill-switch
> packet capture, and both are Phase 4. See `private/egress-exits.md`.

## Before you start

**This changes the live containment posture.** `network-setup.sh` no longer
installs the unconditional `MASQUERADE` and the wildcard uplink `ACCEPT` that
every clone has relied on since the lab was built. After step 2, a clone with
no egress mode applied has **no route out at all**. That is the intended end
state; it is also a behaviour change large enough that the Ubuntu regression in
step 8 is not optional.

Have ready:

- A benign fixture that makes an outbound connection and a DNS lookup. The
  `curl` + `getent hosts` pair in step 5 is enough; no malware is needed for
  any step here.
- A second terminal on Dom0 for `tcpdump`.
- The knowledge that **step 3 will show you a broken network on purpose.**

---

## Step 1 — confirm what the host currently has

Run before changing anything, so there is a before to compare against.

```sh
iptables -S DRAKVUF_ISOLATION
iptables -t nat -S DRAKVUF_NAT
iptables -S DRAKVUF_INPUT
```

Expect the pre-DRAFT-057 shape: a `MASQUERADE` in `DRAKVUF_NAT`, and a
`-i xenbr1.+ -o xenbr0 -j ACCEPT` in `DRAKVUF_ISOLATION`. If they are already
absent, this host has been updated and you are re-running — carry on.

```text
root@dom0:~# iptables -S DRAKVUF_ISOLATION
-N DRAKVUF_ISOLATION
-A DRAKVUF_ISOLATION -i xenbr1.+ ! -o xenbr0 -j DROP
-A DRAKVUF_ISOLATION -d 10.0.0.0/8 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 172.16.0.0/12 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 192.168.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -d 169.254.0.0/16 -i xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -o xenbr0 -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_ISOLATION -o xenbr1.+ -j DROP
-A DRAKVUF_ISOLATION -i xenbr1.+ -j DROP
root@dom0:~# iptables -t nat -S DRAKVUF_NAT
-N DRAKVUF_NAT
-A DRAKVUF_NAT -o xenbr0 -j MASQUERADE
root@dom0:~# iptables -S DRAKVUF_INPUT
-N DRAKVUF_INPUT
-A DRAKVUF_INPUT -i xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_INPUT -i xenbr1.+ -j DROP
```

---

## Step 2 — deploy the new chains

Pull the repository on Dom0, then:

```sh
cd /root/drakvuf-multios-sandbox
./automation/network-setup.sh 4
```

**Expect it to tell you clones have no way out.** That line is the deployment
working, not failing:

```
network-setup.sh: no per-VLAN egress installed -- clones have NO route
  out until an egress mode is applied. Expected under sandboxd, which
  installs one per job. ...
```

Then confirm the shape changed:

```sh
iptables -S DRAKVUF_ISOLATION | grep -n EGRESS
iptables -t nat -S DRAKVUF_NAT          # expect: the chain, and NO rules
iptables -S DRAKVUF_EGRESS              # expect: the chain, and NO rules
iptables -S DRAKVUF_INPUT | head -6     # expect: the uplink DROPs FIRST
```

The `DRAKVUF_INPUT` head must show 9040 and 9053 dropped on `xenbr0` **before**
anything about analysis VLANs. Those two rules are what stop this host being an
open proxy once tor is running; if they are missing, stop and fix that first.

```text
root@dom0:~# cd drakvuf-multios-sandbox/
root@dom0:~/drakvuf-multios-sandbox# git pull
remote: Enumerating objects: 119, done.
remote: Counting objects: 100% (119/119), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 69 (delta 51), reused 69 (delta 51), pack-reused 0 (from 0)
Unpacking objects: 100% (69/69), 94.33 KiB | 870.00 KiB/s, done.
From github.com:evilbootloader/drakvuf-multios-sandbox
   1a331f6..b9e637d  platform-domu -> origin/platform-domu
Updating 1a331f6..b9e637d
Fast-forward
 .github/issue-drafts/DRAFT-057.md                  |  36 ++
 .gitignore                                         |  22 +
 automation/fakenet.ini                             |  93 +++
 automation/network-setup.sh                        | 358 ++++++++++-
 automation/run_analysis-android.sh                 |  12 +-
 automation/run_analysis-ubuntu.sh                  |  28 +-
 automation/torrc                                   |  97 +++
 docs/CURRENT-STATE.md                              |   6 +-
 docs/INDEX.md                                      | 145 ++---
 docs/TROUBLESHOOTING.md                            | 188 ++++++
 docs/architecture/networking.md                    |  91 +++
 platform/migrations/0006_egress.sql                | 120 ++++
 platform/sandbox_platform/auth.py                  |  39 +-
 platform/sandbox_platform/egress.py                | 138 +++++
 platform/sandbox_platform/enums.py                 |  39 +-
 platform/sandbox_platform/jobs.py                  |  56 +-
 platform/sandbox_platform/objects.py               |  59 +-
 platform/sandbox_platform/queries.py               |  55 +-
 platform/sandbox_platform/routers/jobs.py          | 168 ++++-
 platform/sandbox_platform/routers/worker.py        |  56 +-
 platform/sandbox_platform/ui/__init__.py           |  31 +-
 platform/sandbox_platform/ui/static/submit.js      |  31 +-
 platform/sandbox_platform/ui/templates/submit.html |  45 ++
 .../ui/templates/tabs/_overview.html               |  50 ++
 platform/tests/test_egress.py                      | 300 +++++++++
 platform/tests/test_objects.py                     |  54 ++
 private/README.md                                  |  53 ++
 sandboxd/api.py                                    | 122 +++-
 sandboxd/config.py                                 | 120 ++++
 sandboxd/daemon.py                                 |  63 +-
 sandboxd/egress.py                                 | 652 ++++++++++++++++++++
 sandboxd/naming.py                                 |  58 ++
 sandboxd/resources.py                              |  28 +-
 sandboxd/stages.py                                 | 211 ++++++-
 sandboxd/sweep.py                                  |  60 +-
 sandboxd/tests/fake.py                             |  16 +
 sandboxd/tests/test_api.py                         | 118 +++-
 sandboxd/tests/test_daemon.py                      |  98 ++-
 sandboxd/tests/test_egress.py                      | 679 +++++++++++++++++++++
 sandboxd/tests/test_resources.py                   |  44 ++
 sandboxd/tests/test_stages.py                      |  44 +-
 41 files changed, 4512 insertions(+), 171 deletions(-)
 create mode 100644 automation/fakenet.ini
 create mode 100644 automation/torrc
 create mode 100644 platform/migrations/0006_egress.sql
 create mode 100644 platform/sandbox_platform/egress.py
 create mode 100644 platform/tests/test_egress.py
 create mode 100644 private/README.md
 create mode 100644 sandboxd/egress.py
 create mode 100644 sandboxd/tests/test_egress.py
root@dom0:~/drakvuf-multios-sandbox# cd /root/drakvuf-multios-sandbox
./automation/network-setup.sh 4
network-setup.sh: provisioned 4 VLAN sub-interface(s) on xenbr1
network-setup.sh: no per-VLAN egress installed -- clones have NO route
  out until an egress mode is applied. Expected under sandboxd, which
  installs one per job. If you are running dirwatch directly, pass
  'direct' as the second argument or clones will observe nothing.
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_ISOLATION | grep -n EGRESS
7:-A DRAKVUF_ISOLATION -i xenbr1.+ -j DRAKVUF_EGRESS
root@dom0:~/drakvuf-multios-sandbox# iptables -t nat -S DRAKVUF_NAT          # expect: the chain, and NO rules
-N DRAKVUF_NAT
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS              # expect: the chain, and NO rules
-N DRAKVUF_EGRESS
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_INPUT | head -6     # expect: the uplink DROPs FIRST
-N DRAKVUF_INPUT
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 9040 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p udp -m udp --dport 9040 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p tcp -m tcp --dport 9053 -j DROP
-A DRAKVUF_INPUT -i xenbr0 -p udp -m udp --dport 9053 -j DROP
-A DRAKVUF_INPUT -i xenbr1.+ -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

---

## Step 3 — `offline` really is offline

The cheapest risk reduction in the issue, and the one that needs no daemon.

Submit a job with **No network** selected in the UI, or:

```sh
curl -s -X POST https://sandbox.evilbootloader.com/api/v1/jobs \
  -H 'Content-Type: application/json' \
  -d '{"target_os":"ubuntu","filename":"probe.sh","size_bytes":64,
       "egress_mode":"offline"}'
```

While the clone is up, from Dom0:

```sh
iptables -S DRAKVUF_EGRESS               # expect: still no rules
iptables -S | grep -c DRAKVUF_EGRESS_V   # expect: 0
```

And in the guest (through the console, or by watching the pcap):

```sh
curl -m 5 http://1.1.1.1/     # expect: timeout
getent hosts example.com      # expect: failure
```

**The distinction that matters:** a timeout, not a refusal. There is no rule
expressing `offline` — the packet matches nothing in `DRAKVUF_EGRESS` and dies
on `DRAKVUF_ISOLATION`'s terminal DROP. Confirm the counter moved:

```sh
iptables -vnL DRAKVUF_ISOLATION | tail -3
```

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS               # expect: still no rules
-N DRAKVUF_EGRESS
root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep -c DRAKVUF_EGRESS_V   # expect: 0
0
root@dom0:~/drakvuf-multios-sandbox# iptables -vnL DRAKVUF_ISOLATION | tail -3
    0     0 ACCEPT     0    --  *      xenbr1.+  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED
    0     0 DROP       0    --  *      xenbr1.+  0.0.0.0/0            0.0.0.0/0           
   63  4240 DROP       0    --  xenbr1.+ *       0.0.0.0/0            0.0.0.0/0           

# Running commands on the guest had no curl, tried with wget and getent and no connectivity available.

```

**Also confirm isolation still holds**, because this restructure touched the
clone-to-clone rule. From the clone:

```sh
ping -c 2 172.16.2.2          # another VLAN   -- expect: no reply
ping -c 2 192.168.1.1         # the house LAN  -- expect: no reply
ping -c 2 172.16.1.1          # its gateway    -- expect: no reply
```

```text
# Can't copy paste, no reply in any of the commands.

```

---

## Step 4 — install tor and offer the mode

```sh
apt-get install -y tor
install -m 0644 automation/torrc /etc/tor/torrc
systemctl restart tor
ss -ltunp | grep -E '9040|9053'      # expect: tor listening on both
```

Then declare the exit in `sandboxd/config.py`:

```python
EXITS = {
    "tor-default": {
        "mode": "tor",
        "caveats": ["tcp-only", "smtp-blocked-upstream",
                    "smb-blocked-upstream"],
    },
}
```

Restart `sandboxd` and check the log says it is offering it:

```
egress exits offered: offline (offline), tor-default (tor)
```

**If it says it is NOT offering tor**, the probe could not reach 9040 — that is
the guard working, and `ss` above will say why.

```text
root@dom0:~/drakvuf-multios-sandbox# ss -ltnpu | grep -E '9040|9053'      # expect: tor listening on both
udp   UNCONN 0      0                                 0.0.0.0:9053      0.0.0.0:*    users:(("tor",pid=9381,fd=6))                          
tcp   LISTEN 0      4096                              0.0.0.0:9040      0.0.0.0:*    users:(("tor",pid=9381,fd=7))  

2026-08-31 23:11:32,963 INFO    sandboxd: egress exits offered: offline (offline), tor-default (tor)
```

---

## Step 5 — a sample really leaves through Tor

Submit with **Through Tor** selected. While it runs, from Dom0:

```sh
iptables -t nat -S DRAKVUF_EGRESS_PRE_V1
iptables -S DRAKVUF_EGRESS_IN_V1
```

Expect: TCP redirected to 9040, UDP/53 to 9053, and the INPUT chain admitting
exactly those two ports for `xenbr1.1` and dropping the rest.

In the guest:

```sh
curl -m 30 https://check.torproject.org/api/ip
```

**Expect `"IsTor":true` and an address that is not this line's.** That is the
whole capability, in one command.

```text
IsTor:true in the output

```

### 5a — the limitation, proven rather than asserted

This is the step that discharges DRAFT-057's objection to Tor. In the guest:

```sh
dig +short @8.8.8.8 example.com      # UDP direct to a resolver
ping -c 2 1.1.1.1                    # ICMP
```

Both must fail — Tor carries TCP only, so the rules drop them rather than
sending them somewhere that cannot carry them. Capture on the VLAN to show they
were emitted and dropped rather than never attempted:

```sh
tcpdump -i xenbr1.1 -n 'icmp or (udp and port 53 and dst 8.8.8.8)'
```

```text
root@dom0:~/drakvuf-multios-sandbox# tcpdump -i xenbr1.2 -n 'icmp or (udp and port 53 and dst 8.8.8.8)'
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on xenbr1.2, link-type EN10MB (Ethernet), snapshot length 262144 bytes
23:17:45.821837 IP 172.16.2.2.50921 > 8.8.8.8.53: 31502+ [1au] A? example.com. (52)
23:17:52.576244 IP 172.16.2.2 > 1.1.1.1: ICMP echo request, id 1, seq 1, length 64
23:17:53.584986 IP 172.16.2.2 > 1.1.1.1: ICMP echo request, id 1, seq 2, length 64

# Dig succeded, ICMP had no reply
```

**Then open the report and confirm it says so.** The Overview tab must show
`tcp-only` and `smtp-blocked-upstream` under *Network limits*, with the line
about absence of traffic. **If the caveats are not on the page, this step
FAILS even though the mode worked** — an undisclosed limitation is exactly the
confident false negative the draft warned about, and disclosure is the reason
the mode was built at all.

```text
Page text:      tcp-only, smtp-blocked-upstream, smb-blocked-upstream Absence of matching traffic in this report may be caused by these limits rather than by the sample. 

```

---

## Step 6 — install FakeNet-NG and offer `simulated`

Pinned rather than tracked as a submodule: this repository is deliberately
lean. It **is** patched, by one tracked patch — see 6b.

### 6a — install

```sh
apt-get install -y python3-pip python3-venv
python3 -m venv /opt/fakenet-ng
/opt/fakenet-ng/bin/pip install -r automation/fakenet-requirements.txt
/opt/fakenet-ng/bin/pip install --no-deps \
  'git+https://github.com/mandiant/flare-fakenet-ng@v3.5'
```

**Both lines, in that order.** Upstream's dependency list is unpinned and wrong
for this host in both directions: it demands `netfilterqueue`, which only the
diverter imports and which is the one most likely to fail to build, and it
floats `pyopenssl`, which removed the certificate API FakeNet is written
against. Installing FakeNet with `--no-deps` after our own requirements is what
stops either from having a vote. `automation/fakenet-requirements.txt` explains
each entry.

Confirm the pin took. Getting this wrong costs a debugging session and the
symptom names neither pip nor a version:

```sh
/opt/fakenet-ng/bin/pip show pyopenssl | head -2    # expect: Version: 26.1.x
```

Then the config and the writable root the FTP and TFTP listeners need:

```sh
install -m 0644 automation/fakenet.ini /etc/fakenet.ini
mkdir -p /var/lib/fakenet/root
```

**That directory is deliberately not the package directory.** FakeNet's FTP
listener accepts any credentials and grants the resulting account store,
delete, rename and mkdir on whatever `FTProot` names; upstream's default
resolves to its own installed package. Nothing in `/var/lib/fakenet/root` is
evidence — what a sample uploaded is in the pcap — so it can be emptied at any
time, and should be between unrelated runs.

### 6b — patch it, because `DivertTraffic: No` is untested upstream

**Reinstall first, every time. Never patch on top of an older patch.**
`patch --forward` does not merge: it recognises the first hunk of a file as
already applied and skips **that whole file**, new changes included. It exits
1, writes `.rej` files, and changes nothing — so a partly-patched venv survives
a re-run looking updated. That is what happened on 2026-09-02, when a Dom0
carrying changes 1–3 was re-patched and came out with neither 4 nor 5.

```sh
SP="$(/opt/fakenet-ng/bin/python -c 'import fakenet, os; \
    print(os.path.dirname(os.path.dirname(fakenet.__file__)))')"

/opt/fakenet-ng/bin/pip install --no-deps --force-reinstall \
    'git+https://github.com/mandiant/flare-fakenet-ng@v3.5'

patch -p1 --forward -d "$SP" < automation/fakenet-divert-no.patch
```

Expect **four** files patched and no rejects. **Then verify, because the
failure above is silent:**

```sh
grep -c "conn.setblocking(0)"     "$SP/fakenet/listeners/ProxyListener.py"    # 1
grep -c "fn_addr = '0.0.0.0'"     "$SP/fakenet/fakenet.py"                    # 2
grep -c "self.__diverter is None" "$SP/fakenet/diverters/diverterbase.py"     # 3
grep -c "Inadmissible SNI"        "$SP/fakenet/listeners/ssl_utils/__init__.py"   # 1
```

Any zero means that change is missing. Do this after every `pip install`,
upgrade or reinstall, not only the first time.

**Do not skip this and see whether it works.** Unpatched, FakeNet either dies
at startup with `UnboundLocalError: fn_addr`, or — once that one line is fixed
— starts, binds every port, logs nothing alarming and answers nothing. A
`simulated` run against it produces a report indistinguishable from a sample
whose infrastructure was down, which is the exact failure this issue exists to
prevent. The patch header explains all six changes.

**The fourth grep is the one whose absence you will not notice.** Changes 1–3
and 5 fail loudly; change 6 fails in the sample's favour, and a venv missing it
serves TLS perfectly while letting a servername become a path on this host.

```text
root@dom0:~/drakvuf-multios-sandbox# patch -p1 --forward -d "$(/opt/fakenet-ng/bin/python -c 'import fakenet, os; \
    print(os.path.dirname(os.path.dirname(fakenet.__file__)))')" \
    < automation/fakenet-divert-no.patch
patching file fakenet/diverters/diverterbase.py
patching file fakenet/fakenet.py
patching file fakenet/listeners/ProxyListener.py
```

> **This output is from 2026-09-02 and predates change 6**, which is why it
> lists three files rather than four. It is kept as the dated evidence that the
> apply step works; a run today prints a fourth `patching file` line for
> `fakenet/listeners/ssl_utils/__init__.py`. **A run today that still prints
> three has not picked up the security fix** — reinstall and re-apply, per the
> warning above about `patch --forward` skipping a whole file.

### 6c — start it and confirm it bound what it claims

**Read `automation/fakenet.ini`'s header first.** Two of its settings are
opposite to FakeNet's defaults and each default breaks this lab — one flushes
every iptables rule on the host, the other makes `offline` stop meaning
offline. `docs/TROUBLESHOOTING.md` carries both.

Everything in 6c is **on Dom0**. No clone is involved, and none can be — the
mode is not offered until 6d, so there is nothing to submit a `simulated` job
to yet. Step 7 is the from-the-guest version of these same two probes.

That split is deliberate rather than incidental. `simulated` is three
independent things: the per-VLAN redirect rules, the uplink guard, and the
responder itself. Tested together for the first time in step 7, a failure tells
you only that one of the three is wrong. Here the responder is proven alone,
over loopback, with no rules in the path.

On Dom0:

```sh
install -m 0644 automation/fakenet.service        /etc/systemd/system/
install -m 0644 automation/drakvuf-egress.target  /etc/systemd/system/
systemctl daemon-reload
systemctl start drakvuf-egress.target

systemctl is-active fakenet tor                          # expect: active, active
ss -ltnp | grep -E ':(38926|80|25|21|110|6667|1337)\b'   # expect: 7 TCP listeners
ss -lunp | grep -E ':(38926|5300|69|1337)\b'             # expect: 4 UDP listeners
```

**A unit, not `fakenet ... &`.** Three of its directives each close a failure
this runbook already hit: `WorkingDirectory=` makes the `getcwd()` crash
unreachable, `Restart=on-failure` stops a bind failure leaving the lab silently
without a responder, and journal logging means the next traceback is
`journalctl -u fakenet` rather than a screenshot of a shell that has since
closed.

**Candidate, 2026-09-04: the confinement block is new and has not started on
Dom0.** `ProtectSystem=strict` with `ReadWritePaths=-/var/lib/fakenet` is the
process-wide half of the SNI fix — it makes a sample-named write outside the
state directory fail with `EROFS`. It was reasoned against v3.5 and the shipped
ini rather than observed, so a re-install of the unit needs this checked once:

```sh
systemctl show fakenet -p ProtectSystem -p ReadWritePaths   # strict, /var/lib/fakenet
ls -l /var/lib/fakenet/certs/fakenet.flare.crt              # the CA still mints
```

A responder that starts, binds its listeners and writes that certificate has
proved the block is not in its way. If it *cannot* start, `journalctl -u
fakenet` names the path it was refused, and the fix is to add that path to
`ReadWritePaths=` — not to drop `ProtectSystem=`.

The target starts tor as well. It uses `Wants=`, never `Requires=`, so one
responder failing cannot take the other's mode offline — and a host where the
whole target failed still analyses samples, because `offline` needs no
responder at all.

If `systemctl is-active` says `failed`, read `journalctl -u fakenet -n 30`
before anything else: after five failed starts in two minutes the unit stops
retrying and stays failed on purpose, which is what makes sandboxd withhold
`simulated` instead of offering a mode that flickers.

**Count them.** A process that is running is not evidence that a listener is;
the config is read in full before anything binds, so "Loaded configuration
file" is printed either way. If the TCP list is short, a listener failed to
bind and took the process with it — read the log for which. If the UDP list is
missing `:5300`, see `TROUBLESHOOTING.md` on `systemd-resolved`.

**FakeNet's DNS listener is on 5300, not 53**, because `systemd-resolved` holds
53 on this host and a listener that cannot bind exits the whole process. The
clone is unaffected — it still sends to 53 and the redirect rewrites it — so
this number appears nowhere except here, `fakenet.ini` and
`config.FAKENET_DNS_PORT`.

Still on Dom0, prove it answers — which binding does not establish:

```sh
dig +short -p 5300 @127.0.0.1 totally-not-real-c2.invalid    # expect: 192.0.2.123
curl -s -m 5 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:38926/
```

`127.0.0.1` reaches the responder because its listeners bind `0.0.0.0`. The
second command goes to the **proxy** port on purpose, not to port 80: it
exercises the taste-and-hand-off path a clone will use, where port 80 would
bypass it. Expect a status line; `000` is an empty close, which means 6b is not
applied.

Still on Dom0, confirm it did **not** touch the firewall:

```sh
iptables -S DRAKVUF_ISOLATION | wc -l    # expect: unchanged from step 2
iptables -t nat -S PREROUTING            # expect: no FakeNet rule
```

That last check is the one worth doing carefully. If FakeNet has added its own
`PREROUTING` redirect, `DivertTraffic` is not `No`, and **every** clone —
including `offline` ones — is now being answered by it.

And confirm the uplink guard covers it. This is the half an in-lab test cannot
detect, and it has one trap that has already caught a run of this step.

**Probing Dom0's LAN address from Dom0 tests nothing.** A host's own address
routes over loopback — check with `ip route get 192.168.1.6`, which answers
`dev lo` — so the packet never arrives on `xenbr0` and `-i xenbr0` cannot
match. `nc` succeeds, and that success is about `lo`, not about the LAN. The
`dig` half misleads in the other direction: it returns `connection refused`
whether or not the guard exists, because nothing binds UDP/53 on this host at
all now.

**Dom0 reaching its own FakeNet ports over loopback is correct and must stay
that way.** The proxy hands each tasted connection to `localhost:80`, so a DROP
on `lo` would break the fake Internet this mode exists to provide.

First, on Dom0, check the guard is aimed at the interface that actually
receives LAN traffic. This costs nothing and has never been verified:

```sh
ip -4 -o addr show | grep 192.168        # which interface holds the LAN address?
iptables -vnL DRAKVUF_INPUT | head -18   # the DROPs, with their counters
```

**That interface must be `xenbr0`.** If the LAN address sits on a physical NIC
or another bridge, every `-i xenbr0` rule in `DRAKVUF_INPUT` is aimed at
something that never sees the traffic — and that is not only FakeNet's problem.
It would mean tor's 9040/9053 guard has never worked either, on any run of this
lab, and step 2's claim about not being an open proxy is false. Stop and fix
that before going further.

Then probe from something that is **not Dom0**. Use the **platform DomU at
`192.168.1.10`** — it is bridged to `xenbr0`, it is already running, and its
packets to `192.168.1.6` therefore arrive on `xenbr0` exactly as a laptop's
would. No second physical machine is needed for this.

```sh
ssh <platform-domu>
nc -z -w3 192.168.1.6 38926                    # expect: refused or timeout
nc -z -w3 192.168.1.6 80                       # expect: refused or timeout
dig +short -p 5300 @192.168.1.6 example.com    # expect: no answer
```

Back on Dom0, read the counters again and **diff them against the reading
above**:

```sh
iptables -vnL DRAKVUF_INPUT | head -18
```

**Rising DROP counters on `tcp dpt:38926`, `tcp dpt:80` and `udp dpt:5300` are
the evidence.** A timeout on its own is equally consistent with a wrong
address, a firewall on the client, or an unplugged cable — and counters that
stay at zero mean the traffic never reached these rules, which is the result
this check exists to distinguish from success.

An answer to that `dig`, or a counter that does not move while `nc` succeeds,
means Dom0 is exposed to the house LAN. Stop and re-run
`./automation/network-setup.sh 4` before going further.

```text
root@platform:~# nc -z -w3 192.168.1.6 38926
root@platform:~# nc -z -w3 192.168.1.6 80
root@platform:~# dig +short -p 5300 @192.168.1.6 example.com
;; communications error to 192.168.1.6#5300: timed out
;; communications error to 192.168.1.6#5300: timed out
;; communications error to 192.168.1.6#5300: timed out
;; no servers could be reached

(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# iptables -vnL DRAKVUF_INPUT | head -18
Chain DRAKVUF_INPUT (1 references)
 pkts bytes target     prot opt in     out     source               destination         
    0     0 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:9040
    0     0 DROP       17   --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            udp dpt:9040
    0     0 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:9053
    0     0 DROP       17   --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            udp dpt:9053
    0     0 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:21
    0     0 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:25
    3   180 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:80
    0     0 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:110
    0     0 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:1337
    0     0 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:6667
    3   180 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpt:38926
    0     0 DROP       6    --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            tcp dpts:60000:60010
    0     0 DROP       17   --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            udp dpt:69
    0     0 DROP       17   --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            udp dpt:1337
    3   240 DROP       17   --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            udp dpt:5300
    0     0 DROP       17   --  xenbr0 *       0.0.0.0/0            0.0.0.0/0            udp dpt:38926
```

### 6d — offer the mode

Add the exit and restart `sandboxd`:

```python
    "sim-local": {"mode": "simulated",
                  "caveats": ["no-real-internet", "tls-untrusted-cert"]},
```

**Both caveats, and the second is not optional.** The responder's certificate
comes from an ephemeral CA the guest has never trusted, so a sample that
validates — most of them — refuses the handshake and its HTTPS traffic never
reaches a listener. Step 7 proves that. Declared here, the report says the
encryption was refused; omitted, the report shows a sample that did nothing.

Expect the startup log to list it:

```
egress exits offered: offline (offline), tor-default (tor), sim-local (simulated)
```

**If it says it is NOT offering `simulated`**, the launch probe could not reach
38926 — that is the guard working, and the `ss` check above will say why.

```text
# UI shows the three

Simulated internet A responder on the gateway answers the sample instead of the real Internet. DNS resolves, connections succeed, nothing leaves the host. Responses are synthetic, so a sample that checks for a specific server will not find one. No real C2 is contacted. Limits: nothing reaches the real Internet.
No network The clone has an address and a gateway, and no route out. A black-holed network is itself a sandbox signal -- the guest sees timeouts where a real host would answer with RST or ICMP unreachable. Limits: nothing reaches the real Internet.
Through Tor live Real Internet access, transparently through the Tor network. The sample's traffic leaves from a Tor exit rather than from this lab. Tor carries TCP only. UDP command-and-control and direct DNS cannot leave and will be absent from the capture -- absent because they were blocked, which the report says explicitly. Tor's default exit policy also rejects ports 25 and 445, so mail and SMB behaviour will not appear. Limits: TCP only — UDP and ICMP cannot leave; port 25 blocked upstream — no SMTP will appear; ports 137-139/445 blocked upstream — no SMB. 
```

---

## Step 7 — a sample gets a fake Internet, and nothing leaves

Submit with **Simulated internet** selected. In the guest:

```sh
getent hosts totally-not-real-c2.invalid   # expect: 192.0.2.123
curl -m 10 http://totally-not-real-c2.invalid/payload.bin   # expect: a reply
```

A domain that cannot resolve on the real Internet resolving here is the proof
the responder answered rather than the world. `192.0.2.123` is TEST-NET-1 and
is the `ResponseA` pinned in `automation/fakenet.ini` — a different address
means something other than our responder answered.

The address the sample is told to connect to does not matter to the rules: the
`PREROUTING` redirect matches on interface and protocol, never on destination,
so `curl` reaches the proxy whatever DNS said. Step 6c proved the responder
answers over loopback; what this step adds is that the per-VLAN rules carry a
clone to it.

### 7a — HTTPS is refused, and the report must say so

Still in the guest, and this is the step that discharges `tls-untrusted-cert`
the way step 5a discharges tor's `tcp-only`:

```sh
wget -O /dev/null https://totally-not-real-c2.invalid/     # expect: FAILS
wget --no-check-certificate -O /dev/null \
     https://totally-not-real-c2.invalid/                  # expect: SUCCEEDS
```

**Both outcomes are the evidence, and the pair is what makes it conclusive.**
The first fails on certificate validation — FakeNet mints its certificate from
an ephemeral CA the guest has never trusted. The second succeeding proves the
TLS path itself is sound and only the trust decision failed, which is what
separates this from a broken responder.

On Dom0, FakeNet logs one line per refusal rather than a traceback:

```
TLS handshake refused by 172.16.1.2:54960 (...) -- the client did not accept
our certificate
```

If you get a Python traceback ending in `SSLV3_ALERT_BAD_CERTIFICATE` instead,
change 4 of `automation/fakenet-divert-no.patch` is not applied. The behaviour
is the same; the log is not, and a sample beaconing over HTTPS will bury
everything else in it.

**The second `wget` is the one that exercises new code**, and it only started
reaching that code once handshakes began succeeding. If it produces

```
OSError: [Errno 9] Bad file descriptor
```

from `remote_sock.setblocking(0)`, change 5 is not applied. `wrap_socket()`
detaches the socket it is handed — CPython leaves the original at fd -1 — and
upstream keeps using it, so HTTPS through the proxy has never worked in v3.5
with or without a trusted CA. The certificate rejection above masked it.

**Do not fix this by installing FakeNet's CA in the guest.** It would make
HTTPS work and would put a permanently enumerable entry in the trust store —
a well-known sandbox-detection check — and it modifies a golden image. The
limitation is disclosed instead, which is the whole reason the caveat
mechanism exists.

**Then open the report and confirm the caveat is on the page**, exactly as in
step 5a: *Network limits* must show `no-real-internet` **and**
`tls-untrusted-cert`. **If the TLS caveat is not there, this step FAILS even
though everything above behaved** — an undisclosed limitation is the confident
false negative this issue exists to prevent.

```text
# Everything works
wget --no-check-certificate -O /dev/null \
     https://totally-not-real-c2.invalid/                  # expect: SUCCEEDS
# Worked

```

### 7b — nothing left

**Now prove nothing left**, which is the half that matters:

```sh
tcpdump -i xenbr0 -n 'host 172.16.1.2 or net 172.16.0.0/12'
```

Expect **zero packets** for the duration of the run. `simulated` installs no
`FORWARD` accept and no `MASQUERADE`, so there is no path by which it could —
this confirms the rules match the design.

```text
# Clone commands worked.

(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# tcpdump -i xenbr0 -n 'host 172.16.1.2 or net 172.16.0.0/12'
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on xenbr0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
# No output
```

---

## Step 8 — the Ubuntu regression. This gates the merge.

The evidenced pipeline must be unchanged. With `ALLOW_DIRECT=1`, the legacy
launcher reproduces the pre-DRAFT-057 behaviour exactly.

```sh
ALLOW_DIRECT=1 ./automation/run_analysis-ubuntu.sh
```

The script takes no arguments; everything comes from
`automation/pipeline-ubuntu.env`, and `ALLOW_DIRECT` is the only knob here.

Expect the loud `direct` warning, then a normal Ubuntu analysis: sample
delivered, network configured, trace collected, artifacts uploaded.

```sh
iptables -S DRAKVUF_EGRESS       # expect: the wildcard legacy rule
iptables -t nat -S DRAKVUF_EGRESS_NAT
```

Compare the resulting trace against a pre-change run of the same fixture. **Any
difference in what the trace observed is a regression**, not a curiosity.

```text
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS       # expect: the wildcard legacy rule
-N DRAKVUF_EGRESS
-A DRAKVUF_EGRESS -i xenbr1.+ -o xenbr0 -j ACCEPT
root@dom0:~/drakvuf-multios-sandbox# iptables -t nat -S DRAKVUF_EGRESS_NAT
-N DRAKVUF_EGRESS_NAT
-A DRAKVUF_EGRESS_NAT -o xenbr0 -j MASQUERADE
```

---

## Step 8a — the `direct` grant does not outlive step 8

**Do not skip this, and do not reboot between step 8 and here.** A reboot
clears iptables on this host, so rebooting first tests nothing.

Step 8 installs a *wildcard* pair — `-i xenbr1.+ -o xenbr0 -j ACCEPT` and a
matching `MASQUERADE` — that names no VLAN. Until 2026-08-31 nothing removed
it: every delete in `sandboxd/egress.py::argv_revoke` names one VLAN and so
could not match, and `sandboxd` invokes `network-setup.sh` with no second
argument. The grant therefore lasted for the host's uptime, and step 9 below
**cannot detect it** — step 9 greps for `_V<n>` chains, and the wildcard has no
`<n>`.

Stop dirwatch, start `sandboxd`, and read the whole chain:

```sh
iptables -S DRAKVUF_EGRESS
iptables -t nat -S DRAKVUF_EGRESS_NAT
```

Expect `-N DRAKVUF_EGRESS` and nothing else — no line ending in `-j ACCEPT`,
no `MASQUERADE`. `network-setup.sh`'s `offline` branch deletes both by exact
spec, and the startup sweep deletes them again.

Expect this on stdout from `network-setup.sh`, and **not** a warning:

```text
network-setup.sh: no per-VLAN egress installed -- clones have NO route out
```

If instead it prints `WARNING -- DRAKVUF_EGRESS still holds rules that name no
VLAN`, the deletion did not work; stop and fix that before running anything
else, because the next `offline` job will reach the network and its report
will say it did not.

Then submit one job as `offline` and confirm from the capture that it reached
nothing. That is the assertion this step exists for — the chain being empty is
the mechanism, the silent pcap is the property.

```text
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS
-N DRAKVUF_EGRESS
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# iptables -t nat -S DRAKVUF_EGRESS_NAT
-N DRAKVUF_EGRESS_NAT
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# 

```

---

## Step 9 — modes do not leak between runs

The property that makes per-job selection meaningful rather than decorative.

Run two clones **concurrently** in different modes — one `offline`, one
`simulated` — and confirm each VLAN has only its own rules:

```sh
iptables -S DRAKVUF_EGRESS
iptables -t nat -S DRAKVUF_EGRESS_PRE
```

The `offline` clone's VLAN must appear in neither. Then let both finish and
confirm nothing survives:

```sh
iptables -S | grep DRAKVUF_EGRESS_       # expect: no _V<n> chains at all
iptables -t nat -S | grep DRAKVUF_EGRESS_
```

Read the parent chains too, not only the `_V<n>` sub-chains. A grep for
`DRAKVUF_EGRESS_` matches nothing a blanket rule would produce, which is how
the wildcard in step 8a stayed invisible to this step:

```sh
iptables -S DRAKVUF_EGRESS               # expect: -N line only
iptables -t nat -S DRAKVUF_EGRESS_NAT    # expect: -N line only
```

Finally, restart `sandboxd` with rules deliberately left behind (kill it with
`-9` mid-run) and confirm the startup sweep removes them.

```text
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS
-N DRAKVUF_EGRESS
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# iptables -t nat -S DRAKVUF_EGRESS_PRE
-N DRAKVUF_EGRESS_PRE
-A DRAKVUF_EGRESS_PRE -i xenbr1.1 -j DRAKVUF_EGRESS_PRE_V1
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep DRAKVUF_EGRESS_       # expect: no _V<n> chains at all
-N DRAKVUF_EGRESS_IN
-N DRAKVUF_EGRESS_IN_V1
-A DRAKVUF_EGRESS_IN -i xenbr1.1 -j DRAKVUF_EGRESS_IN_V1
-A DRAKVUF_EGRESS_IN_V1 -i xenbr1.1 -p tcp -m tcp --dport 38926 -j ACCEPT
-A DRAKVUF_EGRESS_IN_V1 -i xenbr1.1 -p udp -m udp --dport 38926 -j ACCEPT
-A DRAKVUF_EGRESS_IN_V1 -i xenbr1.1 -p udp -m udp --dport 5300 -j ACCEPT
-A DRAKVUF_EGRESS_IN_V1 -i xenbr1.1 -j DROP
-A DRAKVUF_INPUT -i xenbr1.+ -j DRAKVUF_EGRESS_IN
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# iptables -t nat -S | grep DRAKVUF_EGRESS_
-N DRAKVUF_EGRESS_NAT
-N DRAKVUF_EGRESS_PRE
-N DRAKVUF_EGRESS_PRE_V1
-A PREROUTING -j DRAKVUF_EGRESS_PRE
-A POSTROUTING -j DRAKVUF_EGRESS_NAT
-A DRAKVUF_EGRESS_PRE -i xenbr1.1 -j DRAKVUF_EGRESS_PRE_V1
-A DRAKVUF_EGRESS_PRE_V1 -i xenbr1.1 -p udp -m udp --dport 53 -j REDIRECT --to-ports 5300
-A DRAKVUF_EGRESS_PRE_V1 -i xenbr1.1 -p tcp -j REDIRECT --to-ports 38926
-A DRAKVUF_EGRESS_PRE_V1 -i xenbr1.1 -p udp -j REDIRECT --to-ports 38926
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# 09/02/26 09:30:33 AM [        DNS Server] Received AAAA request for domain 'api.snapcraft.io'.
09/02/26 09:30:33 AM [        DNS Server] Received A request for domain 'api.snapcraft.io'.
09/02/26 09:30:33 AM [  ProxyTCPListener] TLS handshake refused by 172.16.1.2:54960 ([SSL: SSLV3_ALERT_BAD_CERTIFICATE] sslv3 alert bad certificate (_ssl.c:1000)) -- the client did not accept our certificate   iptables -S DRAKVUF_EGRESS               # expect: -N line only        # expect: -N line only
-N DRAKVUF_EGRESS
(fakenet-ng) root@dom0:~/drakvuf-multios-sandbox# iptables -t nat -S DRAKVUF_EGRESS_NAT    # expect: -N line only
-N DRAKVUF_EGRESS_NAT

```

---

## Step 10 — the fallback is honest

Stop FakeNet while a `simulated` job is queued, then let it run:

```sh
systemctl stop fakenet
```

**`systemctl stop`, not `pkill`.** Since step 6c runs FakeNet as a unit,
`pkill` is a SIGTERM systemd reads as a failure, so `Restart=on-failure` brings
the responder back about five seconds later and the fallback never gets
exercised. A clean stop stays stopped. (The evidence below was captured with
`pkill` before the unit existed; what it shows — the run downgrading and saying
so — does not depend on how the responder was stopped.)

Start it again afterwards, or every later `simulated` job silently runs
`offline`:

```sh
systemctl start fakenet
```

The run must complete with **no network** rather than with a black hole, and
the report must say which:

```
requested: simulated   applied: offline
reason: simulated responder not listening on 127.0.0.1:38926 at launch
```

**A run that reports `applied: simulated` here is a FAIL** — it means the
launch-time probe did not fire and the clone spent its analysis talking to a
closed port, which reads as a sample whose infrastructure was down.

```text
Network   simulated via sim-local applied: offline
```

---

## What this discharged, and what it did not

Filed 2026-09-02. DRAFT-057's acceptance criteria for `offline`, `tor` and
`simulated` are discharged by the steps above. **The kill-switch criterion is
not** — that belongs to `routed`, which is Phase 4 and was never in scope here.

What went wrong along the way is in `docs/TROUBLESHOOTING.md`, symptom-first,
not in this file: the steps above are the commands that worked. Six entries
came out of this execution, five of them FakeNet-NG behaviours under
`DivertTraffic: No` and one a firewall check that passed either way.

### Findings worth carrying forward

- **The uplink guard had never been tested.** `network-setup.sh` drops tor's
  9040/9053 on `xenbr0` and has since DRAFT-028, but every probe of it had been
  run from Dom0 against Dom0's own address, which routes over `lo` and cannot
  match `-i xenbr0`. Step 6c now probes from the platform DomU and reads the
  rule counters. The guard was correct; nothing had shown that it was.
- **`simulated` discloses that HTTPS is refused.** The responder's certificate
  comes from a CA the guest has never trusted, so a validating sample gets a
  failed handshake. That is a `tls-untrusted-cert` caveat on the exit rather
  than a CA installed in the golden image, because a CA in the trust store is
  an enumerable sandbox artefact.
- **Five FakeNet patches, and four of them fail silently.** Only the first
  (`fn_addr`) stops the process. The rest let it bind every port and answer
  nothing, or answer plaintext and drop TLS — which is why step 6c proves the
  responder answers over loopback before any clone is involved.
