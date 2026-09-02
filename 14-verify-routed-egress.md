# Runbook — `routed` egress and its kill-switch (DRAFT-057 Phase 4)

> **Issue:** DRAFT-057 —
> [#42](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/42).
>
> **Status: NOT EXECUTED.** Parked at the repository root until its EVIDENCE
> blocks are filled, then moved to `docs/runbooks/14-verify-routed-egress.md`
> and the generators re-run.
>
> **Every command here is Candidate.** No tunnel has ever existed on this host,
> so nothing below has run. Do not treat a step as working because it is
> written down.
>
> **What this proves:** that a clone's traffic leaves through a tunnel and not
> through the house line, and that **losing the tunnel mid-run does not change
> that**. The second half is the acceptance criterion; the first is only how
> you make the second meaningful.
>
> Design: `docs/architecture/routed-egress.md`. Read its DECISION section
> before step 9 — a dead tunnel fails a job rather than downgrading it, and
> that is deliberate.

## What this discharges, and what it cannot

Hosting providers refused this lab's outreach (2026-09, `private/outreach/`).
That blocks the *deployment*, not the *design*, and almost all of DRAFT-057's
`routed` criteria can be proven against a **local peer**: the far end of a
WireGuard tunnel does not have to be rented to be a different network with its
own routing table and its own source address.

| Criterion | Provable here |
|---|---|
| Kill-switch, by capture rather than rule inspection | **yes** — the point of this runbook |
| Modes do not leak between runs | yes |
| Port-blocking surfaced as a caveat rather than absence | yes, as a mechanism |
| `routed` egresses from the **chosen country** | **no** — needs a rented host |

Say so when filing this. A green run here is not evidence about a provider.

## Before you start

**Use a throwaway DomU, not the platform one at `192.168.1.10`.** Mixing a
WireGuard exit into the host running Postgres, MinIO and the API makes both
harder to reason about, and this runbook tears the peer down.

Have ready:

- A temporary PVH DomU on `xenbr0` with `wireguard-tools` installed. Any
  address on the house LAN; `192.168.1.50` is assumed below.
- A second terminal on Dom0 for `tcpdump`.
- The knowledge that **step 6 deliberately breaks a running analysis.**

```
root@dom0:~/drakvuf-multios-sandbox# sudo lvcreate -V 20G  --thin -n router      vg-root/thinpool
root@dom0:~/drakvuf-multios-sandbox# sudo mkfs.ext4 -L platform-root /dev/vg-root/router 
root@dom0:~/drakvuf-multios-sandbox# sudo mkdir -p /mnt/router
root@dom0:~/drakvuf-multios-sandbox# sudo mount /dev/vg-root/router /mnt/router/
root@dom0:~/drakvuf-multios-sandbox# sudo debootstrap --arch=amd64 trixie /mnt/router/ https://ftp.caliu.cat/debian/

for d in dev dev/pts proc sys; do sudo mount --bind /$d /mnt/router/$d; done
sudo chroot /mnt/router /bin/bash

```bash
echo router > /etc/hostname
passwd root

apt update
apt install -y linux-image-amd64 systemd-sysv ifupdown2 openssh-server \
               ca-certificates locales sudo wireguard

root@dom0:/# sudo e2label /dev/mapper/vg--root-router router-root
root@dom0:/# sudo blkid /dev/mapper/vg--root-router
/dev/mapper/vg--root-router: LABEL="router-root" UUID="7a6e767d-ddf9-4948-b2e9-7e7f61696b0c" BLOCK_SIZE="4096" TYPE="ext4"
root@dom0:/# cat > /etc/fstab <<'EOF'
LABEL=router-root  /            ext4  errors=remount-ro  0 1
EOF

root@dom0:/# cat > /etc/network/interfaces <<'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet static
    address 192.168.1.11/24
    gateway 192.168.1.1
EOF
root@dom0:/# cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

exit

sudo mkdir -p /var/lib/xen/router
root@dom0:~/drakvuf-multios-sandbox# sudo cp /mnt/router/boot/vmlinuz-* /var/lib/xen/router/vmlinuz
sudo cp /mnt/router/boot/initrd.img-* /var/lib/xen/router/initrd.img

root@dom0:~/drakvuf-multios-sandbox# for d in sys proc dev/pts dev; do sudo umount /mnt/router/$d; done
sudo umount /mnt/router/
```

```
root@dom0:~# cat /root/router.cfg 
# The platform domain -- Postgres, MinIO and the FastAPI service.
#
# **It never executes a sample.** That asymmetry is the whole reason
# 08-deploy-platform-lxc.md judged an unprivileged container proportionate
# rather than a VM, and it still governs what may run here: nothing downloaded
# from an analysis is opened on this domain, not to "check" a pcap, not to test
# an extracted file. The moment something does, the isolation argument is void.
#
# Replaces CT 102, which was an unprivileged LXC on Proxmox until the
# bare-metal migration erased it. See docs/runbooks/13-platform-domu.md.

# PVH: hardware CPU and memory (VT-x + EPT) with paravirtual devices and NO
# QEMU device model. Every HVM guest costs a qemu-system process inside Dom0's
# 8192 MiB, which is memory the analysis clones are competing for; this domain
# costs none.
#
# The analysis guests are deliberately the opposite -- misc/*_sandbox.cfg are
# HVM because DRAKVUF's altp2m is an HVM/EPT facility, because Windows cannot
# run PVH, and because a PVH guest has no BIOS or emulated chipset and is
# conspicuously a VM to any sample that looks. PVH here precisely because this
# domain does not need to look like a real machine.
type = "pvh"

arch   = 'x86_64'
name   = "router"
memory = 2048
maxmem = 2048

# Raised 2048 -> 4096 on 2026-08-31, deliberately and at a stated price.
#
# **A DomU reservation is not a cgroup cap.** CT 102's 4096 was an LXC
# `--memory` ceiling with unused memory still available beneath it; this is
# taken from the clone pool permanently. The cost is one concurrent analysis:
#
#     32605 total - 8192 Dom0 - 2048 = 22365 / 4246 per clone = 5 clones
#     32605 total - 8192 Dom0 - 4096 = 20317 / 4246 per clone = 4 clones
#
# 4246 is `memory = 4096` plus DOMAIN_OVERHEAD_MIB, both templates since
# 2026-08-29. An earlier version of this comment said 2198, which was the
# figure before that raise -- at 2198 the change would have cost nothing.
#
# Runbook 08 recorded that 2048 works; this is headroom, not a fix for an
# observed fault. Drop back to 2048 if a fifth concurrent clone matters more.

vcpus = 1

# E-cores, 4 of them. Postgres, MinIO and uvicorn are throughput work rather
# than latency-bound, which is what makes the slow half of the machine the
# right half for this domain.
#
# **Generated from PLATFORM_PCPUS in automation/platform.env** by
# scripts/gen-xen-configs.py -- edit it there, not here. Disjoint from the
# clone range (16-27) on purpose: overlapping would put analysis load on the
# domain that records the analysis.
cpus = "28-31"

# PVH has no in-guest bootloader, so Xen loads the kernel directly and these
# files live on DOM0 -- not in the guest's /boot.
#
# **They MUST be re-copied after any kernel upgrade inside the guest.** apt
# updates the guest's /boot and its modules; Xen keeps booting this copy. The
# domain then comes up on the old kernel against new modules, with no error.
# The procedure is in runbook 13 F2.
kernel  = "/var/lib/xen/router/vmlinuz"
ramdisk = "/var/lib/xen/router/initrd.img"

# net.ifnames=0 forces eth0. Without it systemd's predictable naming renames the
# Xen netfront device (typically to enX0), /etc/network/interfaces matches
# nothing, and the domain boots with no address and no error -- visible only
# from `xl console`. The name cannot be checked in advance: a chroot shares
# Dom0's network namespace and so has no guest interface to inspect.
extra = "root=LABEL=router-root ro console=hvc0 net.ifnames=0"

# xvda is the root filesystem; xvdb is /srv/minio, mounted by LABEL from the
# guest's fstab. Both are thin volumes in vg-root -- the same pool as the golden
# images and every clone snapshot, so MinIO retention is a capacity question for
# the whole lab and not only a GDPR one.
disk = [
    'phy:/dev/vg-root/router,xvda,w'
]

# xenbr0, the UPLINK bridge -- NOT xenbr1. This is not an analysis guest and
# must never sit on the analysis network. 192.168.1.10 is configured inside the
# guest and is load-bearing: SANDBOXD_API, SANDBOXD_CONSOLE_API and the mTLS
# certificates all name it.
vif = [ 'bridge=xenbr0' ]

on_poweroff = "destroy"
on_reboot   = "restart"
on_crash    = "destroy"


sudo xl create -c /root/router.cfg 

sudo xl console router
```



---

## Step 1 — the peer

**Candidate.** On the temporary DomU:

```sh
umask 077
wg genkey | tee peer.key | wg pubkey > peer.pub
```

On Dom0:

```sh
umask 077
wg genkey | tee /etc/wireguard/dom0.key | wg pubkey > /etc/wireguard/dom0.pub
```

Peer config, on the DomU (`/etc/wireguard/wg0.conf`):

```ini
[Interface]
Address = 10.99.0.2/24
ListenPort = 51820
PrivateKey = <peer.key>

[Peer]
PublicKey = <dom0.pub>
AllowedIPs = 10.99.0.1/32, 172.16.0.0/12
```

`AllowedIPs` includes `172.16.0.0/12` because the clone's *source* address
arrives unmasqueraded at this end; without it WireGuard drops the packet as
not belonging to that peer, and the symptom is a tunnel that is up and carries
nothing.

Dom0 side (`/etc/wireguard/wg0.conf`):

```ini
[Interface]
Address = 10.99.0.1/24
PrivateKey = <dom0.key>

[Peer]
PublicKey = <peer.pub>
Endpoint = 192.168.1.50:51820
AllowedIPs = 10.99.0.0/24
PersistentKeepalive = 25
```

**`PersistentKeepalive` is not optional here.** WireGuard is silent when idle
and only rekeys under traffic, so without it an idle-but-healthy tunnel has an
ancient handshake and `egress.tunnel_ready` reads it as dead — the mode would
be withheld for a tunnel that is fine. See `TUNNEL_HANDSHAKE_MAX_AGE`.

```sh
wg-quick up wg0
wg show wg0 latest-handshakes    # expect: a peer, and a recent timestamp
```

```text
# router domu
root@router:~# wg-quick up wg0
[#] ip link add wg0 type wireguard
[  224.541475] wireguard: WireGuard 1.0.0 loaded. See www.wireguard.com for information.
[  224.541494] wireguard: Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
[#] wg setconf wg0 /dev/fd/63
[#] ip -4 address add 10.99.0.2/24 dev wg0
[#] ip link set mtu 1420 up dev wg0
[#] ip -4 route add 172.16.0.0/12 dev wg0
root@router:~# wg show wg0 latest-handshakes    # expect: a peer, and a recent timestamp
p0FQslc027phRlZ3ZMflMeKuBxPArLYI+Z3iMpmJVUk=	0

# DOM0
root@dom0:~# wg-quick up wg0
[#] ip link add wg0 type wireguard
[#] wg setconf wg0 /dev/fd/63
[#] ip -4 address add 10.99.0.1/24 dev wg0
[#] ip link set mtu 1420 up dev wg0
root@dom0:~# wg show wg0 latest-handshakes    # expect: a peer, and a recent timestamp
HnJbu7v8Gx09h/69mkuYWqGeO9DwYU3UjT9E0dagCDQ=	0

```

---

## Step 2 — sandboxd agrees the tunnel is up

Before any clone. This is the probe the exit list depends on:

```sh
cd /root/drakvuf-multios-sandbox
.venv-sandboxd/bin/python -c \
  "from sandboxd import egress; print(egress.tunnel_ready('wg0'))"
```

Expect `True`. If it prints `False` while `wg show` looks healthy, the
handshake is older than `TUNNEL_HANDSHAKE_MAX_AGE` — check
`PersistentKeepalive` before anything else.

```text
E2 EVIDENCE — paste both


```

---

## Step 3 — declare the exit and confirm it is offered

Add to `EXITS` in `sandboxd/config.py`:

```python
    "local-peer": {
        "mode": "routed", "interface": "wg0", "country": "lab",
        "caveats": ["no-real-internet"],
    },
```

`no-real-internet` is honest for **this** peer: it terminates the tunnel and
forwards nowhere. A real exit would drop that caveat and carry
`smtp-blocked-upstream` instead, if its provider blocks 25.

Restart `sandboxd` and read the startup log:

```
egress exits offered: offline (offline), ..., local-peer (routed)
```

**If `routed` is NOT offered**, the probe said the tunnel was down — that is
the guard working, and step 2 will say why.

```text
E3 EVIDENCE — paste the log line


```

---

## Step 4 — the rules and the routes both exist

Submit a job selecting **local-peer**. While the clone is up, on Dom0:

```sh
iptables -S DRAKVUF_EGRESS_V1          # expect: -o wg0 ACCEPT, and no xenbr0
ip rule show pref 1001                 # expect: from 172.16.1.0/24 lookup 1001
ip route show table 1001               # expect: default dev wg0
```

**Both halves matter and neither is sufficient.** The iptables rule permits
the packet to leave by `wg0`; the route is what makes the kernel choose `wg0`
at all. Until 2026-09-02 only the first existed, and `routed` failed closed one
hundred percent of the time — safe, and easy to misread as "routed is broken".

Table and preference are `1000 + vlan`, so a clone on vlan 1 uses 1001. Not
`100 + vlan`: that would put vlan 154 on table 254, which is `main`.

```text
E4 EVIDENCE — paste all three


```

---

## Step 5 — traffic actually goes through the tunnel

In the guest:

```sh
ping -c 3 10.99.0.2
```

On the **peer**, at the same time:

```sh
tcpdump -i wg0 -n
```

Expect the clone's own address, `172.16.1.2`, arriving on the peer's `wg0`.
That is the proof the packet crossed the tunnel rather than the LAN: it is
unmasqueraded at this end, so a `172.16.x.x` source on `wg0` cannot have come
any other way.

```text
E5 EVIDENCE — paste the guest command and the peer capture


```

---

## Step 6 — THE KILL-SWITCH. This is the acceptance criterion.

**The trap in this test is that a silent capture is also what you get when
nothing was ever sent.** So the capture must be running before anything
changes, and step 5 must already have shown traffic flowing.

With a routed clone running and generating traffic, on Dom0, in a second
terminal:

```sh
tcpdump -i xenbr0 -n 'net 172.16.0.0/12'
```

**Expect zero packets, for the whole capture, before and after the drop.** The
clone's traffic is inside the tunnel, so it is never on the uplink in
cleartext to begin with.

**You WILL see WireGuard UDP on `xenbr0` if you drop the filter**, because the
tunnel itself runs over the house LAN to reach the peer. That is expected and
correct — it is encapsulated. The filter above is what separates "the tunnel is
working" from "the clone leaked".

Now, with the sample still running:

```sh
wg-quick down wg0
```

Then assert, in this order:

```sh
# 1. still nothing from the clone on the uplink
#    (read the tcpdump packet count in the second terminal)

# 2. the guest sees timeouts, not resets
#    in the guest:  ping -c 2 10.99.0.2   -> no reply

# 3. the rules are unchanged -- the kill-switch is structural, not reactive
iptables -S DRAKVUF_EGRESS_V1
```

**Point 3 is the one that makes this a property rather than a coincidence.**
Nothing removed a rule when the tunnel dropped and nothing needed to: the
ACCEPT names `-o wg0` and no rule anywhere names the uplink, so a vanished
interface simply stops matching and the packet falls to `DRAKVUF_ISOLATION`'s
terminal DROP. Fail-closed is a property of what the rules say, not of a
watchdog noticing in time.

```text
E6 EVIDENCE — paste the packet count from the whole capture, the guest's
timeout, and the unchanged chain


```

---

## Step 7 — teardown removes the routing, not just the rules

Let the job finish, then on Dom0:

```sh
ip rule show pref 1001            # expect: nothing
ip route show table 1001          # expect: nothing
iptables -S | grep DRAKVUF_EGRESS_   # expect: no _V<n> chains
```

**A leftover `ip rule` is the dangerous half**, and it is invisible to every
check written for the iptables side. `ip rule add` is not idempotent and has
no `-N` equivalent, so a stale rule would silently route the *next* clone on
that VLAN into a tunnel nobody selected for it. The rule carries an explicit
preference precisely so teardown can name it exactly.

Then kill `sandboxd` with `-9` mid-run and restart it: the startup sweep calls
the same `argv_revoke`, so it clears routing as well as chains.

```text
E7 EVIDENCE — paste both, before and after the sweep


```

---

## Step 8 — a dead tunnel FAILS the job

Stop the tunnel, then submit a `routed` job.

```sh
wg-quick down wg0
```

**Expect the job to fail, and NOT to run with no network.** The report should
show a failed job naming the tunnel, not a completed one reporting
`applied: offline`.

That differs from `tor` and `simulated`, which downgrade, and the difference is
deliberate (`docs/architecture/routed-egress.md`, DECISION 2026-09-02):
`routed`'s rules already fail closed, so a downgrade buys no safety and only
decides whether the run is spent — and an `offline` run spends a sample that
may check in exactly once.

**A completed job reporting `applied: offline` here is a FAIL of this step**,
even though nothing escaped.

```text
E8 EVIDENCE — paste the job state and the failure reason


```

---

## Step 9 — the Ubuntu regression. This gates the merge.

`argv_apply` is shared, and `direct` goes through the same builder. It must be
untouched by the routing work.

```sh
ALLOW_DIRECT=1 ./automation/run_analysis-ubuntu.sh <args as before>
iptables -S DRAKVUF_EGRESS
ip rule show                     # expect: NO 1000-range rule for this VLAN
```

**`direct` must install no policy route at all.** The uplink is already the
default route; a second copy of that fact is a thing that can drift from it.

Compare the resulting trace against a pre-change run of the same fixture. Any
difference in what the trace observed is a regression.

```text
E9 EVIDENCE — paste output here


```

---

## Watch for, but do not fix speculatively

**Large transfers stalling while small ones succeed.** WireGuard's usable MTU
is below the clone's 1500, and malware is not obliged to honour PMTUD. The
signature is a TLS handshake completing and the first big response hanging. If
it appears, the fix is MSS clamping on the tunnel in the per-VLAN chain; it is
in the design record and is deliberately not installed until observed.

## What to record when this is done

- Fill every EVIDENCE block, and move this file to
  `docs/runbooks/14-verify-routed-egress.md`.
- Re-run `scripts/gen-current-state.py`, `scripts/gen-doc-index.py` and
  `scripts/check-refs.py`, and commit the regenerated files with it.
- Correct the status banner. It says NOT EXECUTED and will be wrong.
- Tick DRAFT-057's kill-switch criterion. **Not the country one** — that needs
  a provider, and this runbook cannot speak to it.
- Destroy the temporary DomU, and remove `local-peer` from `EXITS`. An exit
  left declared against a peer that no longer exists is offered whenever the
  interface happens to be up.
- Anything that went wrong goes to `docs/TROUBLESHOOTING.md`, symptom first.
