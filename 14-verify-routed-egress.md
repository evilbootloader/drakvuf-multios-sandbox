# Runbook — `routed` egress and its kill-switch (DRAFT-057 Phase 4)

> **Issue:** DRAFT-057 —
> [#42](https://github.com/evilbootloader/drakvuf-multios-sandbox/issues/42).
>
> **REDACTED 2026-09-04. These were PUBLIC keys.** `wg show <iface>
> latest-handshakes` and `wg show <iface>` print each peer's **public** key —
> the identifier, never the private key, which does not appear in either
> output. The peer was a throwaway `router` DomU that this runbook tears down
> in step 11. They read `REDACTED-WG-PUBKEY-DOM0` and
> `REDACTED-WG-PUBKEY-ROUTER`; that the two differ is the only property any
> step here depends on, and it is preserved.
>
> Redacted because TruffleHog's `Box` detector matches any 32-character
> alphanumeric run and the pre-push hook refuses on an unverified finding
> regardless of what the value is. Recorded rather than silently rewritten, so
> nobody reads this as evidence that a private key was once committed.
>
> **Status: EXECUTED 2026-09-02 to 2026-09-04.** Every step has run on this
> host, against a local WireGuard peer on a throwaway `router` DomU.
>
> Step 6, the acceptance criterion, passed on the **third** attempt. The first
> two produced `0 packets captured` without testing anything — once with the
> capture stopped before the tunnel dropped, once with no clone running — so the
> step now states its preconditions as lettered asserts with output to paste.
> A silent capture is also what an empty machine produces.
>
> Two limits are stated where they arise rather than papered over: step 5's
> transfer counters are Dom0-side and do not prove the peer processed the data,
> and 9a can no longer be diffed against a pre-change baseline because none was
> ever recorded.
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

| Criterion | Provable here | Outcome |
|---|---|---|
| Kill-switch, by capture rather than rule inspection | **yes** — the point of this runbook | **proven**, step 6 |
| Modes do not leak between runs | yes | **proven**, step 10 — by rule inspection, not capture |
| Port-blocking surfaced as a caveat rather than absence | yes, as a mechanism | mechanism only; this peer blocks everything |
| `routed` egresses from the **chosen country** | **no** — needs a rented host | not addressed |

Say so when filing this. A green run here is not evidence about a provider.

## Before you start

**Use a throwaway DomU, not the platform one at `192.168.1.10`.** Mixing a
WireGuard exit into the host running Postgres, MinIO and the API makes both
harder to reason about, and this runbook tears the peer down.

Have ready:

- A temporary PVH DomU on `xenbr0` with `wireguard-tools` installed. Any
  address on the house LAN; `192.168.1.11` is assumed below, matching the
  `router.cfg` and the `/etc/network/interfaces` in this section.
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

On the temporary DomU:

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
AllowedIPs = 10.99.0.1/32
```

**A single `/32` is the whole of what arrives here.** `argv_apply` masquerades
`routed` along with `direct` (`sandboxd/egress.py`, the `MASQUERADE` rule), so
the clone's own address is rewritten to Dom0's tunnel address before the packet
reaches `wg0`. An earlier version of this runbook listed `172.16.0.0/12` here on
the assumption that clone addresses survive the tunnel. They do not, and they
should not: a rented exit would drop RFC1918 sources on sight.

Dom0 side (`/etc/wireguard/wg0.conf`):

```ini
[Interface]
Address = 10.99.0.1/24
PrivateKey = <dom0.key>
Table = off

[Peer]
PublicKey = <peer.pub>
Endpoint = 192.168.1.11:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

**`AllowedIPs` is a routing table, not a filter.** WireGuard picks the peer by
longest-prefix match on the *destination*, and a destination matching no peer is
rejected at the device with `EHOSTUNREACH`. `argv_apply` points a default route
at `wg0`, so a narrow list here means every Internet-bound clone packet dies on
transmit and Dom0 answers the clone with ICMP host unreachable — a tunnel that
is up, handshaking, and carrying nothing.
See [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#a-routed-clone-gets-icmp-host-unreachable-and-the-tunnel-carries-no-data).

**`Table = off` is not optional, and is the reason `0.0.0.0/0` is safe above.**
wg-quick's default `Table = auto` reacts to a `0.0.0.0/0` peer by installing its
own fwmark default-routing at preferences 32764 and 32765 — which captures
**Dom0's** traffic, not the clone's, on a host you are almost certainly logged
into. sandboxd installs the only route this needs, in a per-VLAN table of its
own; wg-quick must install none.

**`PersistentKeepalive` is not optional here.** WireGuard is silent when idle
and only rekeys under traffic, so without it an idle-but-healthy tunnel has an
ancient handshake and `egress.tunnel_ready` reads it as dead — the mode would
be withheld for a tunnel that is fine. See `TUNNEL_HANDSHAKE_MAX_AGE`.

```sh
wg-quick up wg0
wg show wg0 latest-handshakes    # expect: a peer, and a recent timestamp
```

```text
# DOM0
root@dom0:~/drakvuf-multios-sandbox# wg show wg0 latest-handshakes    # expect: a peer, and a recent timestamp
REDACTED-WG-PUBKEY-DOM0	1788372594

# router domu
root@router:~# wg show wg0 latest-handshakes
REDACTED-WG-PUBKEY-ROUTER	1788372593
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
root@dom0:~/drakvuf-multios-sandbox# .venv-sandboxd/bin/python -c   "from sandboxd import egress; print(egress.tunnel_ready('wg0'))"
True

root@dom0:~/drakvuf-multios-sandbox# wg show
interface: wg0
  public key: REDACTED-WG-PUBKEY-ROUTER
  private key: (hidden)
  listening port: 41692

peer: REDACTED-WG-PUBKEY-DOM0
  endpoint: 192.168.1.11:51820
  allowed ips: 10.99.0.0/24
  latest handshake: 1 minute, 30 seconds ago
  transfer: 92 B received, 276 B sent
  persistent keepalive: every 25 seconds

```

**FINDING (2026-09-02).** The `allowed ips: 10.99.0.0/24` above is the
pre-correction value; step 1 now says `0.0.0.0/0`. The result still stands —
`tunnel_ready` reads handshake age and nothing else, so widening `AllowedIPs`
cannot change it — but `transfer: 92 B received, 276 B sent` is keepalives
alone, and is worth reading as what it is: at this point nothing has crossed
the tunnel yet.

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
2026-09-02 18:12:30,242 INFO    sandboxd: egress exits offered: offline (offline), tor-default (tor), local-peer (routed)
```

---

## Step 4 — the rules and the routes both exist

Submit a job selecting **local-peer**. While the clone is up, on Dom0:

```sh
iptables -S DRAKVUF_EGRESS_V1   # expect: -o wg0 ACCEPT, and no xenbr0
ip rule show pref 1001          # expect: from 172.16.1.0/24 iif xenbr1.1 lookup 1001
ip route show table 1001        # expect: default dev wg0
```

**Both halves matter and neither is sufficient.** The iptables rule permits
the packet to leave by `wg0`; the route is what makes the kernel choose `wg0`
at all. Until 2026-09-02 only the first existed, and `routed` failed closed one
hundred percent of the time — safe, and easy to misread as "routed is broken".

Table and preference are `1000 + vlan`, so a clone on vlan 1 uses 1001. Not
`100 + vlan`: that would put vlan 154 on table 254, which is `main`.

```text
root@dom0:~# iptables -S DRAKVUF_EGRESS_V1          # expect: -o wg0 ACCEPT, and no xenbr0
-N DRAKVUF_EGRESS_V1
-A DRAKVUF_EGRESS_V1 -i xenbr1.1 -o wg0 -j ACCEPT
-A DRAKVUF_EGRESS_V1 -i wg0 -o xenbr1.1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_EGRESS_V1 -j DROP
root@dom0:~# ip rule show pref 1001                 # expect: from 172.16.1.0/24 lookup 1001
1001:	from 172.16.1.0/24 lookup 1001
root@dom0:~# ip route show table 1001               # expect: default dev wg0
default dev wg0 scope link 
```

**FINDING (2026-09-03) — the rule above predates the `iif` fix.** It reads
`from 172.16.1.0/24 lookup 1001` with no `iif`, which is the form corrected on
2026-09-03. Whether this capture is simply older than the fix, or the fix is not
running on this host, **cannot be told from the output**, and step 6 passing
does not settle it — the kill-switch does not depend on `iif`. Step 4b exists to
settle it.

---

## Step 4b — the policy rule cannot catch Dom0's own traffic

With a routed clone up, on Dom0:

```sh
ip rule show pref 1001                      # expect: ... iif xenbr1.1 ...
ip route get 172.16.1.2 from 172.16.1.1     # expect: dev xenbr1.1, NOT wg0
```

The VLAN gateway address is inside the subnet the policy rule selects on, so a
rule matching source network alone also captures packets **Dom0** originates —
and posts them into the tunnel instead of handing them to the clone one hop
away. The rule carries `iif` since 2026-09-03 for exactly this reason.

**Both commands, not one.** The first reads what is installed; the second reads
what the kernel will actually do with it, which is the claim that matters. If
the second prints `wg0`, the sandboxd on this host predates the fix — pull and
restart it before continuing.

**Needs a live clone.** With no routed job holding the VLAN there is no rule at
pref 1001, so `ip route get` prints `dev xenbr1.1` whether or not the fix is
present: the right answer for the wrong reason, on exactly the hosts this exists
to catch.
See [TROUBLESHOOTING](docs/TROUBLESHOOTING.md#dom0s-own-icmp-errors-appear-on-the-tunnel-instead-of-reaching-the-clone).

```text
root@dom0:~/drakvuf-multios-sandbox# ip rule show pref 1001                      # expect: ... iif xenbr1.1 ...
1001:	from 172.16.1.0/24 iif xenbr1.1 lookup 1001
root@dom0:~/drakvuf-multios-sandbox# ip route get 172.16.1.2 from 172.16.1.1     # expect: dev xenbr1.1, NOT wg0
172.16.1.2 from 172.16.1.1 dev xenbr1.1 uid 0 
    cache 
```

---

## Step 5 — traffic actually goes through the tunnel

In the guest:

```sh
ping -c 3 192.0.2.1
```

**Not the peer's own `10.99.0.2`.** `network-setup.sh` drops `10.0.0.0/8` from
every analysis VLAN, and that rule sits ABOVE the jump to `DRAKVUF_EGRESS` on
purpose — so a clone pinging the tunnel address is refused by the isolation
chain and never reaches the per-VLAN rules at all. The failure looks identical
to a broken tunnel. `192.0.2.0/24` is TEST-NET-1: outside every range the
isolation chain drops, unmistakable in a capture, and incapable of reaching
anything real if it ever escapes.

On the **peer**, at the same time:

```sh
tcpdump -i wg0 -n
```

Expect `10.99.0.1 > 192.0.2.1` echo requests arriving on the peer's `wg0`.
There are no replies — this peer forwards nowhere, which is what
`no-real-internet` means. Arrival is the whole of the result.

**The source is Dom0's tunnel address, not the clone's**, because `routed`
masquerades — see step 1. That still proves what this step is for: `10.99.0.1`
is configured on exactly one interface in the world, so its appearance on the
peer's `wg0` cannot have come over the LAN. What identifies the traffic as the
*clone's* is the flow, not the source address — nothing on Dom0 pings
TEST-NET-1 by itself.

**A silent peer-side capture is the failure**, and the reason is almost always
one of the two above: `AllowedIPs` too narrow on the Dom0 side, so the packet is
rejected on transmit before it is ever encrypted, or the policy rule missing
`iif`. `wg show`'s `transfer:` counters distinguish them from a routing problem
in one line — keepalive-sized totals mean nothing crossed.

```text
# 2026-09-03
11:39:11.839833 IP 10.99.0.1 > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64
11:39:12.877518 IP 10.99.0.1 > 192.0.2.1: ICMP echo request, id 1, seq 2, length 64
11:39:13.901527 IP 10.99.0.1 > 192.0.2.1: ICMP echo request, id 1, seq 3, length 64
```

```text
# Dom0, 2026-09-04
root@dom0:~/drakvuf-multios-sandbox# wg show
interface: wg0
  public key: REDACTED-WG-PUBKEY-ROUTER
  private key: (hidden)
  listening port: 45909

peer: REDACTED-WG-PUBKEY-DOM0
  endpoint: 192.168.1.11:51820
  allowed ips: 0.0.0.0/0
  latest handshake: 1 minute, 19 seconds ago
  transfer: 1.27 KiB received, 12.68 KiB sent
  persistent keepalive: every 25 seconds
```

**PASS, with its limit stated.** Two things move against step 2's reading of the
same command:

| | step 2 | here |
|---|---|---|
| `sent` | 276 B | **12.68 KiB** |
| `allowed ips` | `10.99.0.0/24` | **`0.0.0.0/0`** |

**The `sent` counter increments after encryption**, which is precisely what the
2026-09-02 failure prevented: packets rejected by cryptokey routing never reach
the cipher, so that counter stayed at keepalive size while the clone retried.
12.68 KiB is proof the clone's traffic was encrypted and put on the wire. The
`allowed ips` line is the first direct evidence that step 1's correction is live
on the host rather than only committed.

**The limit:** this is Dom0's `wg show` — the interface key is Dom0's, per step
1 — so it does not prove the peer processed the data. `received: 1.27 KiB` is
consistent with keepalives alone. A peer-side capture would settle it.

**Deliberately not chased further.** Encryption and transmission to a peer whose
handshake is 79 seconds old is the whole of what this mode owes; the far end is
a property of the peer, not of the containment. Nothing downstream depends on
it — step 6, the acceptance criterion, is about what does **not** reach the
uplink.

**FINDING (2026-09-02).** The first attempt at this step failed, and both of
the defects it exposed are fixed above. The capture is in
`docs/TROUBLESHOOTING.md` rather than here, because its value is as a symptom
someone else will one day match against.

**FINDING (2026-09-03) — `routed` discloses the clone's internal address to the
exit's resolver.** The second capture contained:

```text
11:18:50.027708 IP 10.99.0.1.50738 > 1.1.1.1.53: 34304+ PTR? 2.1.16.172.in-addr.arpa. (41)
```

That is a reverse lookup for `172.16.1.2` — the clone's own address — leaving
through the tunnel in cleartext. Masquerading rewrites the IP header and cannot
touch a payload that names the same address, so the lab's internal addressing
reaches whatever resolver the exit uses.

Not a containment failure: nothing is reachable at `172.16.1.2` from outside,
and the range is one of the most common on Earth. It is a **fingerprinting**
observation, and it belongs on the report's caveats rather than in a fix —
suppressing it would mean interfering with guest DNS, which is a larger and more
detectable change than the leak it would close. Recorded here so the next person
to see it in a capture does not re-derive it.

---

## Step 6 — THE KILL-SWITCH. This is the acceptance criterion.

**The trap in this test is that a silent capture is also what you get when
nothing was ever sent.** So the capture must be running before anything
changes, and step 5 must already have shown traffic flowing.

This peer forwards nowhere, so the clone's ordinary background traffic reaches
no service and stops being a reliable source of packets. Give the step
something it controls. In the guest, and leave it running:

```sh
ping 192.0.2.1          # continuous, NOT -c 3
```

When `wg0` goes away the route in table 1001 goes with it, the packet falls back
to the main table, and the main table aims at the uplink. That is precisely the
leak this step looks for, offered deliberately once a second.

**The target must be outside RFC1918, and this is not a detail.** Ping the
peer's own `10.99.0.2` instead and the isolation chain's `10.0.0.0/8` drop
catches the packet BEFORE the jump to `DRAKVUF_EGRESS` — so the capture stays
silent, the step appears to pass, and what was actually proven is that a rule
written in 2026-08 still works. The kill-switch would never have been exercised.
A test whose pass condition can be met by the wrong mechanism is the failure
this step opens by warning about.

**The filter catches a leak even though `routed` masquerades**, because the
MASQUERADE rule names `-o wg0` too. A packet that escapes to the uplink escapes
by not matching that rule either, so it arrives on `xenbr0` still carrying
`172.16.1.2`. The two rules fail closed together or not at all.

**You WILL see WireGuard UDP on `xenbr0` if you drop the filter**, because the
tunnel itself runs over the house LAN to reach the peer. That is expected and
correct — it is encapsulated. The filter above is what separates "the tunnel is
working" from "the clone leaked".

### Run it in this order, and record every step

**This step was run twice and was vacuous twice**, in two different ways: once
with the capture stopped before the tunnel was dropped, once with no clone
running at all. Both produced `0 packets captured`, which is also what a pass
looks like. So the preconditions below are asserts with output to paste, not
prose to satisfy — a reader must be able to tell a live test from an empty
machine without having been there.

The tunnel goes UP first. A `routed` job submitted while it is down is refused,
which is step 8, not this step.

```sh
# A. the job is live and the rules under test exist -- not "no chain".
#    THREE rules when this was executed (2026-09-02..04); SIX since the
#    DRAFT-057 Phase 5 throttles landed 2026-09-05, which add three DROPs
#    above the permit. See docs/runbooks/15-verify-egress-throttles.md.
iptables -S DRAKVUF_EGRESS_V1

# B. the clone is offering traffic -- in the guest, left running
ping 192.0.2.1

# C. the capture is listening, second Dom0 terminal, left running
tcpdump -i xenbr0 -n 'net 172.16.0.0/12'

# D. break it
wg-quick down wg0

# E. the rules are unchanged -- the kill-switch is structural, not reactive
iptables -S DRAKVUF_EGRESS_V1

# F. the guest stays silent: no replies, and no "Destination Net Unreachable"

# G. ^C the capture and read its count. Zero, for the whole run.
```

E, F and G must all land inside the analysis window, before the job ends and
teardown removes the chain.

**E is what makes this a property rather than a coincidence.** Nothing removed a
rule when the tunnel dropped and nothing needed to: the ACCEPT names `-o wg0`
and no rule anywhere names the uplink, so a vanished interface simply stops
matching and the packet falls to the chain's terminal DROP. Fail-closed is a
property of what the rules say, not of a watchdog noticing in time.

**F is silence, and silence is the pass.** `-j DROP` sends nothing back — that
is the whole difference between DROP and REJECT, and it is deliberate: an ICMP
error would tell a sample that something on the path is filtering it. But read
the silence precisely, because one specific message would have meant the test
proved nothing:

| Guest shows | Meaning |
|---|---|
| **silence** | routed at the uplink, killed by the terminal DROP — the result this step wants |
| `Destination Net Unreachable` from `172.16.1.1` | no route at all; the packet never reached the chain |
| replies | a leak, or a peer that forwards |
| resets, port unreachable | something answered for the clone — a REJECT where there should be a DROP |

**There are no replies before the drop either**, and that is not a fault.
`192.0.2.1` is TEST-NET-1: no host exists there, so nothing answers through a
working tunnel any more than through a broken one. The ping is a *source of
packets*, not a connectivity test. The consequence is that the guest's view is
identical either side of the drop — **all the discriminating evidence is on
Dom0**, in G's packet count and E's unchanged chain.

```text
# B -- in the guest, left running for the whole of what follows
carlos@desktop:~/Desktop$ date
jue 03 sep 2026 13:58:58 CEST
carlos@desktop:~/Desktop$ ping 192.0.2.1
PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.

# C -- Dom0 terminal 2, left listening
root@dom0:/home/user# tcpdump -i xenbr0 -n 'net 172.16.0.0/12'
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on xenbr0, link-type EN10MB (Ethernet), snapshot length 262144 bytes

# A, D, E -- Dom0 terminal 1
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS_V1
-N DRAKVUF_EGRESS_V1
-A DRAKVUF_EGRESS_V1 -i xenbr1.1 -o wg0 -j ACCEPT
-A DRAKVUF_EGRESS_V1 -i wg0 -o xenbr1.1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_EGRESS_V1 -j DROP
root@dom0:~/drakvuf-multios-sandbox# wg-quick down wg0
[#] ip link delete dev wg0
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS_V1
-N DRAKVUF_EGRESS_V1
-A DRAKVUF_EGRESS_V1 -i xenbr1.1 -o wg0 -j ACCEPT
-A DRAKVUF_EGRESS_V1 -i wg0 -o xenbr1.1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_EGRESS_V1 -j DROP

# G -- back in terminal 2, after the drop
^C
0 packets captured
0 packets received by filter
0 packets dropped by kernel
```

**PASS.** The chain is byte-identical either side of `ip link delete dev wg0`,
and nothing from the clone reached the uplink while it was pinging once a second
at a route that had just been aimed there.

**FINDING (2026-09-03).** The guest never printed `Destination Net Unreachable`,
and that is the load-bearing negative. Deleting `wg0` empties table 1001 but
leaves the `ip rule` at pref 1001 standing — a rule references a table, not a
device — so the clone's packets matched it, found nothing, fell through to
`main`, and were routed at `xenbr0`. Had they instead failed to route, Dom0
would have generated that ICMP error once a second and the zero-packet count
would have proven only that unroutable packets do not travel. The packets
reached the rule under test, and the rule stopped them.

**Not evidenced here, deliberately:** that the pings were crossing the tunnel
*before* the drop. `wg show` cannot say so afterwards — the device is gone. Step
5 establishes it on the same guest, the same target and the same path, and
re-running it here would prove nothing new.

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

That is the job's own teardown. The crash path is step 7b.

```text
root@dom0:~/drakvuf-multios-sandbox# ip rule show pref 1001            # expect: nothing
root@dom0:~/drakvuf-multios-sandbox# ip route show table 1001          # expect: nothing
root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep DRAKVUF_EGRESS_   # expect: no _V<n> chains
-N DRAKVUF_EGRESS_IN
-A DRAKVUF_INPUT -i xenbr1.+ -j DRAKVUF_EGRESS_IN
```

**PASS** for the ordinary teardown: no `pref 1001`, no table 1001, and the only
`DRAKVUF_EGRESS_` names left are the parent `_IN` chain and its jump — no
`_V<n>` survived.

---

## Step 7b — the crash path, which is a different code path

Step 7 tested the teardown a job runs when it finishes normally.
This tests the one that runs when it does not, and **that is the case where a
stale `ip rule` actually costs something**: nothing tore down, so the rule
survives, and the next clone on that VLAN is routed into a tunnel nobody
selected for it. `ip rule add` is not idempotent and has no `-N` equivalent, so
nothing downstream would notice.

With a routed clone up:

```sh
ip rule show pref 1001              # confirm it is THERE first
kill -9 <the sandboxd pid>          # it runs in the FOREGROUND -- no unit

# restart it exactly as CURRENT-STATE.md §1.2 says; the startup sweep runs
# argv_revoke for every VLAN it finds dirty
cd /root/drakvuf-multios-sandbox
set -a; . /etc/sandboxd/sandboxd.env; set +a
.venv-sandboxd/bin/python -m sandboxd.daemon

ip rule show pref 1001              # expect: nothing
ip route show table 1001            # expect: nothing
iptables -S | grep DRAKVUF_EGRESS_  # expect: no _V<n> chains
```

**There is no `systemctl restart sandboxd`, and no `journalctl -u sandboxd`.**
It is a foreground process logging to stderr; treating it as a unit is a
documented past mistake (`docs/CURRENT-STATE.md`). Sourcing the env file first
is not optional — `Settings.from_env` raises `SystemExit` without it, and the
bare invocation then exits at once looking like a broken install.

**The first command is the precondition, not decoration.** A sweep that finds
nothing to clean cannot be distinguished from a sweep that did not run.

```text
root@dom0:~/drakvuf-multios-sandbox# ip rule show pref 1001              # confirm it is THERE first
1001:	from 172.16.1.0/24 iif xenbr1.1 lookup 1001
root@dom0:~/drakvuf-multios-sandbox# ps aux | grep sandboxd
root       65954  0.9  0.4 259712 33324 pts/4    Sl+  09:37   0:00 .venv-sandboxd/bin/python -m sandboxd.daemon
tcpdump    66314  0.0  0.1  19108  8828 ?        Ss   09:37   0:00 tcpdump -i xenbr1.1 -n -U -w /var/lib/sandboxd/results/6177ae39-3ccd-41f5-a54b-74e959fe2ba3/capture.pcap
root       66322 51.8 10.2 836052 829264 ?       Ss   09:37   0:00 drakvuf -r /root/drakvuf-multios-sandbox/profiles/linux.json -d 93 -i 1 -m execproc -e /home/carlos/Desktop/slow.sh -F --disable-sysret -o json -t 120 -a syscalls -a fileextractor -a memdump -a filetracer -D /var/lib/sandboxd/results/6177ae39-3ccd-41f5-a54b-74e959fe2ba3/dump --memdump-dir /var/lib/sandboxd/results/6177ae39-3ccd-41f5-a54b-74e959fe2ba3/memdump
root       66324  0.0  0.0   4088  2100 pts/3    S+   09:37   0:00 grep --color=auto sandboxd
root@dom0:~/drakvuf-multios-sandbox# kill -9 65954         # it runs in the FOREGROUND -- no unit

# SANDBOXD RESTARTED

root@dom0:~/drakvuf-multios-sandbox# ip rule show pref 1001              # expect: nothing
root@dom0:~/drakvuf-multios-sandbox# ip route show table 1001            # expect: nothing
root@dom0:~/drakvuf-multios-sandbox# iptables -S | grep DRAKVUF_EGRESS_  # expect: no _V<n> chains
-N DRAKVUF_EGRESS_IN
-A DRAKVUF_INPUT -i xenbr1.+ -j DRAKVUF_EGRESS_IN
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
Failed at sandboxd — EgressUnavailable: job asked for exit 'local-peer' (routed) and tunnel wg0 has no WireGuard handshake in the last 180s. Refused rather than downgraded: the submitter asked to reach the Internet from somewhere specific, and running with no network instead answers a different question while spending the sample.
```

---

## Step 9 — the Ubuntu regression. This gates the merge.

**Two different things need protecting here, and one command cannot do both.**

An earlier version of this step said "`argv_apply` is shared, and `direct` goes
through the same builder", then gave the `run_analysis-ubuntu.sh` command. That
is false for that command: `ALLOW_DIRECT=1` sets `EGRESS_MODE=direct`, which
takes `network-setup.sh`'s **legacy wildcard** branch and never calls
`argv_apply` at all. The rule it installs is deliberately shaped so you can see
that from the output — a wildcard `xenbr1.+`, where a per-job rule names one
VLAN.

### 9a — the evidenced Ubuntu pipeline still runs

```sh
ALLOW_DIRECT=1 ./automation/run_analysis-ubuntu.sh
iptables -S DRAKVUF_EGRESS       # expect: the wildcard, NOT a _V<n> jump
ip rule show                     # expect: NO 1000-range rule at all
```

**No arguments.** The script reads none — everything comes from
`automation/pipeline-ubuntu.env`, and the only knob for this step is the
`ALLOW_DIRECT` environment variable in front of it.

**The `ip rule` check is the one that matters for this change**, and it is a
real result: the routing work must be invisible to the path that does not use
it. `direct` installs no policy route by design — the uplink is already the
default route, and a second copy of that fact is a thing that can drift from it.

Then confirm the analysis completes and produces its usual artifacts — trace,
pcap, extracted files, memdump.

**Earlier drafts asked for a diff against a pre-change run of the same fixture,
and that cannot be done.** The reasoning was sound: a regression here would not
necessarily raise an error, it would show as DRAKVUF observing *less* than
before, because the sample gave up early on something that used to work. But
nothing in this repository records per-run trace statistics, so there is no
stored baseline to diff against — it would have had to be captured before the
change, and it was not. Asking for it leaves an item nobody can ever close.

The residual risk is small and can be stated: `run_analysis-ubuntu.sh` never
calls `argv_apply`, the `iif` change lives only in the routed path, and the
check above already shows the legacy wildcard installing with no policy route
appearing beside it. **Capture a baseline before the next change to shared
code**, so the next runbook can ask this properly.

### 9b — `argv_apply`'s own `direct` branch

Not reachable from 9a. It needs a job submitted through sandboxd with the host
opted in:

```sh
SANDBOXD_ALLOW_DIRECT=1        # on the sandboxd unit, then submit a direct job
iptables -S DRAKVUF_EGRESS_V<n>  # expect: -o xenbr0 ACCEPT, and no ip rule
```

`test_routed_installs_a_policy_route_and_direct_does_not` covers the argv for
this in the unit suite, so 9b is confirmation on the host rather than the only
line of defence. 9a is not optional either way: it is the evidenced path.

```text
# 9a, 2026-09-03
root@dom0:~/drakvuf-multios-sandbox# ALLOW_DIRECT=1 ./automation/run_analysis-ubuntu.sh
network-setup.sh: WARNING -- egress mode 'direct': every clone NATs
  out xenbr0 with no per-job control. On a residential line
  this is the posture DRAFT-057 exists to replace.
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
DRAKVUF dirwatch v1.1-git20260806065707+da982ab-1 Copyright (C) 2014-2024 Tamas K Lengyel


root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS
-N DRAKVUF_EGRESS
-A DRAKVUF_EGRESS -i xenbr1.+ -o xenbr0 -j ACCEPT
root@dom0:~/drakvuf-multios-sandbox# ip rule show                     # expect: NO 1000-range rule for this VLAN
0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default


# 9b, 2026-09-04
SANDBOXD_ALLOW_DIRECT=1    .venv-sandboxd/bin/python -m sandboxd.daemon
# After submitting a job
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS_V1
-N DRAKVUF_EGRESS_V1
-A DRAKVUF_EGRESS_V1 -i xenbr1.1 -o xenbr0 -j ACCEPT
-A DRAKVUF_EGRESS_V1 -i xenbr0 -o xenbr1.1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A DRAKVUF_EGRESS_V1 -j DROP
root@dom0:~/drakvuf-multios-sandbox# ip rule show
0:	from all lookup local
32766:	from all lookup main
32767:	from all lookup default
```

**PASS.** `direct` gets the per-VLAN chain and **no policy route** — the same
three-rule shape as `routed` with the uplink substituted for the tunnel. That is
the parameterisation working: one builder, one variable, no mode branch.

---

## Step 10 — modes do not leak between runs. Run this AFTER 9a.

Step 9a deliberately installs the blanket legacy rule:

```
-A DRAKVUF_EGRESS -i xenbr1.+ -o xenbr0 -j ACCEPT
```

That is **every clone, every VLAN, out the residential line, with no per-job
control** — the posture DRAFT-057 exists to replace. It is removed by the next
`network-setup.sh` invocation that does not ask for `direct`, which is what
sandboxd does on every launch. But nothing removes it on a host where 9a was the
last thing that ran, and `argv_revoke` cannot: it deletes per-VLAN specs naming
one VLAN, which cannot match a wildcard.

**This is not hypothetical.** One `ALLOW_DIRECT=1` run once left both rules
standing for the rest of a host's uptime, and every later job — including jobs
submitted, recorded and reported as `offline` — NATted out through them.
`offline` installs no rules at all, so there was nothing to notice the
leftovers with.

**Do not re-run 9a to set this up.** What this step needs is the wildcard
present, and `run_analysis-ubuntu.sh` reaches that only by also starting
dirwatch — a window in which a sample dropped in the watch directory runs with
blanket NAT egress out the residential line. `./automation/network-setup.sh 2
direct` takes the identical branch and starts no watcher.

Better still, run command 1 first and stage nothing: if 9a's wildcard is still
standing, that is the real leftover state, and testing removal against it is
worth more than testing against one just installed for the purpose.

```sh
# 1. what did 9a leave behind? If this shows the wildcard, stage nothing.
iptables -S DRAKVUF_EGRESS
iptables -t nat -S DRAKVUF_EGRESS_NAT

# 2. re-provision the way sandboxd does, with no mode argument.
#    The second argument defaults to `offline`, which is the branch that
#    removes the wildcard. Use the same clone count 9a printed.
./automation/network-setup.sh 2

# 3. gone?
iptables -S DRAKVUF_EGRESS           # expect: -N only, no wildcard
iptables -t nat -S DRAKVUF_EGRESS_NAT

# 4. now submit an OFFLINE job and, while the clone is up:
iptables -S DRAKVUF_EGRESS           # expect: still no wildcard, no _V<n> jump
```

**Step 4 is the one that closes the criterion**, because it asks the question
the way a submitter would: a job that was promised no network must have none,
on a host where a previous job had all of it. Steps 1–3 only show the rule being
removed.

**Do not use a ping from the guest as the check here**, though an earlier
version of this step said to. Silence is what the guest gets either way: had the
wildcard survived, the ping would have left by `xenbr0`, been NATted, and died
upstream because nothing routes TEST-NET-1. The guest cannot see the difference,
so the chain listing is the evidence.

Upgrading this from rule inspection to observation, if you ever want it stated
the way the kill-switch criterion is, means a
`tcpdump -i xenbr0 -n 'net 172.16.0.0/12'` across the offline job — the same
technique as step 6. Not done here, and not needed for the claim: steps 1–3
already prove removal independently of what any one job sees.

`network-setup.sh` announces the posture it reads from the chain rather than the
one it intended — an unconditional "clones have NO route out" was once printed
on a host where every clone had full NAT egress. Read that line as evidence too.

```text
root@dom0:~/drakvuf-multios-sandbox# ./automation/network-setup.sh 2 direct
network-setup.sh: WARNING -- egress mode 'direct': every clone NATs
  out xenbr0 with no per-job control. On a residential line
  this is the posture DRAFT-057 exists to replace.
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS           # expect: -N only, no wildcard
-N DRAKVUF_EGRESS
-A DRAKVUF_EGRESS -i xenbr1.+ -o xenbr0 -j ACCEPT
root@dom0:~/drakvuf-multios-sandbox# iptables -t nat -S DRAKVUF_EGRESS_NAT
-N DRAKVUF_EGRESS_NAT
-A DRAKVUF_EGRESS_NAT -o xenbr0 -j MASQUERADE
root@dom0:~/drakvuf-multios-sandbox# ./automation/network-setup.sh 2
network-setup.sh: provisioned 2 VLAN sub-interface(s) on xenbr1
network-setup.sh: no per-VLAN egress installed -- clones have NO route
  out until an egress mode is applied. Expected under sandboxd, which
  installs one per job. If you are running dirwatch directly, pass
  'direct' as the second argument or clones will observe nothing.
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS           
-N DRAKVUF_EGRESS
root@dom0:~/drakvuf-multios-sandbox# iptables -t nat -S DRAKVUF_EGRESS_NAT
-N DRAKVUF_EGRESS_NAT

# 4 -- an OFFLINE job submitted afterwards, read while its clone was up
root@dom0:~/drakvuf-multios-sandbox# iptables -S DRAKVUF_EGRESS           
-N DRAKVUF_EGRESS
```

**PASS.** The wildcard and its MASQUERADE are removed together, from both
tables, by a `network-setup.sh` run that does not ask for `direct` — and an
`offline` job submitted afterwards, on the same host, gets a chain declaration
and nothing else. No jump, no rule, no inherited egress from the run before it.

`network-setup.sh`'s own announcement is evidence too, and deliberately so: it
reads the chain rather than restating its intent, so `clones have NO route out`
printed only once the chain was genuinely clean. An unconditional version of
that line once printed the same words on a host where every clone had full NAT
egress.

---

## Watch for, but do not fix speculatively

**Large transfers stalling while small ones succeed.** WireGuard's usable MTU
is below the clone's 1500, and malware is not obliged to honour PMTUD. The
signature is a TLS handshake completing and the first big response hanging. If
it appears, the fix is MSS clamping on the tunnel in the per-VLAN chain; it is
in the design record and is deliberately not installed until observed.

## What to record when this is done

- Move this file to `docs/runbooks/14-verify-routed-egress.md`. Every EVIDENCE
  block is filled; the banner is corrected.
- Re-run `scripts/gen-current-state.py`, `scripts/gen-doc-index.py` and
  `scripts/check-refs.py`, and commit the regenerated files with it. Confirm the
  new row reads `yes` in `CURRENT-STATE.md` §3.
- Tick DRAFT-057's kill-switch criterion, and the mode-leak one. **Not the
  country one** — that needs a provider, and this runbook cannot speak to it.
- Capture a trace baseline for the Ubuntu fixture, so 9a's regression check
  becomes answerable for the next change to shared code.
- Destroy the temporary DomU, and remove `local-peer` from `EXITS`. An exit
  left declared against a peer that no longer exists is offered whenever the
  interface happens to be up.
- Anything that went wrong goes to `docs/TROUBLESHOOTING.md`, symptom first.
