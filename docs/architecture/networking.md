# Network architecture

> Verified-vs-proposed distinction: the current OVS/VLAN setup below is
> confirmed by direct source reading of `automation/network-setup.sh`
> (2026-08-07). The broader containment design goals are carried over from
> the brainstormed workstream list and are not yet implemented.

## Current implementation: `automation/network-setup.sh`

Provisions the isolated per-clone networking that `clone-ubuntu.pl` and
`preconfig-ubuntu.sh` assume already exists:

- `modprobe 8021q` — VLAN kernel module.
- `echo 1 > /proc/sys/net/ipv4/ip_forward` — enables IP forwarding.
- `iptables -t nat -A POSTROUTING -o xenbr0 -j MASQUERADE` — NATs outbound
  traffic via the uplink bridge `xenbr0`.
- `ifconfig xenbr1 up`.
- For each VLAN `1..N` (`N` = clone count argument): `vconfig add xenbr1 $i`,
  gateway `172.16.$i.1/24` on `xenbr1.$i`, and
  `iptables -A FORWARD -i xenbr1.$i -o !xenbr0 -j DROP` (blocks inter-VLAN
  traffic).

This is the source of the `172.16.<VLAN>.1` gateway/nameserver value
hard-coded into `preconfig-ubuntu.sh`, and of the `xenbr1.<vlan>` interface
name `clone-ubuntu.pl` attaches clones to and `tcpdump.sh` captures on.

`xenbr0` is the uplink/production bridge; `xenbr1` is the analysis bridge
(see `CLAUDE.md`'s naming tables). Golden VMs use `xenbr0` directly (see
`misc/linux.cfg`, `misc/android.cfg` — both `vif = [ 'type=ioemu,model=e1000,bridge=xenbr0' ]`,
no VLAN, no `vif-openvswitch` script); sandbox VMs use `xenbr1` with the OVS
vif script (see `misc/linux_sandbox.cfg`, `misc/android_sandbox.cfg` —
`bridge=xenbr1`).

## Known gap: Android network isolation is unverified

`docs/checklists/android.md` §1.3 ("Verify sandbox network isolation TODO")
is explicitly incomplete — the 6-row isolation test table (Dom0 analysis
gateway, Dom0 management IP, Proxmox management IP, another LAN host,
Internet IPv4, Internet IPv6) has no "Actual"/"Passed" values recorded. This
means Android sandbox containment is **unverified, not just undone** —
tracked as DRAFT-013, gating any real (non-benign) sample execution with
networking enabled for Android.

## Proposed containment design (not yet implemented)

Carried over from the brainstormed workstream list, for later design work,
not decided:

- Network modes: `offline`, `simulated`, `controlled-internet`.
- Default-deny; block management interfaces, RFC1918/home-LAN ranges,
  cloud metadata addresses, unintended IPv6 paths.
- Clone-to-clone isolation (the current per-VLAN `DROP` rule in
  `network-setup.sh` is the closest existing mechanism).
- DNS strategy, egress logging, connection/rate limits, emergency kill
  switch.
- Verification tests proving isolation *before* any Internet access is
  enabled for a given analysis.

## TLS visibility — confirmed gap, not solved

DRAKVUF's `tlsmon` plugin (source-verified, `src/plugins/tlsmon/tlsmon.cpp`
in `tklengyel/drakvuf`) hooks Windows `ncrypt.dll`/Schannel specifically —
it has no OpenSSL/BoringSSL hook path and does not work on Linux/Android
guests. Any TLS visibility for Ubuntu/Android analysis requires original
engineering (hypervisor memory scanning, or in-guest key logging — which
conflicts with the project's agentless design goal) or must be deferred.
Tracked as a research spike, DRAFT-023.