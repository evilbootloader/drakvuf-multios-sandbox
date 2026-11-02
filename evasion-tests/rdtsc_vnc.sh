#!/usr/bin/env bash
# Shows each analysis VM of dom0 in a VNC viewer while it runs. Every benchmark run destroys and
# restores its VM, so the viewer is opened again each time the VM's port answers.
# The viewer is view only, as mouse or keyboard input from it would mix with hidsim's;
# VNC_VIEW_ONLY=0 opens it for input, for runs without hidsim.
# rdtsc_search.sh starts it; it can also run on its own beside a search already running.
#
# Usage: ./rdtsc_vnc.sh   (Ctrl-C closes the viewers)
#   VNC_HOST=192.0.2.10 VNC_PORTS="5900 5901" VNC_VIEWER=vncviewer ./rdtsc_vnc.sh
# The guests' cfgs from misc/xen-vms listen on 127.0.0.1 only: with them, forward the ports
# first (ssh -L 5900:127.0.0.1:5900 -L 5901:127.0.0.1:5901 root@dom0) and keep VNC_HOST=127.0.0.1.
set -uo pipefail
IFS=$'\n\t'

say() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

VNC_HOST=${VNC_HOST:-127.0.0.1}
# The first VM (vncdisplay = 0 in its cfg) takes 5900, the second (vncdisplay = 1) 5901
VNC_PORTS=${VNC_PORTS:-5900 5901}
VNC_VIEWER=${VNC_VIEWER:-$(command -v vncviewer xtigervncviewer 2>/dev/null | head -n 1)}
VNC_VIEW_ONLY=${VNC_VIEW_ONLY:-1}
[[ -n "$VNC_VIEWER" ]] || die 'No vncviewer found: install TigerVNC (tigervnc-viewer) or set VNC_VIEWER.'
[[ -n "${DISPLAY-}${WAYLAND_DISPLAY-}" ]] || die 'No display to open the viewers on.'

# TigerVNC options, those this viewer knows: view only (unless VNC_VIEW_ONLY=0), and exit without
# a dialog when the VM goes
help=$("$VNC_VIEWER" -h 2>&1 || true)
opts=()
for opt in "ViewOnly=$VNC_VIEW_ONLY" Shared=1 AlertOnFatalError=0 ReconnectOnError=0; do
    [[ "$help" != *"${opt%%=*}"* ]] || opts+=("-$opt")
done

# Opens the viewer whenever the port answers, until killed
watch_port() {
    local port=$1
    while :; do
        if timeout 2 bash -c "exec 3<>/dev/tcp/$VNC_HOST/$port" 2>/dev/null; then
            say "$VNC_HOST::$port is up, opening $VNC_VIEWER"
            "$VNC_VIEWER" "${opts[@]}" "$VNC_HOST::$port" >/dev/null 2>&1
        fi
        sleep 2
    done
}

pids=()
# The viewer first: once its watcher is gone it would be orphaned
cleanup() {
    local pid
    for pid in "${pids[@]}"; do
        pkill -P "$pid" 2>/dev/null
        kill "$pid" 2>/dev/null
    done
}
trap cleanup EXIT
trap 'exit 0' INT TERM

say "Watching $VNC_HOST ports $VNC_PORTS with $VNC_VIEWER $(IFS=' '; echo "${opts[*]}")"
IFS=' ' read -r -a ports <<<"$VNC_PORTS"
for port in "${ports[@]}"; do
    [[ "$port" =~ ^[0-9]+$ ]] || die "Bad port '$port' in VNC_PORTS"
    watch_port "$port" &
    pids+=("$!")
done
wait
