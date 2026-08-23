#!/bin/bash
# Issue certificates from this project's internal CA.
#
# Issue #46 (DRAFT-046). Read tls/README.md before using this.
#
# RUN THIS ON A WORKSTATION, NOT ON THE PLATFORM CONTAINER. The CA root key
# is the highest-value key in the system precisely because it can mint
# identities -- including a Dom0 client certificate. Keeping it off the host
# that holds every other credential is the point of the design, so `init`
# refuses to run somewhere that looks like the platform.
#
# There is deliberately no `dhparam` step. Forward secrecy comes from the
# protocol: TLS 1.3 removed static RSA key exchange, and TLS 1.2 negotiates
# ECDHE by default. openssl dhparam supplies parameters for finite-field DHE,
# which 1.3 does not use and which nothing here enables -- the file would be
# read by no one. Key exchange is negotiated per connection and is not carried
# in a certificate, so it is configured on the servers and verified with
# `openssl s_client`, not here.
#
# Not a dirwatch worker script: bash rather than dash, because a person runs
# it and g_spawn never does.
#
# Usage:
#   ./issue-cert.sh init                          # once, ever
#   ./issue-cert.sh server api    192.168.1.10 platform.lan
#   ./issue-cert.sh server minio  192.168.1.10 platform.lan
#   ./issue-cert.sh client dom0-lab
#   ./issue-cert.sh verify api

set -euo pipefail

CA_DIR="${CA_DIR:-$(cd "$(dirname "$0")" && pwd)/ca}"
DAYS_CA="${DAYS_CA:-3650}"
DAYS_LEAF="${DAYS_LEAF:-825}"   # see README on why not longer

umask 077   # before any key is written, not after

die() { echo "issue-cert.sh: $*" >&2; exit 1; }


# Refuse to create a CA on the platform. A heuristic rather than a proof --
# but the failure it prevents (root key on the host holding every other
# credential) is severe enough to warrant an approximate guard, and
# CA_ALLOW_HERE exists for when the heuristic is wrong.
guard_not_platform() {
    [ -n "${CA_ALLOW_HERE:-}" ] && return 0
    if [ -d /opt/platform/src ] || [ "$(hostname)" = "platform" ]; then
        die "this looks like the platform container; the CA root key must not live here.
       Run it on a workstation. Set CA_ALLOW_HERE=1 only if this is wrong."
    fi
}


cmd_init() {
    guard_not_platform
    [ -f "$CA_DIR/ca.key" ] && die "CA already exists at $CA_DIR -- refusing to overwrite.
       Replacing it invalidates every certificate already issued."

    mkdir -p "$CA_DIR"
    openssl genrsa -out "$CA_DIR/ca.key" 4096
    chmod 600 "$CA_DIR/ca.key"

    # pathlen:0 -- this CA signs leaf certificates and cannot sign another CA.
    # Nothing here needs a chain, and forbidding one removes a class of
    # mistake rather than documenting it.
    openssl req -x509 -new -key "$CA_DIR/ca.key" -sha256 -days "$DAYS_CA" \
        -out "$CA_DIR/ca.crt" \
        -subj "/CN=DRAKVUF sandbox internal CA" \
        -addext "basicConstraints=critical,CA:true,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"

    echo "CA created at $CA_DIR"
    echo
    echo "  ca.key  NEVER leaves this machine, and never reaches the platform."
    echo "  ca.crt  the trust anchor -- copy to the platform and to Dom0."
    echo
    openssl x509 -in "$CA_DIR/ca.crt" -noout -enddate
}


# $1 name, $2.. SANs (IP addresses and DNS names, told apart by shape)
cmd_server() {
    local name="${1:?server <name> <san> [san...]}"; shift
    [ $# -ge 1 ] || die "at least one SAN is required"
    [ -f "$CA_DIR/ca.key" ] || die "no CA at $CA_DIR; run 'init' first"

    # SANs, not CN. Modern clients ignore the common name entirely, so a
    # certificate for 192.168.1.10 carrying the address only in CN fails
    # verification -- with an error that does not mention the reason.
    local san="" entry
    for entry in "$@"; do
        if [[ "$entry" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            san+="IP:$entry,"
        else
            san+="DNS:$entry,"
        fi
    done
    # cloudflared reaches its origins over loopback, so every server
    # certificate covers localhost as well as its LAN address.
    san+="IP:127.0.0.1,DNS:localhost"

    openssl genrsa -out "$CA_DIR/$name.key" 2048
    chmod 600 "$CA_DIR/$name.key"
    openssl req -new -key "$CA_DIR/$name.key" -out "$CA_DIR/$name.csr" \
        -subj "/CN=$name"

    # serverAuth ONLY. A certificate valid for both roles could authenticate
    # *to* the service it also identifies, which defeats having two kinds.
    openssl x509 -req -in "$CA_DIR/$name.csr" \
        -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$CA_DIR/$name.crt" -days "$DAYS_LEAF" -sha256 \
        -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature,keyEncipherment\n' "$san")
    rm -f "$CA_DIR/$name.csr"

    echo "server certificate: $CA_DIR/$name.crt"
    openssl x509 -in "$CA_DIR/$name.crt" -noout -ext subjectAltName -enddate
}


cmd_client() {
    local name="${1:?client <worker-id>}"
    [ -f "$CA_DIR/ca.key" ] || die "no CA at $CA_DIR; run 'init' first"

    openssl genrsa -out "$CA_DIR/$name.key" 2048
    chmod 600 "$CA_DIR/$name.key"
    openssl req -new -key "$CA_DIR/$name.key" -out "$CA_DIR/$name.csr" \
        -subj "/CN=$name"

    # clientAuth ONLY -- see the note above. The CN is the worker id for human
    # legibility; NOTHING authorises against it. The bearer token says what a
    # caller may do and lease_owner bounds which jobs it may touch, which is
    # why mTLS here is a transport gate rather than an identity source.
    openssl x509 -req -in "$CA_DIR/$name.csr" \
        -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" -CAcreateserial \
        -out "$CA_DIR/$name.crt" -days "$DAYS_LEAF" -sha256 \
        -extfile <(printf 'extendedKeyUsage=clientAuth\nbasicConstraints=critical,CA:false\nkeyUsage=critical,digitalSignature\n')
    rm -f "$CA_DIR/$name.csr"

    echo "client certificate: $CA_DIR/$name.crt"
    echo "  copy $name.crt, $name.key and ca.crt to that host. Nothing else."
    openssl x509 -in "$CA_DIR/$name.crt" -noout -enddate
}


cmd_verify() {
    local name="${1:?verify <name>}"
    openssl verify -CAfile "$CA_DIR/ca.crt" "$CA_DIR/$name.crt"
    openssl x509 -in "$CA_DIR/$name.crt" -noout -subject -ext subjectAltName \
        -ext extendedKeyUsage -enddate
}


case "${1:-}" in
    init)   shift; cmd_init "$@" ;;
    server) shift; cmd_server "$@" ;;
    client) shift; cmd_client "$@" ;;
    verify) shift; cmd_verify "$@" ;;
    *)      die "usage: $0 {init|server <name> <san>...|client <id>|verify <name>}" ;;
esac