#!/bin/sh
# Fixed guest workload of benchmark_drakvuf.sh. DRAKVUF's injector copies it into the
# guest and starts it in every run; it loops until the guest is destroyed. Each round
# touches files, starts processes (new libraries for libmon), reads /etc and opens a socket.
dir=/tmp/drakvuf-workload
mkdir -p "$dir"
# The plugins start after the injection
sleep 3
i=0
while :; do
    i=$((i + 1))
    f="$dir/file-$((i % 16))"
    head -c 65536 /dev/urandom >"$f"
    sha256sum "$f" >"$f.sum"
    cp "$f" "$f.copy" && mv "$f.copy" "$f.moved" && rm -f "$f.moved"
    ls -la /usr/bin >/dev/null
    cat /etc/passwd /etc/hosts /etc/os-release >/dev/null
    ps aux >/dev/null
    getent hosts localhost >/dev/null
    python3 -c 'import hashlib, json, socket; socket.socket().close(); json.dumps({"x": hashlib.sha256(b"x" * 4096).hexdigest()})' 2>/dev/null
    echo "$i" >"$dir/iterations"
done
