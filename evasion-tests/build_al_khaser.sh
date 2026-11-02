#!/usr/bin/env bash
# Cross-builds al-khaser for x64 Windows with clang-cl and lld-link, using an MSVC CRT
# and Windows SDK unpacked by `xwin splat` (XWIN). Mirrors al-khaser.vcxproj's
# Release|x64 settings, except the CRT is linked statically (/MT) so the binary runs on
# a guest without the Visual C++ redistributables.
#
# The source is upstream al-khaser at AL_KHASER_COMMIT with al-khaser.patch (a code per check,
# for alkhaser_search.sh), cloned into build/al-khaser and reset to that every time. SRC=<dir>
# builds another tree as it is instead (its al-khaser/ directory, the one with pch.h).
#
#   XWIN=/path/to/xwin-sdk ./build_al_khaser.sh [out.exe]   (default build/al-khaser_x64.exe)
set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
XWIN=${XWIN:?set XWIN to the output directory of xwin splat}
AL_KHASER_URL=${AL_KHASER_URL:-https://github.com/ayoubfaouzi/al-khaser.git}
AL_KHASER_COMMIT=${AL_KHASER_COMMIT:-f0e5559073fe02c4f50cc8c3ed8d5b302a6a0659}
AL_KHASER_DIR=${AL_KHASER_DIR:-$SCRIPT_DIR/build/al-khaser}
OUT=${1:-$SCRIPT_DIR/build/al-khaser_x64.exe}
OBJ=${OBJ:-$(mktemp -d)}
JOBS=${JOBS:-$(nproc)}

say() { printf '[%s] %s\n' "$(date '+%F %T')" "$*"; }

for tool in clang-cl lld-link llvm-ml git python3; do
    command -v "$tool" >/dev/null || { say "Missing $tool (clang-cl, lld-link and llvm-ml come with LLVM)"; exit 1; }
done
if [[ -z "${SRC-}" ]]; then
    if [[ ! -e "$AL_KHASER_DIR/.git" ]]; then
        say "Cloning $AL_KHASER_URL into $AL_KHASER_DIR"
        git clone -q "$AL_KHASER_URL" "$AL_KHASER_DIR"
    fi
    git -C "$AL_KHASER_DIR" cat-file -e "$AL_KHASER_COMMIT^{commit}" 2>/dev/null \
        || git -C "$AL_KHASER_DIR" fetch -q origin
    git -C "$AL_KHASER_DIR" checkout -q --detach "$AL_KHASER_COMMIT"
    git -C "$AL_KHASER_DIR" checkout -q -- .
    git -C "$AL_KHASER_DIR" apply "$SCRIPT_DIR/al-khaser.patch"
    say "al-khaser $AL_KHASER_COMMIT with al-khaser.patch in $AL_KHASER_DIR"
    SRC=$AL_KHASER_DIR/al-khaser
fi
mkdir -p "$(dirname "$OUT")"

CFLAGS=(
    --target=x86_64-pc-windows-msvc /nologo /c /O2 /MT /EHsc /GS /Gy /permissive- /std:c++17
    /DNDEBUG /D_CONSOLE /DUNICODE /D_UNICODE
    /imsvc "$XWIN/crt/include"
    /imsvc "$XWIN/sdk/include/ucrt"
    /imsvc "$XWIN/sdk/include/um"
    /imsvc "$XWIN/sdk/include/shared"
    /imsvc "$XWIN/sdk/include/winrt"
    -Wno-everything
)

# Windows paths are case-insensitive: the project's own names (al-khaser.cpp is
# Al-khaser.cpp) and its #includes (Iphlpapi.h, AntiVM/VMware.h) get a link with the
# case they are spelled in, in $OBJ/case
mkdir -p "$OBJ/case"
mapfile -t sources < <(python3 - "$SRC" "$OBJ/case" "${CFLAGS[@]}" <<'EOF'
import os, re, sys
src, fix, flags = sys.argv[1], sys.argv[2], sys.argv[3:]
dirs = [src] + [flags[i + 1] for i, f in enumerate(flags) if f == '/imsvc']

def find(base, rel):
    """rel under base, any case, or None"""
    path = base
    for part in rel.split('/'):
        if part in ('.', '..'):
            path = os.path.normpath(os.path.join(path, part))
            continue
        names = os.listdir(path) if os.path.isdir(path) else []
        match = next((n for n in names if n == part), None) or \
                next((n for n in names if n.lower() == part.lower()), None)
        if match is None:
            return None
        path = os.path.join(path, match)
    return path

for root, _, files in os.walk(src):
    for f in files:
        if not f.endswith(('.cpp', '.h')):
            continue
        text = open(os.path.join(root, f), encoding='latin-1').read()
        for name in re.findall(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', text, re.M):
            name = name.replace('\\', '/')
            if os.path.exists(os.path.join(root, name)) or \
               any(os.path.exists(os.path.join(d, name)) for d in dirs):
                continue
            target = find(root, name) or next(filter(None, (find(d, name) for d in dirs)), None)
            if target and not os.path.isabs(name) and '..' not in name.split('/'):
                os.makedirs(os.path.dirname(os.path.join(fix, name)), exist_ok=True)
                if not os.path.lexists(os.path.join(fix, name)):
                    os.symlink(target, os.path.join(fix, name))

project = open(os.path.join(src, 'al-khaser.vcxproj'), encoding='utf-8-sig').read()
for name in re.findall(r'<ClCompile Include="([^"]+)"', project):
    print(os.path.relpath(find(src, name.replace('\\', '/')), src))
EOF
)
# MSVC's /Yu skips whatever comes before #include "pch.h" (Shared/Utils.cpp includes
# Utils.h first); including pch.h up front does the same
CFLAGS+=(/I "$OBJ/case" /FI"$SRC/pch.h")
asm_sources=(AntiDebug/int2d_x64.asm AntiDisassm/AntiDisassm_x64.asm)

# After --: clang-cl reads a path like /workspaces/... as the /w option
compile() { clang-cl "${CFLAGS[@]}" /Fo"$OBJ/${1//\//_}.obj" -- "$SRC/$1"; }

say "Compiling ${#sources[@]} sources into $OBJ"
rm -f "$OBJ"/*.obj
for src in "${sources[@]}"; do
    compile "$src" &
    while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n || true; done
done
wait
for src in "${sources[@]}"; do
    [[ -f "$OBJ/${src//\//_}.obj" ]] || { say "$src did not compile"; exit 1; }
done

# MASM keeps code labels local to their proc, llvm-ml does not (two procs of
# AntiDisassm_x64.asm define L_END): assemble a copy with each label named after its proc
for asm in "${asm_sources[@]}"; do
    python3 - "$SRC/$asm" "$OBJ/${asm//\//_}" <<'EOF'
import re, sys
lines = open(sys.argv[1], encoding='latin-1').read().replace('\r\n', '\n').split('\n')
out, body, proc = [], [], None
for line in lines:
    m = re.match(r'\s*(\w+)\s+(proc|endp)\b', line, re.I)
    if m and m.group(2).lower() == 'proc':
        proc, body = m.group(1), [line]
        continue
    if proc is None:
        out.append(line)
        continue
    body.append(line)
    if m and m.group(2).lower() == 'endp':
        text = '\n'.join(body)
        for label in set(re.findall(r'^\s*(\w+):(?!:)', text, re.M)):
            text = re.sub(r'\b%s\b' % label, '%s_%s' % (proc, label), text)
        # Nor does it know $: a 5-byte call to $+5 is a call to the next instruction
        text = re.sub(r'^(\s*)call\s+\$\s*\+\s*5\s*$',
                      r'\1call %s_next\n%s_next:' % (proc, proc), text, flags=re.M | re.I)
        # It assembles mov reg, offset sym with a 32-bit absolute address (ADDR32), which a
        # 64-bit image loaded above 4 GB cannot hold: call rcx then faulted. movabs gives
        # ml64's encoding, a 64-bit address (ADDR64)
        text = re.sub(r'^(\s*)mov\s+(\w+)\s*,\s*offset\s+(\w+)\s*$', r'\1movabs \2, offset \3',
                      text, flags=re.M | re.I)
        out.append(text)
        proc = None
open(sys.argv[2], 'w', encoding='latin-1').write('\n'.join(out))
EOF
    llvm-ml -m64 /nologo /c /Fo"$OBJ/${asm//\//_}.obj" -- "$OBJ/${asm//\//_}"
done

libdirs=("$XWIN/crt/lib/x86_64" "$XWIN/sdk/lib/um/x86_64" "$XWIN/sdk/lib/ucrt/x86_64")

# The same for the libraries the sources name in #pragma comment(lib, ...) (Ws2_32.lib)
mkdir -p "$OBJ/caselib"
while read -r lib; do
    for dir in "${libdirs[@]}"; do [[ -e "$dir/$lib" ]] && continue 2; done
    found=$(find "${libdirs[@]}" -maxdepth 1 -iname "$lib" -print -quit)
    [[ -n "$found" ]] && ln -sfn "$found" "$OBJ/caselib/$lib"
done < <(grep -rhoi --include='*.cpp' --include='*.h' 'pragma comment *( *lib *, *"[^"]*"' "$SRC" |
         sed 's/.*"\([^"]*\)"/\1/' | sort -u)

say "Linking $OUT"
lld-link /nologo /subsystem:console /out:"$OUT" /opt:ref /opt:icf \
    /manifest:embed /manifestinput:"$SRC/al-khaser.manifest" \
    /libpath:"$OBJ/caselib" "${libdirs[@]/#//libpath:}" \
    "$OBJ"/*.obj \
    kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib \
    shell32.lib ole32.lib oleaut32.lib uuid.lib

say "Built $OUT ($(stat -c %s "$OUT") bytes)"
