#!/usr/bin/env bash
# Externally admitted macOS worker. The controller holds every authority fd.
set -euo pipefail
umask 077

fail() { printf 'FAIL: macOS signed candidate: %s\n' "$*" >&2; exit 1; }
usage() { printf '%s\n' 'Usage: macos-signed-candidate.sh --admission /dev/fd/3 --out <fresh-absolute-candidate-directory>'; }
for unsafe in BASH_ENV ENV PYTHONHOME PYTHONPATH LD_PRELOAD LD_LIBRARY_PATH; do [[ -z "${!unsafe:-}" ]] || fail "unsafe ambient environment: $unsafe"; done
while IFS= read -r variable; do [[ "$variable" != DYLD_* ]] || fail "unsafe ambient environment: $variable"; done < <(compgen -v)
[[ "${BASH_SOURCE[0]}" == /dev/fd/4 ]] || fail "worker descriptor was not externally admitted"
[[ "${PATH:-}" == /* && "${LANG:-}" == C && "${LC_ALL:-}" == C && "${TZ:-}" == UTC ]] || fail "controller did not supply the admitted private environment"
[[ -n "${TAURI_SIGNING_PRIVATE_KEY:-}" && -n "${HOME:-}" && "$HOME" == /* && "$HOME" != */ ]] || fail "required macOS signing authority or HOME is absent"
[[ $# -eq 4 && "$1" == --admission && "$2" == /dev/fd/3 && "$3" == --out && "$4" == /* ]] || { usage >&2; exit 2; }
[[ -r /dev/fd/3 && -r /dev/fd/5 && -r /dev/fd/29 ]] || fail "controller did not retain the admitted admission, parser, and python descriptors"
# Darwin can report success without executing a regular script through
# /dev/fd. Read the admitted descriptor and compile its bytes explicitly.
# The parser checks its own descriptor identity before any build authority.
exec python3 -I -c '
import os, stat, sys
fd = 5
before = os.fstat(fd)
if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 64 * 1024 * 1024:
    raise SystemExit("FAIL: macOS admission parser is not a bounded single-link regular file")
body = os.pread(fd, before.st_size, 0)
after = os.fstat(fd)
identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
if len(body) != before.st_size or identity(before) != identity(after):
    raise SystemExit("FAIL: macOS admission parser changed while read")
sys.argv = sys.argv[1:]
exec(compile(body, "/dev/fd/5", "exec"), {"__name__": "__main__", "__file__": "/dev/fd/5"})
' /dev/fd/5 run-worker --admission /dev/fd/3 --out "$4"
