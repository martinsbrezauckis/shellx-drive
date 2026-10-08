#!/usr/bin/env python3
"""Verify a controller-signed ShellX Drive macOS terminal attestation."""
import argparse,hashlib,os,re,stat,subprocess,sys,tempfile,types

MODULES=("macos_terminal_attestation_common.py","macos_terminal_attestation_candidate.py")
GPG_FAILURE_STATUSES=frozenset((b"BADSIG",b"ERRSIG",b"EXPSIG",b"EXPKEYSIG",b"FAILURE",b"NODATA",b"NO_PUBKEY",b"REVKEYSIG"))
FINGERPRINT=re.compile(r"^[A-F0-9]{40,64}$")
def load_module(bundle,leaf,name):
    path=os.path.join(bundle,leaf)
    try:
        initial=os.lstat(path)
        if not stat.S_ISREG(initial.st_mode) or stat.S_ISLNK(initial.st_mode) or initial.st_nlink!=1 or initial.st_mode&0o022 or initial.st_size>256*1024: raise RuntimeError("unsafe file identity")
        fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        try: body=os.pread(fd,initial.st_size,0);after=os.fstat(fd);current=os.lstat(path)
        finally: os.close(fd)
        fields=("st_dev","st_ino","st_mode","st_size","st_mtime_ns","st_ctime_ns")
        if len(body)!=initial.st_size or tuple(getattr(initial,key) for key in fields)!=tuple(getattr(after,key) for key in fields) or (after.st_dev,after.st_ino)!=(current.st_dev,current.st_ino): raise RuntimeError("file changed while read")
        module=types.ModuleType(name);module.__file__=path;exec(compile(body.decode("utf-8","strict"),path,"exec"),module.__dict__);return module
    except (OSError,RuntimeError,UnicodeDecodeError,SyntaxError) as error: raise SystemExit(f"FAIL: trusted macOS verifier module {leaf} is invalid: {error}") from None
def trusted_modules():
    script=os.path.abspath(__file__)
    if not sys.flags.isolated or __file__!=script or os.path.islink(script) or os.path.realpath(script)!=script: raise SystemExit("FAIL: terminal verifier requires python3 -I and a normalized absolute non-symlink path")
    common=load_module(os.path.dirname(script),MODULES[0],"shellx_drive_macos_attestation_common")
    sys.modules["macos_terminal_attestation_common"]=common
    return common,load_module(os.path.dirname(script),MODULES[1],"shellx_drive_macos_attestation_candidate")


def protected_tool_path(path, fail, executable=False):
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        fail("gpgv tool or dependency has an unprotected path")
    current = "/"
    for component in path.strip("/").split("/"):
        current = os.path.join(current, component)
        observed = os.lstat(current)
        if stat.S_ISLNK(observed.st_mode) or observed.st_uid != 0 or observed.st_mode & 0o022:
            fail("gpgv tool or dependency has an unprotected path")
        if current != path and not stat.S_ISDIR(observed.st_mode):
            fail("gpgv tool or dependency has an unprotected path")
    if not stat.S_ISREG(observed.st_mode) or observed.st_nlink != 1 or executable and not observed.st_mode & 0o111:
        fail("gpgv tool or dependency has an unprotected path")


def protected_tool(path, fail):
    """Admit only an administrator-owned executable and its loader closure."""
    protected_tool_path(path, fail, executable=True)
    if sys.platform != "darwin":
        return
    # Homebrew's executable can load libraries through mutable `opt` links.
    # Check the complete native loader closure before trusting its status text.
    pending = [path]
    seen = set()
    while pending:
        binary = pending.pop()
        if binary in seen:
            continue
        seen.add(binary)
        result = subprocess.run(["/usr/bin/otool", "-L", binary], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"}, check=False)
        if result.returncode != 0:
            fail("gpgv tool dependency closure could not be inspected")
        lines = result.stdout.decode("utf-8", "strict").splitlines()
        if not lines or lines[0] != binary + ":":
            fail("gpgv tool dependency closure is malformed")
        for line in lines[1:]:
            dependency = line.strip().split(" (compatibility version ", 1)[0]
            if not dependency.startswith("/"):
                fail("gpgv tool dependency has an unresolved loader path")
            if dependency.startswith("/usr/lib/") or dependency.startswith("/System/Library/"):
                continue  # Apple-controlled sealed system libraries.
            protected_tool_path(dependency, fail)
            pending.append(dependency)


def verify_signature(canonical, signature, keyring, fingerprint, gpgv, domain, fail):
    with tempfile.TemporaryDirectory(prefix="shellx-drive-macos-verify-") as temporary:
        os.chmod(temporary, 0o700)
        payload = os.path.join(temporary, "payload")
        signature_path = os.path.join(temporary, "attestation.asc")
        keyring_path = os.path.join(temporary, "release-keyring.gpg")
        gnupg_home = os.path.join(temporary, "gnupg")
        os.mkdir(gnupg_home, 0o700)
        for path, body in ((payload, domain.encode("utf-8") + b"\0" + canonical), (signature_path, signature), (keyring_path, keyring)):
            with open(path, "xb") as output:
                os.chmod(path, 0o600)
                output.write(body)
        result = subprocess.run([gpgv, "--status-fd=1", "--keyring", keyring_path, signature_path, payload], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"GNUPGHOME": gnupg_home, "LC_ALL": "C", "PATH": "/usr/bin:/bin"}, check=False)
        if result.returncode != 0:
            fail("terminal attestation signature did not verify")
        statuses=[line.split() for line in result.stdout.splitlines() if line.startswith(b"[GNUPG:] ")]
        valid=[fields for fields in statuses if len(fields)>=2 and fields[1]==b"VALIDSIG"]
        if any(len(fields)>=2 and fields[1] in GPG_FAILURE_STATUSES for fields in statuses) or len(valid)!=1 or len(valid[0])!=12:
            fail("terminal attestation signature did not bind the pinned fingerprint")
        try: signing_fingerprint=valid[0][2].decode("ascii","strict");primary_fingerprint=valid[0][11].decode("ascii","strict")
        except UnicodeDecodeError: fail("terminal attestation signature did not bind the pinned fingerprint")
        if not FINGERPRINT.fullmatch(signing_fingerprint) or primary_fingerprint!=fingerprint:
            fail("terminal attestation signature did not bind the pinned fingerprint")


def write_receipt(path, value, attestation_bytes, installed_app, pinned_fingerprint, common, candidate):
    candidate.normalized_absolute(path, "output receipt")
    if os.path.exists(path):
        common.fail("output receipt must be fresh")
    parent = os.path.dirname(path)
    observed = candidate.physical(parent, "output receipt parent", "directory")
    if observed.st_uid != os.geteuid() or observed.st_mode & 0o077:
        common.fail("output receipt parent must be private and caller-owned")
    receipt = {"artifacts": value["artifacts"], "attestationSha256": hashlib.sha256(attestation_bytes).hexdigest(), "schema": "shellx-drive.macos-terminal-verification/v1", "source": value["source"], "status": "pass"}
    if installed_app is not None:
        receipt.update({"identity": value["identity"], "installedApp": installed_app, "releaseKeyFingerprint": pinned_fingerprint, "schema": "shellx-drive.macos-installed-verification/v1"})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(f"{common.canonical_json(receipt)}\n".encode("utf-8"))


def main():
    common, candidate = trusted_modules()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-dir", required=True)
    parser.add_argument("--attestation", required=True)
    parser.add_argument("--attestation-signature", required=True)
    parser.add_argument("--keyring", required=True)
    parser.add_argument("--pinned-fingerprint", required=True)
    parser.add_argument("--gpgv", required=True)
    parser.add_argument("--installed-app")
    parser.add_argument("--output-receipt", required=True)
    args = parser.parse_args()
    if not common.FINGERPRINT.fullmatch(args.pinned_fingerprint):
        common.fail("pinned fingerprint must be full uppercase hexadecimal")
    gpgv = candidate.normalized_absolute(args.gpgv, "gpgv tool")
    candidate.physical(gpgv, "gpgv tool", "file")
    protected_tool(gpgv, common.fail)
    candidate_dir = candidate.normalized_absolute(args.candidate_dir, "candidate directory")
    candidate.physical(candidate_dir, "candidate directory", "directory")
    for path, name, label in ((args.attestation, common.ATTESTATION_NAME, "attestation"), (args.attestation_signature, common.SIGNATURE_NAME, "attestation signature")):
        candidate.normalized_absolute(path, label)
        if os.path.basename(path) != name or os.path.dirname(path) != candidate_dir:
            common.fail(f"{label} must be the fixed candidate-root {name}")
    attestation_bytes, _ = candidate.stable_file(args.attestation, "terminal attestation")
    signature, _ = candidate.stable_file(args.attestation_signature, "terminal attestation signature")
    keyring, _ = candidate.stable_file(args.keyring, "pinned verification keyring")
    if not keyring:
        common.fail("pinned verification keyring is empty")
    value, canonical = common.parse_canonical_document(attestation_bytes, "terminal attestation")
    verify_signature(canonical, signature, keyring, args.pinned_fingerprint, gpgv, common.DOMAIN, common.fail)
    common.validate_attestation(value)
    candidate.verify_candidate(value, candidate_dir)
    installed_app = candidate.verify_installed_app(value, args.installed_app) if args.installed_app else None
    write_receipt(args.output_receipt, value, attestation_bytes, installed_app, args.pinned_fingerprint, common, candidate)
    print(f"MACOS_TERMINAL_ATTESTATION_OK receipt={args.output_receipt}")


if __name__ == "__main__":
    try: main()
    except Exception as error:
        if error.__class__.__name__ == "VerificationError": raise SystemExit(f"FAIL: {error}") from None
        raise
