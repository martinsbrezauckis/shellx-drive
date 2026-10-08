"""Stage and artifact walkers executed inside the admitted helper namespace."""

def stage_digests(root, source):
    root_stat = physical(root, "admitted stage root", "directory")
    require(mode4(root_stat.st_mode) == "0700" and root_stat.st_uid == os.geteuid(), "admitted stage root must stay caller-owned 0700")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    content, descriptors, records = hashlib.sha256(), hashlib.sha256(), []
    object_format = "sha256" if len(source["commit"]) == 64 else "sha1"
    try:
        def walk(directory_fd, prefix=""):
            for name in sorted(os.listdir(directory_fd), key=os.fsencode):
                require(name and "/" not in name and "\0" not in name, "admitted stage contains an unsafe entry name")
                relative = f"{prefix}/{name}" if prefix else name
                child_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
                try:
                    before, mode = os.fstat(child_fd), stat.S_IMODE(os.fstat(child_fd).st_mode)
                    require(before.st_uid == root_stat.st_uid and not mode & 0o022, f"admitted stage entry {relative} has unsafe owner or mode")
                    if stat.S_ISDIR(before.st_mode):
                        descriptors.update(f"D\0{relative}\0{before.st_dev}\0{before.st_ino}\0{mode:o}\n".encode()); walk(child_fd, relative); continue
                    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, f"admitted stage contains unsupported entry {relative}")
                    body_hash, blob_hash, offset = hashlib.sha256(), hashlib.new(object_format), 0
                    blob_hash.update(f"blob {before.st_size}\0".encode())
                    while offset < before.st_size:
                        chunk = os.pread(child_fd, min(1024 * 1024, before.st_size - offset), offset); require(chunk, f"admitted stage file {relative} ended while it was hashed")
                        body_hash.update(chunk); blob_hash.update(chunk); offset += len(chunk)
                    after = os.fstat(child_fd)
                    for field in ("st_dev", "st_ino", "st_size", "st_mtime_ns"): require(getattr(before, field) == getattr(after, field), f"admitted stage file {relative} changed while it was hashed")
                    git_mode = "100755" if before.st_mode & 0o111 else "100644"
                    records.append((os.fsencode(relative), f"{relative}\0{git_mode}\0{blob_hash.hexdigest()}\0{body_hash.hexdigest()}\0{before.st_size}\n".encode()))
                    descriptors.update(f"F\0{relative}\0{before.st_dev}\0{before.st_ino}\0{mode:o}\0{before.st_size}\n".encode())
                finally: os.close(child_fd)
        walk(root_fd)
    finally: os.close(root_fd)
    for _, record in sorted(records, key=lambda item: item[0]): content.update(record)
    root_after = physical(root, "admitted stage root", "directory")
    require((root_after.st_dev, root_after.st_ino, root_after.st_uid, mode4(root_after.st_mode)) == (root_stat.st_dev, root_stat.st_ino, root_stat.st_uid, mode4(root_stat.st_mode)), "admitted stage root changed during inspection")
    return content.hexdigest(), descriptors.hexdigest()

def read_stage_file(stage_fd, relative, label):
    parts = relative.split("/"); require(parts and all(part and part not in (".", "..") for part in parts), f"{label} has an unsafe relative path")
    parent = os.dup(stage_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent); os.close(parent); parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            before = os.fstat(fd); require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_INPUT, f"{label} must be a bounded single-link regular file")
            chunks, offset = [], 0
            while offset < before.st_size:
                chunk = os.pread(fd, min(1024 * 1024, before.st_size - offset), offset); require(chunk, f"{label} ended while it was read")
                chunks.append(chunk); offset += len(chunk)
            stable(before, os.fstat(fd), label); return b"".join(chunks)
        finally: os.close(fd)
    finally: os.close(parent)

def require_runtime_contract(stage_fd):
    required = {"desktop/src-tauri/src/main.rs": b'cfg(target_os = "macos")', "desktop/src-tauri/src/application/macos/shell.rs": b"run_uninstall_cleanup_with_lease", "desktop/src-tauri/src/application/unix_uninstall/remote.rs": b"PendingMacOsCredentialStore", "desktop/src-tauri/src/application/unix_uninstall.rs": b"remove_owned_launch_at_login", "desktop/macos-acceptance/macos-uninstall-proof-core.sh": b"macos_uninstall_proof_open_root"}
    for relative, marker in required.items(): require(marker in read_stage_file(stage_fd, relative, f"macOS runtime contract {relative}"), f"macOS runtime contract is missing {marker.decode()}")
def safe_leaf(name, label):
    require(name not in ("", ".", "..") and os.path.basename(name) == name and "\0" not in name and "\r" not in name and "\n" not in name, f"{label} must be a safe basename"); return name
def one_artifact(directory, suffix, kind, label):
    physical(directory, label, "directory"); matches = []
    for name in os.listdir(directory):
        path, observed = os.path.join(directory, name), os.lstat(os.path.join(directory, name))
        if name.endswith(suffix) and not stat.S_ISLNK(observed.st_mode) and ((kind == "directory" and stat.S_ISDIR(observed.st_mode)) or (kind == "file" and stat.S_ISREG(observed.st_mode))): matches.append(path)
    require(len(matches) == 1, f"{label} must contain exactly one {suffix} artifact"); physical(matches[0], f"{label} artifact", kind); return matches[0]
def artifact_file(path, label):
    observed = inspect_regular(path, label); return {"name": safe_leaf(os.path.basename(path), label), "sha256": observed["sha256"], "size": observed["size"]}
def inspect_app_tree(app):
    root, physical_root = physical(app, "macOS app bundle", "directory"), os.path.realpath(app)
    records, normalized_paths, file_count, total_bytes = [f"D\0.\0{mode4(root.st_mode)}\n"], {"."}, 0, 0
    def walk(directory, parent=""):
        nonlocal file_count, total_bytes
        entries = []
        for raw in os.listdir(directory):
            normalized = unicodedata.normalize("NFC", raw); require(raw and "/" not in raw and "\0" not in raw and "\r" not in raw and "\n" not in raw and raw == normalized, "macOS app tree has an unsafe non-NFC entry"); entries.append((raw, normalized))
        for raw, normalized in sorted(entries, key=lambda item: item[1].encode("utf-8")):
            relative = f"{parent}/{normalized}" if parent else normalized; require(relative not in normalized_paths, f"macOS app tree has an NFC-normalized path collision at {relative}")
            normalized_paths.add(relative); absolute, observed = os.path.join(directory, raw), os.lstat(os.path.join(directory, raw))
            if stat.S_ISDIR(observed.st_mode):
                require(os.path.realpath(absolute).startswith(f"{physical_root}/"), f"macOS app directory {relative} escapes the bundle"); records.append(f"D\0{relative}\0{mode4(observed.st_mode)}\n"); walk(absolute, relative)
            elif stat.S_ISREG(observed.st_mode):
                after = inspect_regular(absolute, f"macOS app file {relative}"); records.append(f"F\0{relative}\0{after['mode']}\0{after['size']}\0{after['sha256']}\n"); file_count += 1; total_bytes += after["size"]
            elif stat.S_ISLNK(observed.st_mode):
                target = os.readlink(absolute); normalized_target = unicodedata.normalize("NFC", target)
                require(target and not os.path.isabs(target) and target == normalized_target and "\0" not in target and "\r" not in target and "\n" not in target, f"macOS app symlink {relative} has a noncanonical target")
                resolved = os.path.realpath(os.path.join(os.path.dirname(absolute), target)); require(resolved == physical_root or resolved.startswith(f"{physical_root}/"), f"macOS app symlink {relative} escapes the bundle"); records.append(f"L\0{relative}\0{normalized_target}\n")
            else: fail(f"macOS app tree contains unsupported entry {relative}")
    walk(app); root_after = physical(app, "macOS app bundle", "directory")
    for field in ("st_dev", "st_ino", "st_uid", "st_mode", "st_mtime_ns", "st_ctime_ns"): require(getattr(root, field) == getattr(root_after, field), "macOS app root changed during inspection")
    return {"treeDigest": hashlib.sha256("".join(records).encode()).hexdigest(), "fileCount": file_count, "totalBytes": total_bytes}
def output_file(path, data):
    physical(os.path.dirname(path), f"output parent for {os.path.basename(path)}", "directory"); fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:]); require(written > 0, f"failed to write {path}"); offset += written
        os.fsync(fd)
    finally: os.close(fd)
def output_canonical(path, value): output_file(path, f"{canonical_json(value)}\n".encode("utf-8"))
def parse_codesign(raw):
    text = raw.decode("utf-8", "replace")
    def field(pattern, label):
        match = re.search(pattern, text, re.MULTILINE); require(match is not None, f"codesign evidence lacks {label}"); return match.group(1).strip()
    identifier, team, cdhash, designated = field(r"^Identifier=(.+)$", "bundle identifier"), field(r"^TeamIdentifier=(.+)$", "team identifier"), field(r"^CDHash=([A-Fa-f0-9]{40,64})$", "CDHash"), field(r"^designated => (.+)$", "designated requirement")
    require(identifier == "com.shellx.drive.desktop" and team == EXPECTED_TEAM_ID and EXPECTED_IDENTITY in text, "signed app identity drifted")
    return {"bundleIdentifier": identifier, "teamIdentifier": team, "cdHash": cdhash, "designatedRequirement": designated}
