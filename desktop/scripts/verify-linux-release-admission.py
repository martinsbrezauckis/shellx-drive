#!/usr/bin/env python3
"""Validate the controller-owned Linux release admission and emit shell-safe fields."""
import argparse, hashlib, json, os, pathlib, re, stat, unicodedata

SCHEMA = "release-studio.shellx-drive-linux-admission.v1"
REQUIRED_TOOLS = {"bash", "node", "pnpm", "tauri-cli", "cargo", "python3", "dpkg-sig", "dpkg-deb", "unsquashfs", "gpg", "gpgv", "appimage-validator", "tauri-updater-verifier", "stat", "sha256sum", "install", "cmp", "mktemp", "mkdir", "chmod", "mv", "rm", "grep", "find", "awk", "uname"}
SOURCE_DESCRIPTOR_PATHS = {"linux-release-common":"desktop/scripts/linux-release-common.sh","linux-build-artifacts":"desktop/scripts/linux-build-artifacts.sh","write-linux-build-config":"desktop/scripts/write-linux-build-config.py","verify-linux-package-layout":"desktop/scripts/verify-linux-package-layout.py","linux-candidate-manifest":"desktop/scripts/linux-candidate-manifest.mjs","updater-candidate-core":"desktop/scripts/updater-candidate-core.mjs","write-linux-worker-observation":"desktop/scripts/write-linux-worker-observation.py","linux-verify-candidate":"desktop/scripts/linux-verify-candidate.sh","verify-linux-candidate-manifest":"desktop/scripts/verify-linux-candidate-manifest.py","verify-linux-verifier-attestation":"desktop/scripts/verify-linux-verifier-attestation.py","tauri-config":"desktop/src-tauri/tauri.conf.json","tauri-linux-config":"desktop/src-tauri/tauri.linux.conf.json","verify-linux-trusted-release":"desktop/scripts/verify-linux-trusted-release.py","verify-linux-trusted-common":"desktop/scripts/verify-linux-trusted-common.py","verify-linux-trusted-candidate":"desktop/scripts/verify-linux-trusted-candidate.py"}

def fail(message):
    raise SystemExit(f"FAIL: {message}")

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb", buffering=0) as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def digest_fd(fd,size):
    h=hashlib.sha256();offset=0
    while offset<size:
        chunk=os.pread(fd,min(1024*1024,size-offset),offset)
        if not chunk:break
        h.update(chunk);offset+=len(chunk)
    return h.hexdigest()

def stage_digests(root,object_format="sha1"):
    root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); root_meta=os.fstat(root_fd)
    if stat.S_IMODE(root_meta.st_mode)!=0o700 or root_meta.st_uid!=os.getuid(): fail("stage root must be caller-owned 0700")
    content=hashlib.sha256(); descriptor=hashlib.sha256();file_records=[]
    def walk(directory_fd,prefix=""):
        names=sorted((entry.name for entry in os.scandir(directory_fd)),key=os.fsencode)
        for name in names:
            relative=f"{prefix}/{name}" if prefix else name; fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd); before=os.fstat(fd)
            if before.st_uid!=root_meta.st_uid or stat.S_IMODE(before.st_mode)&0o022: fail("stage contains unsafe identity")
            if stat.S_ISDIR(before.st_mode):
                descriptor.update(f"D\0{relative}\0{before.st_dev}\0{before.st_ino}\0{stat.S_IMODE(before.st_mode):o}\n".encode()); walk(fd,relative); os.close(fd); continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: fail("stage contains unsupported entry")
            chunks=[]
            while chunk:=os.read(fd,1024*1024): chunks.append(chunk)
            after=os.fstat(fd);os.close(fd)
            if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): fail("stage file changed while hashing")
            body=b"".join(chunks);file_sha=hashlib.sha256(body).hexdigest();blob_oid=hashlib.new(object_format,f"blob {len(body)}\0".encode()+body).hexdigest();git_mode="100755" if before.st_mode&0o111 else "100644"
            file_records.append((relative,f"{relative}\0{git_mode}\0{blob_oid}\0{file_sha}\0{before.st_size}\n".encode()));descriptor.update(f"F\0{relative}\0{before.st_dev}\0{before.st_ino}\0{stat.S_IMODE(before.st_mode):o}\0{before.st_size}\n".encode())
    walk(root_fd);os.close(root_fd)
    for _,record in sorted(file_records,key=lambda item:item[0].encode()):content.update(record)
    return content.hexdigest(),descriptor.hexdigest()

def immutable_tree_digest(root,owner):
    root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); tree=hashlib.sha256();descriptor=hashlib.sha256()
    def walk(directory_fd,prefix=""):
        names=sorted((entry.name for entry in os.scandir(directory_fd)),key=lambda name:unicodedata.normalize("NFC",name).encode())
        for name in names:
            if name!=unicodedata.normalize("NFC",name): fail("runtime tree name is not NFC")
            relative=f"{prefix}/{name}" if prefix else name;fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory_fd);before=os.fstat(fd);mode=stat.S_IMODE(before.st_mode)
            if before.st_uid!=owner or mode&0o022: fail("runtime tree identity is unsafe")
            if stat.S_ISDIR(before.st_mode): tree.update(f"D\0{relative}\0{mode:o}\n".encode());descriptor.update(f"D\0{relative}\0{before.st_dev}\0{before.st_ino}\0{mode:o}\n".encode());walk(fd,relative);os.close(fd);continue
            if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1: fail("runtime tree contains unsupported entry")
            h=hashlib.sha256()
            while chunk:=os.read(fd,1024*1024):h.update(chunk)
            after=os.fstat(fd);os.close(fd)
            if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns): fail("runtime tree changed while hashing")
            tree.update(f"F\0{relative}\0{mode:o}\0{before.st_size}\0{h.hexdigest()}\n".encode());descriptor.update(f"F\0{relative}\0{before.st_dev}\0{before.st_ino}\0{mode:o}\0{before.st_size}\n".encode())
    walk(root_fd);os.close(root_fd);return tree.hexdigest(),descriptor.hexdigest()

parser = argparse.ArgumentParser()
parser.add_argument("action", choices=("inspect-stage", "verify-admission", "verify-continuity"))
parser.add_argument("--admission")
parser.add_argument("--stage-root", required=True)
parser.add_argument("--output-root")
parser.add_argument("--format", choices=("shell","json"), required=True)
args = parser.parse_args()
if args.action=="inspect-stage":
    if args.format!="json": fail("inspect-stage requires JSON output")
    content,descriptor=stage_digests(pathlib.Path(args.stage_root));print(json.dumps({"fullStageDigest":content,"descriptorDigest":descriptor},sort_keys=True,separators=(",",":")));raise SystemExit(0)
if not args.admission or not args.output_root or args.format!="shell": fail("admission verification arguments are incomplete")
admission = pathlib.Path(args.admission)
if str(admission) != "/dev/fd/3": fail("admission must remain bound to controller fd3")
if any(name.startswith("PYTHON") for name in os.environ): fail("Python ambient environment is forbidden")
meta=os.fstat(3)
if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o600 or meta.st_nlink != 1: fail("admission fd must be a 0600 single-link regular file")
try:
    os.lseek(3,0,os.SEEK_SET); data = json.loads(os.read(3,meta.st_size).decode("utf-8"))
except Exception as error:
    fail(f"admission is not valid JSON: {error}")
if data.get("schema") != SCHEMA or data.get("project") != "shellx-drive" or data.get("version") != "0.1.0":
    fail("admission schema, project, or version is invalid")
if set(data)!={"schema","project","version","source","fullStageDigest","stageRoot","generatedStateRoot","outputRoot","releaseStudio","toolchainManifest","tools","releaseIdentity","runtime"}: fail("admission has unexpected or missing fields")
if set(data.get("releaseStudio",{}))!={"commit","tree","controllerSha256","admissionHelperSha256"}: fail("releaseStudio identity shape is invalid")
release=data.get("releaseIdentity",{}); keyring=release.get("keyring",{})
if set(release)!={"schema","signerFingerprint","identityPath","identitySha256","keyring"} or release.get("schema")!="release-studio.shellx-drive-linux-release-identity.v1" or not isinstance(release.get("signerFingerprint"),str) or not 40<=len(release["signerFingerprint"])<=64 or not release["signerFingerprint"].isalnum() or release["signerFingerprint"]!=release["signerFingerprint"].upper(): fail("release identity is invalid")
identity_path=pathlib.Path(release.get("identityPath",""))
if not identity_path.is_absolute() or identity_path.is_symlink() or not identity_path.is_file() or digest(identity_path)!=release.get("identitySha256"): fail("release identity source changed")
identity=json.loads(identity_path.read_text(encoding="utf-8"))
if identity.get("schema")!=release["schema"] or identity.get("signerFingerprint")!=release["signerFingerprint"]: fail("release identity source does not match admission")
keyring_path=pathlib.Path(keyring.get("path","")); keyring_meta=keyring_path.lstat() if keyring_path.is_absolute() else None
if set(keyring)!={"path","sha256","dev","inode","uid","mode"} or keyring_meta is None or not stat.S_ISREG(keyring_meta.st_mode) or stat.S_ISLNK(keyring_meta.st_mode) or keyring_meta.st_nlink!=1 or (str(keyring_meta.st_dev),str(keyring_meta.st_ino),keyring_meta.st_uid,f"{stat.S_IMODE(keyring_meta.st_mode):04o}")!=(keyring.get("dev"),keyring.get("inode"),keyring.get("uid"),keyring.get("mode")) or digest(keyring_path)!=keyring.get("sha256"): fail("release keyring identity changed")
stage_identity = data.get("stageRoot", {})
if set(stage_identity)!={"path","dev","inode","uid","mode","descriptorDigest"}: fail("stageRoot shape is invalid")
stage = pathlib.Path(stage_identity.get("path", "")) if isinstance(stage_identity, dict) else pathlib.Path("")
stage_meta = stage.stat() if stage.is_absolute() else None
if not stage.is_absolute() or stage.resolve(strict=True) != pathlib.Path(args.stage_root).resolve(strict=True):
    fail("admitted stageRoot does not equal the worker physical source root")
if (str(stage_meta.st_dev), str(stage_meta.st_ino), stage_meta.st_uid, f"{stat.S_IMODE(stage_meta.st_mode):04o}") != (stage_identity.get("dev"), stage_identity.get("inode"), stage_identity.get("uid"), stage_identity.get("mode")):
    fail("admitted stageRoot descriptor identity changed")
stage_content_digest,stage_descriptor_digest=stage_digests(stage,"sha256" if len(data.get("source",{}).get("commit",""))==64 else "sha1")
if stage_content_digest!=data.get("fullStageDigest") or stage_descriptor_digest!=stage_identity.get("descriptorDigest"): fail("admitted full-stage identity changed")
generated = data.get("generatedStateRoot", {}); generated_path=pathlib.Path(generated.get("path", ""))
if set(generated)!={"path","dev","inode","uid","mode"}: fail("generatedStateRoot shape is invalid")
generated_meta=generated_path.stat() if generated_path.is_absolute() else None
if generated_meta is None or stat.S_IMODE(generated_meta.st_mode)!=0o700 or (str(generated_meta.st_dev),str(generated_meta.st_ino),generated_meta.st_uid,f"{stat.S_IMODE(generated_meta.st_mode):04o}")!=(generated.get("dev"),generated.get("inode"),generated.get("uid"),generated.get("mode")): fail("generated state root identity is invalid")
output=pathlib.Path(data.get("outputRoot", ""))
if not output.is_absolute() or str(output)!=args.output_root or output.parent.resolve(strict=True)!=generated_path.resolve(strict=True): fail("outputRoot must be one direct child of generatedStateRoot")
if args.action == "verify-continuity":
    if not output.is_dir() or output.is_symlink() or stat.S_IMODE(output.stat().st_mode)!=0o700: fail("post-build outputRoot identity is invalid")
elif output.exists(): fail("outputRoot must be fresh before worker entry")
runtime=data.get("runtime",{}); gnupg=runtime.get("gnupgHome",{}); tool_path=runtime.get("toolPathRoot",{})
parser_identity=runtime.get("admissionParser",{});worker_identity=runtime.get("worker",{});source_descriptors=runtime.get("sourceDescriptors",{})
if set(runtime)!={"gnupgHome","toolPathRoot","dependencyRoots","toolDescriptors","admissionParser","worker","sourceDescriptors"} or set(parser_identity)!={"path","sha256","dev","inode","uid","mode"} or set(worker_identity)!={"path","sha256","dev","inode","uid","mode"} or set(gnupg)!={"path","dev","inode","uid","mode"} or set(tool_path)!={"path","treeDigest","descriptorDigest","dev","inode","uid","mode"}: fail("runtime shape is invalid")
worker_meta=os.fstat(4)
if worker_identity["path"]!=str(stage/"desktop/scripts/linux-sign-candidate.sh") or (str(worker_meta.st_dev),str(worker_meta.st_ino),worker_meta.st_uid,f"{stat.S_IMODE(worker_meta.st_mode):04o}")!=(worker_identity["dev"],worker_identity["inode"],worker_identity["uid"],worker_identity["mode"]) or not stat.S_ISREG(worker_meta.st_mode) or worker_meta.st_nlink!=1 or not worker_meta.st_mode&0o111 or stat.S_IMODE(worker_meta.st_mode)&0o022 or digest_fd(4,worker_meta.st_size)!=worker_identity["sha256"]: fail("release worker descriptor identity changed")
parser_meta=os.fstat(5)
if parser_identity["path"]!=str(stage/"desktop/scripts/verify-linux-release-admission.py") or (str(parser_meta.st_dev),str(parser_meta.st_ino),parser_meta.st_uid,f"{stat.S_IMODE(parser_meta.st_mode):04o}")!=(parser_identity["dev"],parser_identity["inode"],parser_identity["uid"],parser_identity["mode"]) or not stat.S_ISREG(parser_meta.st_mode) or parser_meta.st_nlink!=1 or digest_fd(5,parser_meta.st_size)!=parser_identity["sha256"]: fail("admission parser descriptor identity changed")
if set(source_descriptors)!=set(SOURCE_DESCRIPTOR_PATHS): fail("source descriptor map is incomplete")
for index,(descriptor_id,relative) in enumerate(SOURCE_DESCRIPTOR_PATHS.items(),100):
    item=source_descriptors[descriptor_id];fd=item.get("fd") if isinstance(item,dict) else None
    if set(item)!={"fd","path","sha256","dev","inode","uid","mode"} or fd!=index or item["path"]!=str(stage/relative): fail(f"source descriptor shape is invalid: {descriptor_id}")
    held=os.fstat(fd);actual=(str(held.st_dev),str(held.st_ino),held.st_uid,f"{stat.S_IMODE(held.st_mode):04o}")
    if not stat.S_ISREG(held.st_mode) or held.st_nlink!=1 or actual!=(item["dev"],item["inode"],item["uid"],item["mode"]) or digest_fd(fd,held.st_size)!=item["sha256"]: fail(f"source descriptor changed: {descriptor_id}")
for label,item,want_mode in (("GNUPG home",gnupg,"0700"),("tool PATH root",tool_path,"0700")):
    path=pathlib.Path(item.get("path","")); item_meta=path.stat() if path.is_absolute() else None
    if item_meta is None or (str(item_meta.st_dev),str(item_meta.st_ino),item_meta.st_uid,f"{stat.S_IMODE(item_meta.st_mode):04o}")!=(item.get("dev"),item.get("inode"),item.get("uid"),item.get("mode")) or item.get("mode")!=want_mode: fail(f"{label} identity is invalid")
if immutable_tree_digest(pathlib.Path(tool_path["path"]),tool_path["uid"])!=(tool_path["treeDigest"],tool_path["descriptorDigest"]): fail("tool PATH tree digest changed")
if os.environ.get("PATH")!=tool_path.get("path") or os.environ.get("GNUPGHOME")!=gnupg.get("path"): fail("runtime PATH or GNUPGHOME escaped admission")
source = data.get("source", {})
if not isinstance(source, dict) or set(source)!={"commit","tree"} or not all(isinstance(source.get(k), str) and len(source[k]) == 40 for k in ("commit", "tree")):
    fail("source commit/tree identity is invalid")
if not isinstance(data.get("fullStageDigest"), str) or len(data["fullStageDigest"]) != 64:
    fail("fullStageDigest is invalid")
manifest = data.get("toolchainManifest", {})
if not isinstance(manifest, dict) or set(manifest)!={"path","sha256"} or not pathlib.Path(manifest.get("path", "")).is_absolute() or len(manifest.get("sha256", "")) != 64:
    fail("toolchainManifest identity is invalid")
if digest(manifest["path"]) != manifest["sha256"]:
    fail("toolchain manifest digest changed")
toolchain_data=json.loads(pathlib.Path(manifest["path"]).read_text(encoding="utf-8"));dependencies=runtime.get("dependencyRoots",{})
if set(toolchain_data)!={"schema","host","tools","aliases","dependencyRoots","trace"}: fail("toolchain manifest shape is invalid")
trace=toolchain_data["trace"]
if set(trace)!={"schema","status","source","argvSha256","executableAliases"} or trace["schema"]!="release-studio.shellx-drive-linux-tool-trace.v1" or trace["status"]!="pass" or trace["source"]!=data["source"] or not isinstance(trace["argvSha256"],str) or len(trace["argvSha256"])!=64 or not isinstance(trace["executableAliases"],list) or any(alias not in toolchain_data["aliases"] for alias in trace["executableAliases"]): fail("toolchain execution trace is invalid")
if toolchain_data.get("dependencyRoots")!=dependencies: fail("runtime dependency roots differ from toolchain manifest")
for dep_id,item in dependencies.items():
    if set(item)!={"path","treeDigest","descriptorDigest","dev","inode","uid","mode"}: fail(f"dependency root shape is invalid: {dep_id}")
    path=pathlib.Path(item.get("path",""));meta=path.stat() if path.is_absolute() else None
    if meta is None or (str(meta.st_dev),str(meta.st_ino),meta.st_uid,f"{stat.S_IMODE(meta.st_mode):04o}")!=(item.get("dev"),item.get("inode"),item.get("uid"),item.get("mode")) or immutable_tree_digest(path,item["uid"])!=(item["treeDigest"],item["descriptorDigest"]): fail(f"dependency root changed: {dep_id}")
tools = data.get("tools")
if not isinstance(tools, dict) or not REQUIRED_TOOLS.issubset(tools):
    fail("admission lacks required pinned tools")
if toolchain_data["tools"]!=tools: fail("admitted tools differ from toolchain manifest")
tool_variables={}
for tool_id in tools:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*",tool_id): fail(f"unsafe tool id: {tool_id}")
    variable=re.sub(r"[._-]","_",tool_id.upper())
    if variable in tool_variables: fail(f"tool ids collide as TOOL_{variable}")
    tool_variables[variable]=tool_id
descriptors=runtime["toolDescriptors"]
expected_descriptors={tool_id:10+index for index,tool_id in enumerate(sorted(tools,key=lambda value:value.encode()))}
if descriptors!=expected_descriptors: fail("tool descriptor map is incomplete or nondeterministic")
for tool_id, item in tools.items():
    if not isinstance(item, dict): fail(f"tool {tool_id} is malformed")
    if set(item)!={"path","sha256","dev","inode","uid","mode"}: fail(f"tool {tool_id} shape is invalid")
    path = pathlib.Path(item.get("path", ""));fd=descriptors[tool_id]
    try: tool_meta = os.fstat(fd)
    except OSError: fail(f"tool descriptor {tool_id} is unavailable")
    expected = (item.get("dev"), item.get("inode"), item.get("uid"), item.get("mode"))
    actual = (str(tool_meta.st_dev), str(tool_meta.st_ino), tool_meta.st_uid, f"{stat.S_IMODE(tool_meta.st_mode):04o}")
    if not path.is_absolute() or not stat.S_ISREG(tool_meta.st_mode) or tool_meta.st_nlink != 1 or not tool_meta.st_mode&0o111:
        fail(f"tool {tool_id} is not an admitted executable regular file")
    if actual != expected or digest_fd(fd,tool_meta.st_size) != item.get("sha256") or stat.S_IMODE(tool_meta.st_mode) & 0o022:
        fail(f"tool {tool_id} identity changed")
python_meta=os.stat("/proc/self/exe");python_fd_meta=os.fstat(descriptors["python3"])
if (python_meta.st_dev,python_meta.st_ino)!=(python_fd_meta.st_dev,python_fd_meta.st_ino): fail("controller did not admit the bootstrap parser identity")
for name, value in {
    "ADMISSION_SOURCE_COMMIT": source["commit"], "ADMISSION_SOURCE_TREE": source["tree"],
    "ADMISSION_STAGE_DIGEST": data["fullStageDigest"], "ADMISSION_TOOLCHAIN_SHA256": manifest["sha256"],
    "ADMISSION_DESCRIPTOR_DIGEST": stage_identity["descriptorDigest"],
    "ADMISSION_OUTPUT_ROOT": str(output),
    "ADMISSION_TOOL_PATH_ROOT": tool_path["path"],
    "ADMISSION_RELEASE_FINGERPRINT": release["signerFingerprint"],
    "ADMISSION_RELEASE_KEYRING": str(keyring_path),
    "ADMISSION_RELEASE_KEYRING_SHA256": keyring["sha256"],
}.items(): print(f"{name}={value}")
for tool_id, item in tools.items():
    if any(c in item["path"] for c in "\r\n="): fail("unsafe tool assignment")
    variable=re.sub(r"[._-]","_",tool_id.upper())
    print(f"TOOL_{variable}=/dev/fd/{descriptors[tool_id]}")
