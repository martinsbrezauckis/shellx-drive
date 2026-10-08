"""Descriptor-bound macOS admission, continuity, and tool execution."""
import hashlib,json,os,re,stat,subprocess,unicodedata

TOOLCHAIN_SCHEMA="release-studio.shellx-drive-macos-toolchain.v1"
TOOL_TRACE_SCHEMA="release-studio.shellx-drive-macos-tool-trace.v1"
OBSERVATION_SCHEMA="shellx-drive.macos-worker-observation/v1"
PROJECT,PLATFORM="shellx-drive","macos-arm64"
EXPECTED_IDENTITY="Developer ID Application: Martins Brezauckis (4M329JW6R4)"
EXPECTED_TEAM_ID="4M329JW6R4";EXPECTED_CERTIFICATE_SHA1="11BE2A1FCEC2B6E5395C42173CB4CFFA574A853B"
NOTARY_PROFILE,TARGET="shellx-notary","aarch64-apple-darwin"
EVIDENCE_FILES={"codesign":"codesign.txt","entitlements":"signed-entitlements.plist","gatekeeper":"gatekeeper.txt","notarytool":"notarytool-result.json","stapler":"stapler.txt","updaterVerifier":"updater-verifier.txt","workerComplete":"worker-complete.json"}
HELD_FDS=tuple(sorted({3,4,5,*TOOL_FDS.values(),*SOURCE_FDS.values()}));CURRENT_ADMISSION=None
def require(value,message):
 if not value: fail(message)
def mode4(value): return f"{stat.S_IMODE(value):04o}"
def safe_integer(value,label): require(isinstance(value,int) and not isinstance(value,bool) and 0<=value<=2**53-1,f"{label} must be a non-negative safe integer")
def git_oid(value,label): require(isinstance(value,str) and re.fullmatch(r"[0-9a-f]{40}",value),f"{label} must be a 40-character lowercase Git oid")
def sha256(value,label): require(isinstance(value,str) and re.fullmatch(r"[0-9a-f]{64}",value),f"{label} must be a lowercase SHA-256")
def exact_keys(value,keys,label): require(isinstance(value,dict) and set(value)==set(keys),f"{label} has unexpected or missing fields")
def validate_nfc(value,label="canonical JSON"):
 if isinstance(value,str): require(value==unicodedata.normalize("NFC",value) and not any(0xd800<=ord(char)<=0xdfff for char in value),f"{label} is not NFC")
 elif isinstance(value,list):
  for item in value:validate_nfc(item,label)
 elif isinstance(value,dict):
  for key,item in value.items():validate_nfc(key,label);validate_nfc(item,label)
 elif value is not None and not isinstance(value,(bool,int)): fail(f"{label} has unsupported data")
def canonical_json(value): validate_nfc(value);return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False)
def stable(before,after,label):
 for key in ("st_dev","st_ino","st_uid","st_mode","st_size","st_mtime_ns","st_ctime_ns"):require(getattr(before,key)==getattr(after,key),f"{label} changed while inspected")
def physical(path,label,kind):
 require(normalized(path),f"{label} path is malformed")
 try:observed=os.lstat(path)
 except OSError as error:fail(f"{label} cannot be inspected: {error}")
 require(not stat.S_ISLNK(observed.st_mode) and os.path.realpath(path)==path and ((kind=="file" and stat.S_ISREG(observed.st_mode)) or (kind=="directory" and stat.S_ISDIR(observed.st_mode))),f"{label} is not a physical {kind}");return observed
def read_regular(path,label,limit=MAX_INPUT):
 physical(path,label,"file");fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd);require(before.st_nlink==1 and before.st_size<=limit,f"{label} is not a bounded single-link regular file");body=os.pread(fd,before.st_size,0);after=os.fstat(fd);stable(before,after,label);current=physical(path,label,"file");require(len(body)==before.st_size and (current.st_dev,current.st_ino)==(after.st_dev,after.st_ino),f"{label} changed while read");return body,after
 finally:os.close(fd)
def physical_executable(item,label):
 body,meta=read_regular(item["path"],label,MAX_INPUT);mode=stat.S_IMODE(meta.st_mode)
 require(meta.st_size>0 and mode&0o111 and not mode&0o022,f"{label} is not a bounded safe executable")
 require((str(meta.st_dev),str(meta.st_ino),meta.st_uid,mode4(meta.st_mode),hashlib.sha256(body).hexdigest())==(item["dev"],item["inode"],item["uid"],item["mode"],item["sha256"]),f"{label} physical pathname identity changed")
 return (meta.st_dev,meta.st_ino,meta.st_uid,meta.st_mode,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns,hashlib.sha256(body).digest())
def shell_quote(value): return "'"+value.replace("'","'\\''")+"'"
def private_wrapper_identity(admission,tool):
 runtime=admission["runtime"];root=runtime["toolPathRoot"];path=os.path.join(root["path"],tool)
 require(normalized(path) and os.path.dirname(path)==root["path"],f"admitted private tool wrapper {tool} path is malformed")
 body,meta=read_regular(path,f"admitted private tool wrapper {tool}",MAX_INPUT);mode=stat.S_IMODE(meta.st_mode)
 expected=f"#!{admission['tools']['bash']['path']}\nexec -a {shell_quote(tool)} {shell_quote(admission['tools'][tool]['path'])} \"$@\"\n".encode()
 require(meta.st_uid==root["uid"] and mode==0o700 and meta.st_size>0 and body==expected,f"admitted private tool wrapper {tool} physical pathname identity changed")
 return (meta.st_dev,meta.st_ino,meta.st_uid,meta.st_mode,meta.st_size,meta.st_mtime_ns,meta.st_ctime_ns,hashlib.sha256(body).digest())
def verify_execution_paths(admission,tool):
 for name in sorted({"bash",tool}):
  descriptor(TOOL_FDS[name],admission["tools"][name],f"admitted macOS tool {name}",True);physical_executable(admission["tools"][name],f"admitted macOS tool {name}")
 return private_wrapper_identity(admission,tool)
def inspect_regular(path,label):
 body,meta=read_regular(path,label,2**53-1);return {"sha256":hashlib.sha256(body).hexdigest(),"size":meta.st_size,"mode":mode4(meta.st_mode)}
def parse_canonical_json(body,label):
 require(len(body)<=MAX_INPUT,f"{label} exceeds 64 MiB")
 try:text=body.decode("utf-8");value=json.loads(text,object_pairs_hook=pairs,parse_int=integer,parse_float=lambda _:fail("canonical JSON permits integers only"),parse_constant=lambda _:fail("canonical JSON permits integers only"))
 except (UnicodeDecodeError,ValueError,json.JSONDecodeError) as error:fail(f"{label} is invalid JSON: {error}")
 require(text==canonical_json(value)+"\n",f"{label} is not canonical JSON");return value
def immutable_tree(root,label):
 initial=physical(root,label,"directory");content=hashlib.sha256();descriptors=hashlib.sha256()
 def walk(directory,prefix=""):
  for name in sorted(os.listdir(directory),key=os.fsencode):
   require(name and "/" not in name and "\0" not in name and "\r" not in name and "\n" not in name and name==unicodedata.normalize("NFC",name),f"{label} has an unsafe entry")
   relative=f"{prefix}/{name}" if prefix else name;path=os.path.join(directory,name);item=os.lstat(path);mode=stat.S_IMODE(item.st_mode);require(item.st_uid==initial.st_uid and not mode&0o022,f"{label} entry {relative} has unsafe identity")
   if stat.S_ISDIR(item.st_mode): require(os.path.realpath(path)==path,f"{label} directory {relative} resolves through a symlink");content.update(f"D\0{relative}\0{mode:o}\n".encode());descriptors.update(f"D\0{relative}\0{item.st_dev}\0{item.st_ino}\0{mode:o}\n".encode());walk(path,relative)
   elif stat.S_ISREG(item.st_mode):
    require(item.st_nlink==1,f"{label} file {relative} must be single-link");observed=inspect_regular(path,f"{label} file {relative}");content.update(f"F\0{relative}\0{mode:o}\0{observed['size']}\0{observed['sha256']}\n".encode());descriptors.update(f"F\0{relative}\0{item.st_dev}\0{item.st_ino}\0{mode:o}\0{item.st_size}\n".encode())
   else:fail(f"{label} contains unsupported entry {relative}")
 walk(root);after=physical(root,label,"directory");stable(initial,after,label);return {"path":root,"treeDigest":content.hexdigest(),"descriptorDigest":descriptors.hexdigest(),"dev":str(after.st_dev),"inode":str(after.st_ino),"uid":after.st_uid,"mode":mode4(after.st_mode)}
def source_item(admission,name): return admission["runtime"]["sourceDescriptors"][name]
def source_fd_path(name): return f"/dev/fd/{SOURCE_FDS[name]}"
def descriptor_identity(item): return {key:item[key] for key in ("path","sha256","dev","inode","uid","mode")}
def source_bytes(admission,name): return descriptor(SOURCE_FDS[name],descriptor_identity(source_item(admission,name)),f"admitted macOS source {name}")
def verify_runtime(admission):
 runtime=admission["runtime"];require(runtime["toolDescriptors"]==TOOL_FDS and set(runtime["sourceDescriptors"])==set(SOURCE_DESCRIPTOR_PATHS),"runtime descriptor map drifted")
 descriptor(4,runtime["worker"],"admitted macOS worker",non_executable=True)
 descriptor(5,runtime["admissionParser"],"admitted macOS parser",non_executable=True)
 for name in SOURCE_DESCRIPTOR_PATHS: descriptor(SOURCE_FDS[name],descriptor_identity(source_item(admission,name)),f"admitted macOS source {name}")
 for name in TOOLS: descriptor(TOOL_FDS[name],admission["tools"][name],f"admitted macOS tool {name}",True)
 root=immutable_tree(runtime["toolPathRoot"]["path"],"admitted private tool PATH");require(canonical_json(root)==canonical_json(runtime["toolPathRoot"]),"admitted private tool PATH changed")
 require(os.environ.get("PATH")==runtime["toolPathRoot"]["path"],"admitted private PATH drifted")
 require(os.environ.get("HOME")==runtime["releaseHome"]["path"],"admitted release HOME drifted")
 for name in ("cargoHome","rustupHome"):
  root=immutable_tree(runtime["dependencyRoots"][name]["path"],f"admitted dependency root {name}");require(canonical_json(root)==canonical_json(runtime["dependencyRoots"][name]),f"admitted dependency root {name} changed")
 aliases={}
 for name in TOOLS:
  require(re.fullmatch(r"[a-z0-9][a-z0-9._-]*",name),f"unsafe tool id {name}");alias=re.sub(r"[._-]","_",name.upper());require(alias not in aliases,f"tool aliases collide: {name}/{aliases.get(alias)}");aliases[alias]=name
 require(set(os.listdir(runtime["toolPathRoot"]["path"]))==set(TOOLS),"private tool PATH aliases drifted")
def verify_toolchain(admission):
 body,_=read_regular(admission["toolchainManifest"]["path"],"macOS toolchain manifest");require(hashlib.sha256(body).hexdigest()==admission["toolchainManifest"]["sha256"],"macOS toolchain manifest changed");manifest=parse_canonical_json(body,"macOS toolchain manifest")
 exact_keys(manifest,("aliases","dependencyRoots","host","schema","tools","trace"),"macOS toolchain manifest")
 require(manifest["schema"]==TOOLCHAIN_SCHEMA and isinstance(manifest["host"],str) and manifest["host"] and not any(char in manifest["host"] for char in "\0\r\n") and set(manifest["tools"])==set(TOOLS) and canonical_json(manifest["tools"])==canonical_json(admission["tools"]),"macOS toolchain differs from admission")
 aliases=manifest["aliases"];require(isinstance(aliases,dict) and set(aliases.values())==set(TOOLS) and len(aliases)==len(TOOLS),"macOS tool aliases are incomplete")
 normalized_aliases={}
 for alias,tool in aliases.items():
  require(isinstance(alias,str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]*",alias) and tool in TOOLS,f"macOS tool alias {alias!r} is unsafe")
  normalized_alias=re.sub(r"[+._-]","_",alias.upper());require(normalized_alias not in normalized_aliases,f"macOS tool aliases collide: {alias}/{normalized_aliases.get(normalized_alias)}");normalized_aliases[normalized_alias]=alias
 roots=manifest["dependencyRoots"];require(canonical_json(roots)==canonical_json(admission["runtime"]["dependencyRoots"]),"macOS dependency roots differ from admission")
 trace=manifest["trace"];exact_keys(trace,("argvSha256","executableAliases","schema","source","status"),"macOS toolchain trace");sha256(trace["argvSha256"],"macOS toolchain trace argvSha256");exact_keys(trace["source"],("commit","tree"),"macOS toolchain trace source");require(canonical_json(trace["source"])==canonical_json(admission["source"]) and trace["schema"]==TOOL_TRACE_SCHEMA and trace["status"]=="pass","macOS toolchain trace differs from admission")
 aliases_seen=trace["executableAliases"];require(isinstance(aliases_seen,list) and aliases_seen and all(isinstance(alias,str) and alias in aliases for alias in aliases_seen),"macOS toolchain trace aliases are invalid");require(aliases_seen==sorted(set(aliases_seen),key=lambda alias:alias.encode()),"macOS toolchain trace aliases are not sorted and unique")
def verify_admission(admission,admission_sha,output):
 exact_keys(admission,("fullStageDigest","generatedStateRoot","outputRoot","project","releaseIdentity","releaseStudio","runtime","schema","source","stageRoot","toolchainManifest","tools","version"),"macOS admission");require(admission["schema"]==SCHEMA and admission["project"]==PROJECT and isinstance(admission["version"],str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",admission["version"]),"macOS admission identity drifted")
 exact_keys(admission["source"],("commit","tree"),"macOS source");git_oid(admission["source"]["commit"],"macOS source commit");git_oid(admission["source"]["tree"],"macOS source tree");sha256(admission["fullStageDigest"],"macOS stage digest")
 exact_keys(admission["stageRoot"],("descriptorDigest","dev","inode","mode","path","uid"),"macOS stage root");sha256(admission["stageRoot"]["descriptorDigest"],"macOS stage descriptor digest");directory({key:admission["stageRoot"][key] for key in ("path","dev","inode","uid","mode")},"macOS stage root",True);directory(admission["generatedStateRoot"],"macOS generated state",True)
 require(admission["outputRoot"]==output and normalized(output) and os.path.dirname(output)==admission["generatedStateRoot"]["path"] and not os.path.lexists(output),"output must be the fresh admitted child")
 exact_keys(admission["releaseStudio"],("admissionHelperSha256","commit","controllerSha256","tree"),"macOS release controller identity");[git_oid(admission["releaseStudio"][key],f"release controller {key}") for key in ("commit","tree")];[sha256(admission["releaseStudio"][key],f"release controller {key}") for key in ("controllerSha256","admissionHelperSha256")]
 exact_keys(admission["releaseIdentity"],("path","sha256"),"macOS release identity");require(normalized(admission["releaseIdentity"]["path"]),"macOS release identity path is malformed");sha256(admission["releaseIdentity"]["sha256"],"macOS release identity digest");identity,_=read_regular(admission["releaseIdentity"]["path"],"macOS release identity");require(hashlib.sha256(identity).hexdigest()==admission["releaseIdentity"]["sha256"],"macOS release identity changed")
 exact_keys(admission["toolchainManifest"],("path","sha256"),"macOS toolchain manifest");require(normalized(admission["toolchainManifest"]["path"]),"macOS toolchain manifest path malformed");sha256(admission["toolchainManifest"]["sha256"],"macOS toolchain manifest digest");require(set(admission["tools"])==set(TOOLS),"macOS tool set drifted")
 verify_runtime(admission);verify_toolchain(admission);global CURRENT_ADMISSION;CURRENT_ADMISSION=admission;return admission
def verify_continuity(admission):
 stage,descriptor_digest=stage_digests(admission["stageRoot"]["path"],admission["source"]);require(stage==admission["fullStageDigest"] and descriptor_digest==admission["stageRoot"]["descriptorDigest"],"admitted source stage changed");directory(admission["generatedStateRoot"],"macOS generated state",True);verify_runtime(admission);verify_toolchain(admission);return admission["tools"]
def run_tool(_tools,tool,args,*,cwd=None,environment=None,capture=False,separate=False,pass_fds=()):
 require(CURRENT_ADMISSION is not None and tool in TOOLS,"unadmitted tool invocation");verify_runtime(CURRENT_ADMISSION);extra=set(pass_fds);runtime=CURRENT_ADMISSION["runtime"];env={"HOME":runtime["releaseHome"]["path"],"CARGO_HOME":runtime["dependencyRoots"]["cargoHome"]["path"],"RUSTUP_HOME":runtime["dependencyRoots"]["rustupHome"]["path"],"LANG":"C","LC_ALL":"C","TZ":"UTC","PATH":runtime["toolPathRoot"]["path"]};forbidden={"HOME","CARGO_HOME","RUSTUP_HOME","PATH","BASH_ENV","ENV","LD_PRELOAD","LD_LIBRARY_PATH","DYLD_LIBRARY_PATH","DYLD_INSERT_LIBRARIES"};require(not environment or not (forbidden&set(environment)) and not any(key.startswith(("DYLD_","PYTHON")) for key in (environment or {})),"tool environment may not escape admitted roots");env.update(environment or {})
 # Darwin cannot execute regular binaries through /dev/fd. The held fds remain
 # identity evidence while the immutable private-PATH wrapper and both physical
 # executables are checked immediately around the launch. A malicious same-uid
 # peer could still race exec itself; release signing therefore requires the
 # dedicated signer account boundary enforced by the external controller.
 before=verify_execution_paths(CURRENT_ADMISSION,tool);result=None
 try:result=subprocess.run([tool,*args],cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE if capture else subprocess.DEVNULL,stderr=subprocess.PIPE if capture else subprocess.DEVNULL,pass_fds=tuple(sorted(set(HELD_FDS)|extra)),check=False)
 finally:
  after=verify_execution_paths(CURRENT_ADMISSION,tool);require(after==before,f"admitted private tool wrapper {tool} changed during execution");verify_runtime(CURRENT_ADMISSION)
 if result.returncode:fail(f"admitted tool {tool} failed with status {result.returncode}")
 return (result.stdout or b"",result.stderr or b"") if separate else (result.stdout or b"")+(result.stderr or b"")
