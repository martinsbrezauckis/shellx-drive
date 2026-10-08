#!/usr/bin/env python3
"""Held-descriptor parser for the externally admitted macOS worker."""
import hashlib,json,os,re,stat,sys,unicodedata

SCHEMA="release-studio.shellx-drive-macos-admission.v1"
TOOLS=("awk","bash","cargo","chmod","codesign","cp","ditto","find","git","gpg","gpgv","grep","hdiutil","mkdir","mktemp","mv","node","plutil","pnpm","python3","rm","rustc","security","shasum","spctl","stat","tauri-cli","tauri-updater-verifier","uname","xcrun")
TOOL_FDS={name:10+index for index,name in enumerate(sorted(TOOLS,key=lambda item:item.encode()))}
SOURCE_DESCRIPTOR_PATHS={
 "macos-release-core":"desktop/scripts/macos-release-core.py","macos-release-stage":"desktop/scripts/macos-release-stage.py","macos-release-worker":"desktop/scripts/macos-release-worker.py",
 "tauri-config":"desktop/src-tauri/tauri.conf.json","tauri-macos-config":"desktop/src-tauri/tauri.macos.conf.json","entitlements":"desktop/src-tauri/entitlements.plist",
 "updater-candidate-core":"desktop/scripts/updater-candidate-core.mjs",
}
SOURCE_FDS={name:100+index for index,name in enumerate(SOURCE_DESCRIPTOR_PATHS)}
MAX_INPUT=64*1024*1024
def fail(message): raise RuntimeError(message)
def need(value,message):
 if not value: fail(message)
def normalized(value): return isinstance(value,str) and value and not any(char in value for char in "\0\r\n") and os.path.isabs(value) and os.path.normpath(value)==value and value!="/" and not value.endswith("/")
def exact(value,keys,label): need(isinstance(value,dict) and set(value)==set(keys),f"{label} has unexpected or missing fields")
def decimal(value,label): need(isinstance(value,str) and re.fullmatch(r"(?:0|[1-9][0-9]*)",value),f"{label} must be canonical decimal text")
def sha(value,label): need(isinstance(value,str) and re.fullmatch(r"[0-9a-f]{64}",value),f"{label} must be a lowercase SHA-256")
def integer(raw):
 if raw=="-0": fail("canonical JSON contains negative zero")
 value=int(raw);need(-(2**53-1)<=value<=2**53-1,"canonical JSON integer is unsafe");return value
def pairs(items):
 value={}
 for key,item in items:
  if key in value: fail("canonical JSON has duplicate keys")
  value[key]=item
 return value
def nfc(value):
 if isinstance(value,str): need(value==unicodedata.normalize("NFC",value) and not any(0xd800<=ord(char)<=0xdfff for char in value),"canonical JSON has non-NFC text")
 elif isinstance(value,list):
  for item in value:nfc(item)
 elif isinstance(value,dict):
  for key,item in value.items():nfc(key);nfc(item)
 elif value is not None and not isinstance(value,(bool,int)): fail("canonical JSON has unsupported value")
def canonical(value): nfc(value);return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(",",":"),allow_nan=False)
def bytes_fd(fd,limit=MAX_INPUT):
 before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=limit,f"held fd{fd} is not a bounded single-link regular file")
 body=os.pread(fd,before.st_size,0);after=os.fstat(fd);need(len(body)==before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),f"held fd{fd} changed while read");return body,after
def descriptor(fd,item,label,executable=False,non_executable=False):
 exact(item,("path","sha256","dev","inode","uid","mode"),label);need(normalized(item["path"]),f"{label}.path is malformed");sha(item["sha256"],f"{label}.sha256");decimal(item["dev"],f"{label}.dev");decimal(item["inode"],f"{label}.inode");need(isinstance(item["uid"],int) and not isinstance(item["uid"],bool) and item["uid"]>=0 and re.fullmatch(r"[0-7]{4}",item["mode"]),f"{label} descriptor is malformed")
 body,meta=bytes_fd(fd);mode=f"{stat.S_IMODE(meta.st_mode):04o}";need((str(meta.st_dev),str(meta.st_ino),meta.st_uid,mode)==(item["dev"],item["inode"],item["uid"],item["mode"]) and hashlib.sha256(body).hexdigest()==item["sha256"],f"{label} descriptor identity changed");need(not stat.S_IMODE(meta.st_mode)&0o022 and (not executable or bool(meta.st_mode&0o111)) and (not non_executable or not bool(meta.st_mode&0o111)),f"{label} descriptor mode is unsafe");return body
def directory(item,label,private=False):
 exact(item,("path","dev","inode","uid","mode"),label);need(normalized(item["path"]),f"{label}.path is malformed");decimal(item["dev"],f"{label}.dev");decimal(item["inode"],f"{label}.inode");need(isinstance(item["uid"],int) and re.fullmatch(r"[0-7]{4}",item["mode"]),f"{label} descriptor is malformed")
 observed=os.lstat(item["path"]);need(stat.S_ISDIR(observed.st_mode) and not stat.S_ISLNK(observed.st_mode) and os.path.realpath(item["path"])==item["path"] and (str(observed.st_dev),str(observed.st_ino),observed.st_uid,f"{stat.S_IMODE(observed.st_mode):04o}")==tuple(item[key] for key in ("dev","inode","uid","mode")),f"{label} identity changed");need(not private or item["mode"]=="0700" and observed.st_uid==os.geteuid(),f"{label} must stay caller-owned 0700")
def admission_fd():
 body,meta=bytes_fd(3);need(stat.S_IMODE(meta.st_mode)==0o600 and meta.st_uid==os.geteuid(),"admission fd must be caller-owned 0600")
 try:value=json.loads(body.decode("utf-8"),object_pairs_hook=pairs,parse_int=integer,parse_float=lambda _:fail("canonical JSON permits integers only"),parse_constant=lambda _:fail("canonical JSON permits integers only"))
 except (UnicodeDecodeError,ValueError,json.JSONDecodeError) as error:fail(f"admission is not canonical JSON: {error}")
 need(body.decode("utf-8")==canonical(value)+"\n","admission is not canonical JSON");return value,hashlib.sha256(body).hexdigest()
def main():
 need(len(sys.argv)==6 and sys.argv[0]=="/dev/fd/5" and sys.argv[1] in ("verify-admission","run-worker") and sys.argv[2:5]==["--admission","/dev/fd/3","--out"] and normalized(sys.argv[5]),"usage: /dev/fd/5 verify-admission|run-worker --admission /dev/fd/3 --out FRESH_ABS_DIR")
 action,output=sys.argv[1],sys.argv[5]
 need(not any(key.startswith("PYTHON") or key.startswith("DYLD_") for key in os.environ),"unsafe Python or loader environment")
 admission,admission_sha=admission_fd();exact(admission,("fullStageDigest","generatedStateRoot","outputRoot","project","releaseIdentity","releaseStudio","runtime","schema","source","stageRoot","toolchainManifest","tools","version"),"macOS admission")
 need(admission["schema"]==SCHEMA and admission["project"]=="shellx-drive" and isinstance(admission["stageRoot"],dict),"macOS admission identity is invalid")
 stage=admission["stageRoot"];exact(stage,("descriptorDigest","dev","inode","mode","path","uid"),"macOS stage root");directory({key:stage[key] for key in ("path","dev","inode","uid","mode")},"macOS stage root",True)
 runtime=admission["runtime"];exact(runtime,("admissionParser","dependencyRoots","releaseHome","sourceDescriptors","toolDescriptors","toolPathRoot","worker"),"macOS runtime")
 parser=runtime["admissionParser"];worker=runtime["worker"];need(parser.get("path")==f"{stage['path']}/desktop/scripts/macos-release-admission.py" and worker.get("path")==f"{stage['path']}/desktop/scripts/macos-signed-candidate.sh", "macOS parser or worker path drifted");descriptor(5,parser,"macOS admission parser",non_executable=True);descriptor(4,worker,"macOS worker",non_executable=True)
 sources=runtime["sourceDescriptors"];need(set(sources)==set(SOURCE_DESCRIPTOR_PATHS),"macOS source descriptor set is incomplete")
 for name,relative in SOURCE_DESCRIPTOR_PATHS.items():
  item=sources[name];exact(item,("fd","path","sha256","dev","inode","uid","mode"),f"macOS source descriptor {name}");need(item["fd"]==SOURCE_FDS[name] and item["path"]==f"{stage['path']}/{relative}",f"macOS source descriptor {name} drifted");descriptor(item["fd"],{key:item[key] for key in ("path","sha256","dev","inode","uid","mode")},f"macOS source descriptor {name}")
 need(set(admission["tools"])==set(TOOLS) and runtime["toolDescriptors"]==TOOL_FDS,"macOS tool descriptor set is incomplete or nondeterministic")
 for name in TOOLS: descriptor(TOOL_FDS[name],admission["tools"][name],f"macOS tool {name}",True)
 tool_root=runtime["toolPathRoot"];exact(tool_root,("descriptorDigest","dev","inode","mode","path","treeDigest","uid"),"macOS tool path root");directory({key:tool_root[key] for key in ("path","dev","inode","uid","mode")},"macOS tool path root",True);need(os.environ.get("PATH")==tool_root["path"],"private admitted PATH drifted")
 exact(runtime["releaseHome"],("dev","inode","mode","path","uid"),"macOS release HOME");directory(runtime["releaseHome"],"macOS release HOME",True);need(os.environ.get("HOME")==runtime["releaseHome"]["path"],"admitted release HOME drifted")
 roots=runtime["dependencyRoots"];need(set(roots)=={"cargoHome","rustupHome"},"macOS dependency root set is incomplete")
 for name in roots:
  exact(roots[name],("descriptorDigest","dev","inode","mode","path","treeDigest","uid"),f"macOS dependency root {name}");sha(roots[name]["descriptorDigest"],f"macOS dependency root {name} descriptor digest");sha(roots[name]["treeDigest"],f"macOS dependency root {name} tree digest");directory({key:roots[name][key] for key in ("path","dev","inode","uid","mode")},f"macOS dependency root {name}")
 namespace={"__name__":"shellx_drive_macos_held","ADMISSION_FD":3,"WORKER_FD":4,"PARSER_FD":5,"SCHEMA":SCHEMA,"MAX_INPUT":MAX_INPUT,"TOOLS":TOOLS,"SOURCE_DESCRIPTOR_PATHS":SOURCE_DESCRIPTOR_PATHS,"SOURCE_FDS":SOURCE_FDS,"TOOL_FDS":TOOL_FDS,"fail":fail,"normalized":normalized,"descriptor":descriptor,"directory":directory,"pairs":pairs,"integer":integer}
 for name in ("macos-release-core","macos-release-stage","macos-release-worker"):
  body=descriptor(SOURCE_FDS[name],{key:sources[name][key] for key in ("path","sha256","dev","inode","uid","mode")},f"macOS source descriptor {name}");exec(compile(body,f"<held:{name}>","exec"),namespace)
 admitted=namespace["verify_admission"](admission,admission_sha,output)
 if action=="verify-admission": print(f"MACOS_RELEASE_ADMISSION_PREFLIGHT_OK source_commit={admitted['source']['commit']} source_tree={admitted['source']['tree']}");return
 need(os.uname().sysname=="Darwin" and os.uname().machine=="arm64","this worker requires native macOS arm64")
 observation=namespace["run_worker"](admitted,admission_sha);print(f"MACOS_RELEASE_WORKER_COMPLETE source_commit={admitted['source']['commit']} source_tree={admitted['source']['tree']} observation={observation}")
try: main()
except Exception as error: print(f"FAIL: macOS signed candidate: {error}",file=sys.stderr);sys.exit(1)
