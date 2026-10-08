#!/usr/bin/env python3
"""Create an out-of-tree Linux Tauri overlay with absolute resource inputs."""
import argparse,json,pathlib,shutil
p=argparse.ArgumentParser();p.add_argument("--stage",required=True);p.add_argument("--linux-config",required=True);p.add_argument("--keyring",required=True);p.add_argument("--out",required=True);a=p.parse_args()
stage=pathlib.Path(a.stage).resolve(strict=True); source=stage/"desktop/src-tauri/tauri.linux.conf.json"; data=json.loads(pathlib.Path(a.linux_config).read_text()); output=pathlib.Path(a.out).parent; resources=output/"debian-verifier-resources";resources.mkdir(mode=0o700)
files=data["bundle"]["linux"]["deb"]["files"]
held_resources={"/usr/lib/shellx-drive/verification/linux-verify-candidate.sh":107,"/usr/lib/shellx-drive/verification/linux-release-common.sh":100,"/usr/lib/shellx-drive/verification/verify-linux-candidate-manifest.py":108,"/usr/lib/shellx-drive/verification/verify-linux-verifier-attestation.py":109}
for installed,value in list(files.items()):
 original=(source.parent/pathlib.Path(value)).resolve(strict=True); copied=resources/original.name
 if installed in held_resources:
  with open(f"/dev/fd/{held_resources[installed]}","rb",buffering=0) as src,open(copied,"xb") as dst: shutil.copyfileobj(src,dst)
 else: shutil.copyfile(original,copied)
 copied.chmod(0o755 if installed.endswith(("run-linux-desktop-acceptance.sh","linux-verify-candidate.sh")) else 0o644);files[installed]=str(copied)
keyring=resources/"release-keyring.gpg";shutil.copyfile(pathlib.Path(a.keyring).resolve(strict=True),keyring);keyring.chmod(0o644);files["/usr/lib/shellx-drive/verification/release-keyring.gpg"]=str(keyring)
pathlib.Path(a.out).write_text(json.dumps(data,sort_keys=True,separators=(",",":"))+"\n")
