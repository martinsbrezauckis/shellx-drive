#!/usr/bin/env python3
"""Record unsigned worker observations; the external release controller verifies them."""
import argparse,hashlib,json,pathlib
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
p=argparse.ArgumentParser();p.add_argument("--admission",required=True);p.add_argument("--candidate-dir",required=True);p.add_argument("--manifest",required=True);p.add_argument("--layout",required=True);p.add_argument("--out",required=True);p.add_argument("--post-continuity-pass",action="store_true",required=True);a=p.parse_args()
ad=json.loads(pathlib.Path(a.admission).read_text());root=pathlib.Path(a.candidate_dir);manifest=json.loads(pathlib.Path(a.manifest).read_text())
names=[pathlib.Path(a.manifest).name,pathlib.Path(a.manifest).name+".asc",manifest["artifacts"]["appimage"]["file"],manifest["artifacts"]["deb"]["file"],manifest["updaters"]["linux-x86_64"]["signature"],manifest["updaters"]["linux-x86_64-deb"]["signature"],"linux-updater-candidate.json","linux-deb-updater-candidate.json","linux-release-keyring.gpg"]
outputs={name:{"sha256":sha(root/name),"size":(root/name).stat().st_size} for name in names}
layout_path=pathlib.Path(a.layout);package_files=json.loads(layout_path.read_text());layout_path.unlink()
payload={"schema":"shellx-drive.linux-release-worker-observation/v1","status":"worker-complete","admissionSha256":sha(a.admission),"source":{"commit":ad["source"]["commit"],"tree":ad["source"]["tree"],"fullStageDigest":ad["fullStageDigest"],"descriptorDigest":ad["stageRoot"]["descriptorDigest"]},"toolchainManifestSha256":ad["toolchainManifest"]["sha256"],"outputs":outputs,"packageFilesObserved":package_files,"postContinuity":{"stage":"pass","tools":"pass"}}
pathlib.Path(a.out).write_text(json.dumps(payload,sort_keys=True,separators=(",",":"))+"\n")
