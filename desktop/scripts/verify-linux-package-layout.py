#!/usr/bin/env python3
"""Inspect final native packages before attesting their installed closure."""
import argparse,hashlib,json,os,pathlib,shutil,stat,subprocess
p=argparse.ArgumentParser();p.add_argument("--deb",required=True);p.add_argument("--appimage",required=True);p.add_argument("--dpkg-deb",required=True);p.add_argument("--unsquashfs",required=True);p.add_argument("--work-root",required=True);p.add_argument("--out",required=True);a=p.parse_args()
root=pathlib.Path(a.work_root);deb_root=root/"deb-layout";app_root=root/"appimage-layout"
def admitted_fd(value):
 if not value.startswith("/dev/fd/") or not value[8:].isdigit(): raise SystemExit("FAIL: package tool is not descriptor-bound")
 fd=int(value[8:]);meta=os.fstat(fd)
 if not stat.S_ISREG(meta.st_mode) or not meta.st_mode&0o111: raise SystemExit("FAIL: package tool descriptor is invalid")
 return fd
dpkg_fd=admitted_fd(a.dpkg_deb);unsquash_fd=admitted_fd(a.unsquashfs)
subprocess.run([a.dpkg_deb,"-x",a.deb,deb_root],check=True,close_fds=True,pass_fds=(dpkg_fd,))
required={"usr/bin/shellx-drive-desktop":0o755,"usr/share/applications/shellx-drive.desktop":0o644,"usr/share/icons/hicolor/256x256/apps/shellx-drive.png":0o644,"usr/lib/shellx-drive/acceptance/run-linux-desktop-acceptance.sh":0o755,"usr/lib/shellx-drive/acceptance/verify-linux-acceptance-state.py":0o644,"usr/lib/shellx-drive/acceptance/CONTROL_RESULT_LEDGER.tsv":0o644,"usr/lib/shellx-drive/acceptance/linux-control-ledger.py":0o644,"usr/lib/shellx-drive/verification/linux-verify-candidate.sh":0o755,"usr/lib/shellx-drive/verification/linux-release-common.sh":0o644,"usr/lib/shellx-drive/verification/verify-linux-candidate-manifest.py":0o644,"usr/lib/shellx-drive/verification/verify-linux-verifier-attestation.py":0o644,"usr/lib/shellx-drive/verification/release-keyring.gpg":0o644}
external_only={"usr/lib/shellx-drive/acceptance/EXTERNAL_ACCEPTANCE_BUNDLE.json","usr/lib/shellx-drive/acceptance/linux-external-acceptance-common.py","usr/lib/shellx-drive/acceptance/linux-external-acceptance-verifier.py"}
acceptance_root=deb_root/"usr/lib/shellx-drive/acceptance"
acceptance_meta=acceptance_root.lstat()
expected_acceptance={pathlib.PurePosixPath(path).name for path in required if path.startswith("usr/lib/shellx-drive/acceptance/")}
if not stat.S_ISDIR(acceptance_meta.st_mode) or stat.S_ISLNK(acceptance_meta.st_mode) or {entry.name for entry in os.scandir(acceptance_root)}!=expected_acceptance: raise SystemExit("FAIL: Debian acceptance subtree contains unexpected or case-variant entries")
observed={}
for relative,mode in required.items():
 target=deb_root/relative;meta=target.lstat()
 if not stat.S_ISREG(meta.st_mode) or stat.S_ISLNK(meta.st_mode) or stat.S_IMODE(meta.st_mode)!=mode: raise SystemExit(f"FAIL: Debian verifier layout drifted: {relative}")
 observed["/"+relative]={"sha256":hashlib.sha256(target.read_bytes()).hexdigest(),"size":meta.st_size,"mode":f"{mode:04o}"}
if (deb_root/"usr/share/applications/shellx-drive.desktop").read_bytes()!=b"[Desktop Entry]\nType=Application\nName=ShellX Drive\nExec=shellx-drive-desktop\nIcon=shellx-drive\n": raise SystemExit("FAIL: Debian desktop entry drifted")
icon=(deb_root/"usr/share/icons/hicolor/256x256/apps/shellx-drive.png").read_bytes()
if len(icon)<24 or icon[:8]!=b"\x89PNG\r\n\x1a\n" or icon[8:16]!=b"\x00\x00\x00\rIHDR" or int.from_bytes(icon[16:20],"big")!=256 or int.from_bytes(icon[20:24],"big")!=256: raise SystemExit("FAIL: Debian desktop icon drifted")
if any((deb_root/relative).exists() or (deb_root/relative).is_symlink() for relative in external_only): raise SystemExit("FAIL: Debian contains a retained external acceptance verifier")
body=pathlib.Path(a.appimage).read_bytes();offset=body.find(b"hsqs")
if offset<0: raise SystemExit("FAIL: AppImage SquashFS boundary is unavailable")
subprocess.run([a.unsquashfs,"-o",str(offset),"-d",app_root,a.appimage],check=True,stdout=subprocess.DEVNULL,close_fds=True,pass_fds=(unsquash_fd,))
def inspect_appimage_tree(directory_fd,prefix=""):
 for entry in sorted(os.scandir(directory_fd),key=lambda item:item.name.encode("utf-8")):
  relative=f"{prefix}/{entry.name}" if prefix else entry.name
  lowered=relative.lower()
  if "usr/lib/shellx-drive/verification" in lowered or "usr/lib/shellx-drive/acceptance" in lowered: raise SystemExit("FAIL: AppImage contains misleading host verifier paths")
  meta=os.stat(entry.name,dir_fd=directory_fd,follow_symlinks=False)
  if stat.S_ISLNK(meta.st_mode): raise SystemExit("FAIL: AppImage layout contains a symlink")
  if stat.S_ISDIR(meta.st_mode):
   child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory_fd)
   try:
    confirmed=os.fstat(child)
    if (meta.st_dev,meta.st_ino,meta.st_mode)!=(confirmed.st_dev,confirmed.st_ino,confirmed.st_mode): raise SystemExit("FAIL: AppImage directory identity changed")
    inspect_appimage_tree(child,relative)
   finally: os.close(child)
  elif not stat.S_ISREG(meta.st_mode): raise SystemExit("FAIL: AppImage layout contains a special file")
app_fd=os.open(app_root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try: inspect_appimage_tree(app_fd)
finally: os.close(app_fd)
pathlib.Path(a.out).write_text(json.dumps({"deb":observed,"appImageHostVerifierCopies":0},sort_keys=True,separators=(",",":"))+"\n")
shutil.rmtree(deb_root);shutil.rmtree(app_root)
