# Native Windows raw-PE builder. The controller's short encoded bootstrap reads
# this held source and the canonical plan as a framed stdin payload, verifies
# both hashes, and then exposes only the verified plan bytes in-process.
# Environment scrubbing alone is not an isolation boundary: execution requires
# the controller to admit a separately isolated builder SID first.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail([string]$Message) { throw "Windows native unsigned build: $Message" }
function Sha256([byte[]]$Bytes) {
  $hash = [System.Security.Cryptography.SHA256]::Create()
  try { return ([System.BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $hash.Dispose() }
}
function Require-ExactProperties($Value, [string[]]$Names, [string]$Label) {
  $actual = @($Value.PSObject.Properties.Name | Sort-Object)
  $expected = @($Names | Sort-Object)
  if ($actual.Count -ne $expected.Count -or (@(Compare-Object $actual $expected).Count -ne 0)) { Fail "$Label properties drifted" }
}
function Test-CanonicalWindowsPath([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  if ($Path -notmatch '^(?:[A-Za-z]:\\|\\\\[^\\/:*?"<>|\x00-\x1f]+\\[^\\/:*?"<>|\x00-\x1f]+\\)(?:[^\\/:*?"<>|\x00-\x1f]+\\)*[^\\/:*?"<>|\x00-\x1f]+$') { return $false }
  $tail = if ($Path -match '^[A-Za-z]:\\') { $Path.Substring(3) } else { $Path.Split('\\', 5)[4] }
  foreach ($segment in $tail.Split(@('\\'), [System.StringSplitOptions]::None)) {
    if ($segment -eq '.' -or $segment -eq '..' -or $segment.EndsWith(' ') -or $segment.EndsWith('.')) { return $false }
  }
  try { $canonical = [System.IO.Path]::GetFullPath($Path) } catch { return $false }
  return [string]::Equals($canonical, $Path, [System.StringComparison]::OrdinalIgnoreCase)
}
function Convert-ToSid($IdentityReference) {
  if ($null -eq $IdentityReference) { Fail 'ACL identity reference is absent' }
  if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) { return $IdentityReference.Value }
  if ($IdentityReference -is [System.Security.Principal.IdentityReference]) {
    try { return $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { Fail 'ACL identity cannot be translated to a SID' }
  }
  try { return (New-Object System.Security.Principal.NTAccount([string]$IdentityReference)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
  catch { Fail 'ACL identity cannot be translated to a SID' }
}
function Assert-ExclusiveBuilderAcl([string]$Path, [string]$ExpectedSid, [string]$Label) {
  if ($ExpectedSid -notmatch '^S-\d+(?:-\d+)+$') { Fail 'admitted builder SID is invalid' }
  $acl = Get-Acl -LiteralPath $Path
  if ((Convert-ToSid $acl.Owner) -ne $ExpectedSid) { Fail "$Label owner SID differs from the admitted builder" }
  if (-not $acl.AreAccessRulesProtected) { Fail "$Label ACL must be protected from inherited principals" }
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne 1) { Fail "$Label ACL must contain exactly one access rule" }
  $rule = $rules[0]
  $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
  if ((Convert-ToSid $rule.IdentityReference) -ne $ExpectedSid -or $rule.AccessControlType.ToString() -ne 'Allow' -or (($rule.FileSystemRights -band $fullControl) -ne $fullControl)) {
    Fail "$Label ACL is not exclusive full control for the admitted builder SID"
  }
}
function New-PrivateDirectory([string]$Path, [string]$ExpectedSid) {
  if ([System.IO.Directory]::Exists($Path) -or [System.IO.File]::Exists($Path)) { Fail 'worker root must be fresh' }
  $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  if ($currentSid -ne $ExpectedSid) { Fail 'current native builder identity differs from the externally admitted isolated SID' }
  [System.IO.Directory]::CreateDirectory($Path) | Out-Null
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetOwner($identity)
  $acl.SetAccessRuleProtection($true, $false)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
  $acl.AddAccessRule($rule)
  Set-Acl -LiteralPath $Path -AclObject $acl
  Assert-ExclusiveBuilderAcl $Path $ExpectedSid 'worker root'
}
function Reject-SigningEnvironment {
  $blocked = @('TAURI_SIGNING_PRIVATE_KEY', 'TAURI_SIGNING_PRIVATE_KEY_PASSWORD', 'SHELLX_DRIVE_WINDOWS_SIGNING_REQUIRED', 'SHELLX_WINDOWS_SIGNING_METADATA_PATH', 'SHELLX_WINDOWS_SIGNTOOL_PATH', 'SHELLX_WINDOWS_SIGNING_DLIB_PATH', 'SHELLX_DRIVE_RELEASE_CALLBACK_LOG')
  foreach ($name in $blocked) { if (Test-Path "Env:$name") { Fail "credential or signing environment is present: $name" } }
  foreach ($entry in Get-ChildItem Env:) {
    if ($entry.Name -like 'AZURE_*' -or $entry.Name -like 'CSC_*' -or $entry.Name -like 'SIGNTOOL_*') { Fail "credential or signing environment is present: $($entry.Name)" }
  }
}
function Write-SealedData([string]$Path, [string]$Base64, [string]$ExpectedSha256) {
  if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$') { Fail 'sealed input SHA-256 is invalid' }
  $bytes = [Convert]::FromBase64String($Base64)
  if ((Sha256 $bytes) -ne $ExpectedSha256) { Fail 'sealed input differs from its admission hash' }
  $stream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
  if ((Sha256 ([System.IO.File]::ReadAllBytes($Path))) -ne $ExpectedSha256) { Fail 'sealed input changed after materialization' }
}
function Require-PhysicalFileSha([string]$Path, [string]$ExpectedSha256, [string]$Label) {
  if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$') { Fail "$Label SHA-256 is invalid" }
  $item = Get-Item -LiteralPath $Path -Force
  if (-not $item -or $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { Fail "$Label must be a physical file" }
  if ((Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant() -ne $ExpectedSha256) { Fail "$Label differs from its admitted SHA-256" }
}
function Copy-PrivateDesktopWorkspace([string]$StageRoot, [string]$Workspace, [string]$NodePath) {
  $source = Join-Path $StageRoot 'desktop'
  $sourceItem = Get-Item -LiteralPath $source -Force -ErrorAction Stop
  if (-not $sourceItem.PSIsContainer -or (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { Fail 'protected desktop source must be a physical directory' }
  if (Test-Path -LiteralPath $Workspace) { Fail 'private desktop workspace must be fresh' }
  & $NodePath --input-type=module --eval 'const fs=await import(process.argv[1]); const [source,destination]=process.argv.slice(-2); const sourceStat=fs.lstatSync(source); if (!sourceStat.isDirectory() || sourceStat.isSymbolicLink()) throw Error(); fs.cpSync(source,destination,{dereference:false,errorOnExist:true,force:false,preserveTimestamps:false,recursive:true,verbatimSymlinks:true}); const copied=fs.lstatSync(destination); if (!copied.isDirectory() || copied.isSymbolicLink()) throw Error();' node:fs $source $Workspace
  if ($LASTEXITCODE -ne 0) { Fail "could not materialize private desktop workspace (exit code $LASTEXITCODE)" }
  $workspaceItem = Get-Item -LiteralPath $Workspace -Force -ErrorAction Stop
  if (-not $workspaceItem.PSIsContainer -or (($workspaceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { Fail 'private desktop workspace was not created as a physical directory' }
}

Reject-SigningEnvironment
try { $planBytes = Get-Variable -Name SHELLX_DRIVE_WINDOWS_NATIVE_PLAN_BYTES -Scope Global -ValueOnly -ErrorAction Stop } catch { Fail 'verified native bootstrap plan bytes are absent' }
if ($planBytes -isnot [byte[]] -or $planBytes.Length -eq 0) { Fail 'verified native bootstrap plan bytes are invalid' }
if ($env:SHELLX_DRIVE_WINDOWS_NATIVE_PLAN_SHA256 -notmatch '^[0-9a-f]{64}$' -or (Sha256 $planBytes) -ne $env:SHELLX_DRIVE_WINDOWS_NATIVE_PLAN_SHA256) { Fail 'native admission plan differs from its controller-provided SHA-256' }
try { $planText = (New-Object System.Text.UTF8Encoding($false, $true)).GetString($planBytes); $plan = $planText | ConvertFrom-Json -ErrorAction Stop } catch { Fail 'native admission plan is not strict UTF-8 JSON data' }
Require-ExactProperties $plan @('aclCollector', 'admission', 'bootstrap', 'candidateRoot', 'cargo', 'config', 'isolation', 'linker', 'nativeWorkerRoot', 'node', 'powershell', 'rawApplicationPath', 'rustc', 'schema', 'stageRoot', 'systemRoot', 'tauriCli', 'toolPath', 'worker', 'writer') 'native admission plan'
if ($plan.schema -ne 'release-studio.shellx-drive-windows-native-execution-plan/v1') { Fail 'native admission plan schema drifted' }
Require-ExactProperties $plan.bootstrap @('sha256') 'native admission bootstrap identity'
if ($plan.bootstrap.sha256 -notmatch '^[0-9a-f]{64}$' -or $plan.bootstrap.sha256 -ne $env:SHELLX_DRIVE_WINDOWS_NATIVE_BOOTSTRAP_SHA256) { Fail 'native admission bootstrap differs from its controller-provided SHA-256' }
foreach ($path in @($plan.candidateRoot, $plan.nativeWorkerRoot, $plan.stageRoot, $plan.cargo.path, $plan.linker.path, $plan.node.path, $plan.powershell.path, $plan.rustc.path, $plan.systemRoot, $plan.tauriCli.path, $plan.toolPath)) { if (-not (Test-CanonicalWindowsPath $path)) { Fail 'native admission plan contains a non-canonical absolute Windows path' } }
Require-ExactProperties $plan.isolation @('builderSid', 'receiptSha256', 'verifierId') 'native builder isolation'
if ($plan.isolation.builderSid -notmatch '^S-\d+(?:-\d+)+$' -or $plan.isolation.receiptSha256 -notmatch '^[0-9a-f]{64}$' -or $plan.isolation.verifierId -notmatch '^[A-Za-z0-9._-]{1,120}$') { Fail 'native builder isolation data is invalid' }
foreach ($entry in @($plan.cargo, $plan.linker, $plan.node, $plan.powershell, $plan.rustc, $plan.tauriCli, $plan.worker)) { Require-ExactProperties $entry @('path', 'sha256') 'native admission source/tool identity'; if ($entry.sha256 -notmatch '^[0-9a-f]{64}$') { Fail 'native admission source/tool SHA-256 is invalid' } }
foreach ($entry in @($plan.aclCollector, $plan.admission, $plan.config, $plan.writer)) { Require-ExactProperties $entry @('base64', 'sha256') 'sealed native admission data'; if ($entry.sha256 -notmatch '^[0-9a-f]{64}$') { Fail 'sealed native admission SHA-256 is invalid' } }
if ($plan.rawApplicationPath -ne 'x86_64-pc-windows-msvc/release/shellx-drive-desktop.exe') { Fail 'native admission plan raw application path drifted' }
foreach ($tool in @(@{value=$plan.cargo;label='admitted Cargo executable'}, @{value=$plan.linker;label='admitted MSVC linker executable'}, @{value=$plan.node;label='admitted Node executable'}, @{value=$plan.tauriCli;label='admitted Tauri CLI'}, @{value=$plan.rustc;label='admitted Rustc executable'})) { Require-PhysicalFileSha $tool.value.path $tool.value.sha256 $tool.label }
$self = (Get-Process -Id $PID).Path
if (-not $self -or -not [System.IO.Path]::GetFullPath($self).Equals([System.IO.Path]::GetFullPath($plan.powershell.path), [System.StringComparison]::OrdinalIgnoreCase)) { Fail 'native PowerShell executable differs from the admitted executable' }
Require-PhysicalFileSha $self $plan.powershell.sha256 'admitted PowerShell executable'

$privateParent = Split-Path -Parent $plan.candidateRoot
if ($privateParent -ne (Split-Path -Parent $plan.nativeWorkerRoot)) { Fail 'candidate and worker roots do not share their admitted private parent' }
Assert-ExclusiveBuilderAcl $privateParent $plan.isolation.builderSid 'externally admitted private parent'
New-PrivateDirectory $plan.nativeWorkerRoot $plan.isolation.builderSid
$admissionPath = Join-Path $plan.nativeWorkerRoot 'admission.json'
$writerPath = Join-Path $plan.nativeWorkerRoot 'write-windows-unsigned-handoff.mjs'
$aclCollectorPath = Join-Path $plan.nativeWorkerRoot 'windows-native-acl-receipt.ps1'
$configPath = Join-Path $plan.nativeWorkerRoot 'tauri.conf.json'
Write-SealedData $admissionPath $plan.admission.base64 $plan.admission.sha256
Write-SealedData $writerPath $plan.writer.base64 $plan.writer.sha256
Write-SealedData $aclCollectorPath $plan.aclCollector.base64 $plan.aclCollector.sha256
Write-SealedData $configPath $plan.config.base64 $plan.config.sha256

$env:HOME = $plan.nativeWorkerRoot
$env:USERPROFILE = $plan.nativeWorkerRoot
$env:CARGO_TARGET_DIR = Join-Path $plan.nativeWorkerRoot 'cargo-target'
$env:CARGO = $plan.cargo.path
$env:RUSTC = $plan.rustc.path
$env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $plan.linker.path
$env:TEMP = $plan.nativeWorkerRoot
$env:TMP = $plan.nativeWorkerRoot
$env:PATH = $plan.toolPath
$env:SystemRoot = $plan.systemRoot
$env:WINDIR = $plan.systemRoot
$env:SHELLX_DRIVE_NATIVE_ADMISSION_SHA256 = $plan.admission.sha256
$workspace = Join-Path $plan.nativeWorkerRoot 'desktop-workspace'
Copy-PrivateDesktopWorkspace $plan.stageRoot $workspace $plan.node.path
Set-Location $workspace
& $plan.node.path $plan.tauriCli.path build --target x86_64-pc-windows-msvc --no-bundle --features desktop-shell --config $configPath
if ($LASTEXITCODE -ne 0) { Fail "Tauri raw-PE build failed with exit code $LASTEXITCODE" }
$raw = Join-Path $env:CARGO_TARGET_DIR $plan.rawApplicationPath
if (-not (Test-Path -LiteralPath $raw -PathType Leaf) -or ((Get-Item -LiteralPath $raw).Attributes -band [IO.FileAttributes]::ReparsePoint)) { Fail 'Tauri did not produce a physical raw x86_64 PE application' }
$packageCargoManifest = Join-Path $plan.stageRoot 'desktop\src-tauri\Cargo.toml'
$workspaceCargoManifest = Join-Path $plan.stageRoot 'desktop\Cargo.toml'
& $plan.node.path $writerPath --admission-file $admissionPath --raw $raw --out $plan.candidateRoot --tauri-config $configPath --package-cargo-manifest $packageCargoManifest --workspace-cargo-manifest $workspaceCargoManifest
if ($LASTEXITCODE -ne 0) { Fail "native handoff writer failed with exit code $LASTEXITCODE" }
$aclReceiptPath = Join-Path $plan.nativeWorkerRoot 'native-ntfs-acl-receipt.json'
& $plan.powershell.path -NoLogo -NoProfile -NonInteractive -File $aclCollectorPath -CandidateRoot $plan.candidateRoot -ExpectedBuilderSid $plan.isolation.builderSid -Out $aclReceiptPath
if ($LASTEXITCODE -ne 0) { Fail "native NTFS ACL receipt collector failed with exit code $LASTEXITCODE" }
Write-Output 'WINDOWS_NATIVE_UNSIGNED_BUILD_COMPLETE status=pass'
