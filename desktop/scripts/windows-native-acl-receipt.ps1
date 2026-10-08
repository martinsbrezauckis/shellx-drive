# Collects only post-build NTFS ownership and ACL metadata for the fixed raw
# handoff. It is sealed by the native admission plan and is PowerShell 5.1
# compatible: it does not inspect signing stores, profiles, or credentials.
param(
  [Parameter(Mandatory = $true)][string]$CandidateRoot,
  [Parameter(Mandatory = $true)][string]$ExpectedBuilderSid,
  [Parameter(Mandatory = $true)][string]$Out
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail([string]$Message) { throw "Windows NTFS ACL receipt: $Message" }
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
function Read-ExclusiveAcl([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { Fail "required handoff path is missing: $Path" }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail "handoff path is a reparse point: $Path" }
  $acl = Get-Acl -LiteralPath $Path
  $ownerSid = Convert-ToSid $acl.Owner
  if ($ownerSid -ne $ExpectedBuilderSid) { Fail "handoff owner SID differs from the admitted builder: $Path" }
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -lt 1) { Fail "handoff path has no explicit or inherited ACL rules: $Path" }
  $recorded = @()
  foreach ($rule in $rules) {
    $sid = Convert-ToSid $rule.IdentityReference
    $access = $rule.AccessControlType.ToString()
    $rights = $rule.FileSystemRights.ToString()
    if ($sid -ne $ExpectedBuilderSid -or $access -ne 'Allow' -or $rights -ne 'FullControl') { Fail "handoff path ACL grants an unexpected principal or right: $Path" }
    $recorded += [pscustomobject]@{
      access = $access
      inheritance = $rule.InheritanceFlags.ToString()
      propagation = $rule.PropagationFlags.ToString()
      rights = $rights
      sid = $sid
    }
  }
  [pscustomobject]@{
    accessRules = @($recorded | Sort-Object sid, access, rights, inheritance, propagation)
    ownerSid = $ownerSid
    path = $Path
    protected = [bool]$acl.AreAccessRulesProtected
  }
}

if (-not (Test-CanonicalWindowsPath $CandidateRoot) -or -not (Test-CanonicalWindowsPath $Out)) { Fail 'candidate root and receipt output must be canonical absolute Windows paths' }
if ($ExpectedBuilderSid -notmatch '^S-\d+(?:-\d+)+$') { Fail 'expected builder SID is invalid' }
if (Test-Path -LiteralPath $Out) { Fail 'receipt output must be fresh' }
$paths = @(
  $CandidateRoot,
  (Join-Path $CandidateRoot 'payload'),
  (Join-Path $CandidateRoot 'payload\shellx-drive-desktop.exe'),
  (Join-Path $CandidateRoot 'unsigned-handoff.json')
)
$receipt = [ordered]@{
  builderSid = $ExpectedBuilderSid
  candidateRoot = $CandidateRoot
  paths = @($paths | ForEach-Object { Read-ExclusiveAcl $_ })
  schema = 'release-studio.shellx-drive-windows-ntfs-acl-receipt/v1'
  status = 'pass'
}
$bytes = [System.Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json -Depth 8 -Compress) + "`n")
$stream = New-Object System.IO.FileStream($Out, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
