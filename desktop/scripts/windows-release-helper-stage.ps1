[CmdletBinding(PositionalBinding = $false)]
param(
  [string] $SourceDirectoryPath = "",
  [string] $ExpectedStageHelperSha256 = "",
  [string] $ExpectedSecurityHelperSha256 = "",
  [string] $ExpectedComponentsHelperSha256 = "",
  [string] $ExpectedIdentityHelperSha256 = "",
  [string] $ExpectedSignerSha256 = "",
  [string] $RemovePrivateDirectoryPath = ""
)

$ErrorActionPreference = "Stop"

function Get-ExactReleaseHelper(
  [string] $Path,
  [string] $ExpectedSha256,
  [string] $Label
) {
  if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$' -or
      -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label identity is missing"
  }
  $Item = Get-Item -LiteralPath $Path -Force
  if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label must not be a reparse point"
  }
  $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Item.FullName).Hash.ToLowerInvariant()
  if ($ActualSha256 -ne $ExpectedSha256) {
    throw "$Label does not match its committed SHA-256"
  }
  return $Item
}

$StageHelper = Get-ExactReleaseHelper `
  $PSCommandPath $ExpectedStageHelperSha256 "Release helper staging entry"
if (-not $SourceDirectoryPath) {
  $SourceDirectoryPath = $StageHelper.Directory.FullName
}
$SecuritySource = Get-ExactReleaseHelper `
  (Join-Path $SourceDirectoryPath "windows-release-security.ps1") `
  $ExpectedSecurityHelperSha256 `
  "Windows release security helper"
. $SecuritySource.FullName

if ($RemovePrivateDirectoryPath) {
  Remove-PrivateWindowsDirectory $RemovePrivateDirectoryPath "Private Windows release helper stage"
  return
}
if (-not $SourceDirectoryPath) {
  throw "Private helper staging requires a source directory"
}

$ComponentsSource = Get-ExactReleaseHelper `
  (Join-Path $SourceDirectoryPath "windows-signing-components.ps1") `
  $ExpectedComponentsHelperSha256 `
  "Windows signing components helper"
$IdentitySource = Get-ExactReleaseHelper `
  (Join-Path $SourceDirectoryPath "windows-artifact-identity.ps1") `
  $ExpectedIdentityHelperSha256 `
  "Windows artifact identity helper"
$SignerSource = Get-ExactReleaseHelper `
  (Join-Path $SourceDirectoryPath "windows-artifact-sign.ps1") `
  $ExpectedSignerSha256 `
  "Windows artifact signer"
$PrivateStageParent = [Environment]::GetFolderPath("UserProfile")
if (-not $PrivateStageParent) {
  throw "Windows user profile is unavailable for private helper staging"
}
$PrivateStage = New-PrivateWindowsDirectory `
  -ParentPath $PrivateStageParent `
  -Prefix ".shellx-drive-release-helpers-$PID-"
try {
  foreach ($Helper in @(
      @{ Source = $SecuritySource; Sha256 = $ExpectedSecurityHelperSha256 },
      @{ Source = $ComponentsSource; Sha256 = $ExpectedComponentsHelperSha256 },
      @{ Source = $IdentitySource; Sha256 = $ExpectedIdentityHelperSha256 },
      @{ Source = $SignerSource; Sha256 = $ExpectedSignerSha256 }
    )) {
    $Destination = Join-Path $PrivateStage.FullName $Helper.Source.Name
    [void] (Copy-PinnedFileToPrivateStage `
      -SourcePath $Helper.Source.FullName `
      -DestinationPath $Destination `
      -ExpectedSha256 $Helper.Sha256 `
      -Label "Release helper $($Helper.Source.Name)")
  }
  [PSCustomObject]@{
    stage_path = $PrivateStage.FullName
    signer_path = (Join-Path $PrivateStage.FullName $SignerSource.Name)
    security_path = (Join-Path $PrivateStage.FullName $SecuritySource.Name)
    components_path = (Join-Path $PrivateStage.FullName $ComponentsSource.Name)
    identity_path = (Join-Path $PrivateStage.FullName $IdentitySource.Name)
  } | ConvertTo-Json -Compress
} catch {
  Remove-PrivateWindowsDirectory $PrivateStage.FullName "Failed Windows release helper stage"
  throw
}
