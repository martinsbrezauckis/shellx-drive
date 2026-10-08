[CmdletBinding(PositionalBinding = $false)]
param(
  [string] $Version = "1.0.128",
  [string] $CacheRoot = "$env:USERPROFILE\shellx-signing-tools-private"
)

$ErrorActionPreference = "Stop"
$PackageName = "microsoft.artifactsigning.client"
$PackageLeaf = "$PackageName.$Version.nupkg"
$RegistrationUrl = "https://api.nuget.org/v3/registration5-gz-semver2/$PackageName/$Version.json"
$SecurityHelper = Join-Path $PSScriptRoot "windows-release-security.ps1"

if (-not (Test-Path -LiteralPath $SecurityHelper -PathType Leaf)) {
  throw "Windows release security helper was not found: $SecurityHelper"
}
. $SecurityHelper

function Get-FileSha512Base64([string] $Path) {
  $Stream = [System.IO.File]::OpenRead($Path)
  try {
    $Hasher = [System.Security.Cryptography.SHA512]::Create()
    try { return [Convert]::ToBase64String($Hasher.ComputeHash($Stream)) }
    finally { $Hasher.Dispose() }
  } finally {
    $Stream.Dispose()
  }
}

function Assert-MicrosoftPackageDirectory([string] $Path) {
  $Directory = Get-Item -LiteralPath $Path -Force
  Assert-NoReparsePoint $Directory "Artifact Signing package directory"
  Assert-TrustedWindowsPathAcl $Directory "Artifact Signing package directory"
  $Entries = @(Get-ChildItem -LiteralPath $Directory.FullName -Force)
  if ($Entries.Count -eq 0 -or $Entries.Count -gt 128) {
    throw "Artifact Signing package directory has an unsafe file count"
  }
  foreach ($Entry in $Entries) {
    if ($Entry -isnot [System.IO.FileInfo] -or
        ($Entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Artifact Signing package directory must contain only flat regular files"
    }
    Assert-TrustedWindowsPathAcl $Entry "Artifact Signing package file"
    if ($Entry.Extension -ieq ".dll") {
      $Signature = Get-AuthenticodeSignature -LiteralPath $Entry.FullName
      if ($Signature.Status.ToString() -ne "Valid" -or
          $null -eq $Signature.SignerCertificate -or
          $Signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
        throw "Artifact Signing package DLL is not validly signed by Microsoft: $($Entry.Name)"
      }
    }
  }
  $Dlib = Join-Path $Directory.FullName "Azure.CodeSigning.Dlib.dll"
  if (-not (Test-Path -LiteralPath $Dlib -PathType Leaf)) {
    throw "Artifact Signing package does not contain Azure.CodeSigning.Dlib.dll"
  }
  return $Dlib
}

$CacheFullPath = [System.IO.Path]::GetFullPath($CacheRoot)
if (Test-Path -LiteralPath $CacheFullPath) {
  $Cache = Get-Item -LiteralPath $CacheFullPath -Force
  if (-not $Cache.PSIsContainer) { throw "Signing tool cache is not a directory: $CacheFullPath" }
  Assert-PrivateWindowsAcl $Cache "Signing tool cache"
} else {
  $Cache = Claim-PrivateWindowsDirectory $CacheFullPath
}

$PackageParent = Join-Path $Cache.FullName "Microsoft.ArtifactSigning.Client"
[void] [System.IO.Directory]::CreateDirectory($PackageParent)
$PackageDirectory = Join-Path $PackageParent $Version
$DlibDirectory = Join-Path $PackageDirectory "bin\x64"
if (Test-Path -LiteralPath $PackageDirectory) {
  Write-Output (Assert-MicrosoftPackageDirectory $DlibDirectory)
  exit 0
}

$Stage = New-PrivateWindowsDirectory $Cache.FullName ".artifact-signing-download-"
try {
  $Archive = Join-Path $Stage.FullName "$PackageLeaf.zip"
  $Extracted = Join-Path $Stage.FullName "package"
  $Registration = Invoke-RestMethod -UseBasicParsing -Uri $RegistrationUrl
  $Catalog = Invoke-RestMethod -UseBasicParsing -Uri ([string] $Registration.catalogEntry)
  if ($Catalog.packageHashAlgorithm -cne "SHA512" -or
      $Catalog.version -cne $Version -or
      -not $Registration.packageContent) {
    throw "NuGet registration metadata does not identify the requested package"
  }
  $ExpectedSha512 = ([string] $Catalog.packageHash).Trim()
  if ($ExpectedSha512 -notmatch '^[A-Za-z0-9+/]{86}==$') {
    throw "NuGet returned an invalid package SHA-512"
  }
  Invoke-WebRequest -UseBasicParsing -Uri ([string] $Registration.packageContent) -OutFile $Archive
  $ObservedSha512 = Get-FileSha512Base64 $Archive
  if ($ObservedSha512 -cne $ExpectedSha512) {
    throw "Downloaded Artifact Signing package does not match NuGet SHA-512"
  }
  Expand-Archive -LiteralPath $Archive -DestinationPath $Extracted
  $StagedDlibDirectory = Join-Path $Extracted "bin\x64"
  [void] (Assert-MicrosoftPackageDirectory $StagedDlibDirectory)
  [System.IO.Directory]::Move($Extracted, $PackageDirectory)
  Write-Output (Assert-MicrosoftPackageDirectory $DlibDirectory)
} finally {
  if (Test-Path -LiteralPath $Stage.FullName) {
    [System.IO.Directory]::Delete($Stage.FullName, $true)
  }
}
