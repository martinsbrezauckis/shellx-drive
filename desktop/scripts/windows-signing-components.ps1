# Authenticode component admission, private staging, use-time validation, and
# schema-v3 receipt helpers. Dot-source windows-release-security.ps1 first.

function First-ExistingPath([string[]] $Paths) {
  foreach ($Path in $Paths) {
    if ($Path -and (Test-Path -LiteralPath $Path)) { return $Path }
  }
  return $null
}

function Get-TrustedMicrosoftSigningComponent(
  [string] $Path, [string] $Label, [string] $ExpectedLeafName,
  [string] $ExpectedOriginalFilename = ""
) {
  $Item = Get-RegularNonReparseFile $Path $Label
  Assert-TrustedWindowsPathAcl $Item $Label
  if ($Item.Name -ine $ExpectedLeafName) { throw "$Label must be named $ExpectedLeafName" }
  $Signature = Get-AuthenticodeSignature -LiteralPath $Item.FullName
  if ($Signature.Status.ToString() -ne "Valid" -or $null -eq $Signature.SignerCertificate) {
    throw "$Label does not have a valid Authenticode signature: $($Signature.Status)"
  }
  $Publisher = $Signature.SignerCertificate.Subject
  if ($Publisher -notmatch '(^|,\s*)O=Microsoft Corporation(,|$)') {
    throw "$Label is not signed by the expected Microsoft publisher: $Publisher"
  }
  if ($ExpectedOriginalFilename) {
    $OriginalFilename = $Item.VersionInfo.OriginalFilename
    if (-not $OriginalFilename -or $OriginalFilename -ine $ExpectedOriginalFilename) {
      throw "$Label has an unexpected original filename: $OriginalFilename"
    }
  }
  return [PSCustomObject]@{
    path = $Item.FullName
    sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Item.FullName).Hash.ToLowerInvariant()
    publisher = $Publisher
    publisher_thumbprint = $Signature.SignerCertificate.Thumbprint.ToLowerInvariant()
  }
}

function Stage-TrustedMicrosoftSigningComponent(
  $SourceIdentity, [string] $StagePath, [string] $LeafName, [string] $Label,
  [string] $ExpectedOriginalFilename = ""
) {
  $StagedPath = Join-Path $StagePath $LeafName
  [void] (Copy-PinnedFileToPrivateStage `
    -SourcePath $SourceIdentity.path `
    -DestinationPath $StagedPath `
    -ExpectedSha256 $SourceIdentity.sha256 `
    -Label $Label)
  $StagedIdentity = Get-TrustedMicrosoftSigningComponent `
    -Path $StagedPath `
    -Label "Staged $Label" `
    -ExpectedLeafName $LeafName `
    -ExpectedOriginalFilename $ExpectedOriginalFilename
  if ($StagedIdentity.sha256 -ne $SourceIdentity.sha256 -or
      $StagedIdentity.publisher_thumbprint -ne $SourceIdentity.publisher_thumbprint) {
    throw "$Label private staged identity does not match its admitted source"
  }
  return [PSCustomObject]@{
    path = $SourceIdentity.path
    resolved_path = $StagedIdentity.path
    sha256 = $StagedIdentity.sha256
    source_sha256 = $SourceIdentity.sha256
    publisher = $StagedIdentity.publisher
    publisher_thumbprint = $StagedIdentity.publisher_thumbprint
    private_stage_acl = "protected-current-user-only"
  }
}

function Stage-TrustedDlibPackage($SourceIdentity, [string] $StageParent) {
  $SourceDlib = Get-RegularNonReparseFile $SourceIdentity.path "Azure Artifact Signing Dlib"
  $SourceDirectory = $SourceDlib.Directory
  Assert-NoReparsePoint $SourceDirectory "Azure Artifact Signing Dlib directory"
  Assert-TrustedWindowsPathAcl $SourceDirectory "Azure Artifact Signing Dlib directory"
  $StageDirectory = New-PrivateWindowsDirectory $StageParent "dlib-"
  $Entries = @(Get-ChildItem -LiteralPath $SourceDirectory.FullName -Force | Sort-Object Name)
  if ($Entries.Count -eq 0 -or $Entries.Count -gt 128) {
    throw "Azure Artifact Signing Dlib package has an unsafe file count"
  }
  $TotalBytes = [int64] 0
  $Manifest = @()
  foreach ($Entry in $Entries) {
    if ($Entry -isnot [System.IO.FileInfo] -or
        ($Entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Azure Artifact Signing Dlib package must contain only flat regular files"
    }
    Assert-TrustedWindowsPathAcl $Entry "Azure Artifact Signing Dlib package file"
    $TotalBytes += $Entry.Length
    if ($TotalBytes -gt 536870912) {
      throw "Azure Artifact Signing Dlib package exceeds its private staging budget"
    }
    $Hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Entry.FullName).Hash.ToLowerInvariant()
    $Destination = Join-Path $StageDirectory.FullName $Entry.Name
    [void] (Copy-PinnedFileToPrivateStage $Entry.FullName $Destination $Hash "Dlib package file")
    $Manifest += [PSCustomObject]@{ name = $Entry.Name; sha256 = $Hash }
  }
  $StagedDlib = Get-TrustedMicrosoftSigningComponent `
    -Path (Join-Path $StageDirectory.FullName "Azure.CodeSigning.Dlib.dll") `
    -Label "Staged Azure Artifact Signing Dlib" `
    -ExpectedLeafName "Azure.CodeSigning.Dlib.dll"
  if ($StagedDlib.sha256 -ne $SourceIdentity.sha256 -or
      $StagedDlib.publisher_thumbprint -ne $SourceIdentity.publisher_thumbprint) {
    throw "Azure Artifact Signing Dlib staged identity does not match its admitted source"
  }
  return [PSCustomObject]@{
    path = $SourceIdentity.path
    resolved_path = $StagedDlib.path
    package_path = $StageDirectory.FullName
    sha256 = $StagedDlib.sha256
    source_sha256 = $SourceIdentity.sha256
    publisher = $StagedDlib.publisher
    publisher_thumbprint = $StagedDlib.publisher_thumbprint
    package_files = $Manifest
    private_stage_acl = "protected-current-user-only"
  }
}

function Get-ReleaseToolIdentities() {
  $Names = $env:SHELLX_DRIVE_RELEASE_TOOL_NAMES
  $Tools = [ordered]@{}
  if (-not $Names) {
    if (-not $ValidateToolsOnly) {
      throw "Pinned WSL release tool identities are required for signing and verification."
    }
    return $Tools
  }
  foreach ($Name in $Names.Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)) {
    if ($Name -notmatch '^[A-Z][A-Z0-9_]*$') { throw "Invalid pinned release tool name: $Name" }
    $Prefix = "SHELLX_DRIVE_RELEASE_TOOL_${Name}"
    $Path = [Environment]::GetEnvironmentVariable("${Prefix}_PATH")
    $ResolvedPath = [Environment]::GetEnvironmentVariable("${Prefix}_RESOLVED_PATH")
    $Sha256 = [Environment]::GetEnvironmentVariable("${Prefix}_SHA256")
    if (-not $Path -or -not $ResolvedPath -or $Sha256 -notmatch '^[0-9a-f]{64}$') {
      throw "Pinned release tool identity is incomplete: $Name"
    }
    $Tools[$Name.ToLowerInvariant()] = [ordered]@{
      path = $Path
      resolved_path = $ResolvedPath
      sha256 = $Sha256
    }
  }
  return $Tools
}

function Add-Utf8NoBomJsonLine([string] $Path, $Value) {
  $Encoding = [System.Text.UTF8Encoding]::new($false, $true)
  $Line = ($Value | ConvertTo-Json -Compress -Depth 6) + [Environment]::NewLine
  [System.IO.File]::AppendAllText($Path, $Line, $Encoding)
}

function Write-SigningComponentReceipt([string] $Path, $SignTool, $Dlib) {
  if (-not $Path) { return }
  $ParentPath = Split-Path -Parent $Path
  if (-not $ParentPath) { $ParentPath = (Get-Location).Path }
  if (-not (Test-Path -LiteralPath $ParentPath -PathType Container)) {
    throw "Signing receipt parent does not exist: $ParentPath"
  }
  $Parent = Get-Item -LiteralPath $ParentPath -Force
  Assert-NoReparsePoint $Parent "Signing receipt parent"
  if (Test-Path -LiteralPath $Path) {
    $Existing = Get-RegularNonReparseFile $Path "Signing receipt"
    $ReceiptFullName = $Existing.FullName
  } else {
    $ReceiptFullName = Join-Path $Parent.FullName (Split-Path -Leaf $Path)
  }
  $Entry = [ordered]@{
    schema = "shellx-drive.windows-signing-components/v3"
    recorded_at = (Get-Date).ToUniversalTime().ToString("o")
    source_commit = $env:SHELLX_DRIVE_EXPECTED_SOURCE_COMMIT
    signtool = $SignTool
    artifact_signing_dlib = $Dlib
    release_tools = (Get-ReleaseToolIdentities)
    release_helpers = $script:ReleaseHelperIdentities
  }
  Add-Utf8NoBomJsonLine $ReceiptFullName $Entry
}

function Write-SignedArtifactReceipt(
  [string] $Path,
  [string] $ArtifactLeaf,
  [string] $PreSignSha256,
  [string] $SignedSha256,
  $AuthenticodeObservation
) {
  if (-not $Path) { throw "Signed artifact receipt path is required" }
  $ParentPath = Split-Path -Parent $Path
  if (-not $ParentPath) { $ParentPath = (Get-Location).Path }
  $Parent = Get-Item -LiteralPath $ParentPath -Force
  Assert-NoReparsePoint $Parent "Signed artifact receipt parent"
  if (Test-Path -LiteralPath $Path) {
    $ReceiptFullName = (Get-RegularNonReparseFile $Path "Signed artifact receipt").FullName
  } else {
    $ReceiptFullName = Join-Path $Parent.FullName (Split-Path -Leaf $Path)
  }
  $Entry = [ordered]@{
    schema = "shellx-drive.windows-signed-artifact/v2"
    recorded_at = (Get-Date).ToUniversalTime().ToString("o")
    source_commit = $env:SHELLX_DRIVE_EXPECTED_SOURCE_COMMIT
    artifact_leaf = $ArtifactLeaf
    pre_sign_sha256 = $PreSignSha256
    signed_sha256 = $SignedSha256
    authenticode = $AuthenticodeObservation
    publication = "private-stage-file-move"
  }
  Add-Utf8NoBomJsonLine $ReceiptFullName $Entry
}

function Assert-MicrosoftPublisherPinned(
  $Identity, [string] $Label, [string] $ExpectedLeafName, [string] $ExpectedOriginalFilename = ""
) {
  [void] (Assert-PinnedPrivateFile $Identity.resolved_path $Identity.sha256 $Label)
  $Observed = Get-TrustedMicrosoftSigningComponent `
    $Identity.resolved_path $Label $ExpectedLeafName $ExpectedOriginalFilename
  if ($Observed.sha256 -ne $Identity.sha256 -or
      $Observed.publisher_thumbprint -ne $Identity.publisher_thumbprint -or
      $Observed.publisher -ne $Identity.publisher) {
    throw "$Label publisher-bound identity drifted immediately before use"
  }
}

function Assert-SignToolPinned($Identity) {
  Assert-MicrosoftPublisherPinned $Identity "Private staged signtool.exe" "signtool.exe" "signtool.exe"
}

function Assert-DlibPinned($Identity) {
  foreach ($Entry in $Identity.package_files) {
    [void] (Assert-PinnedPrivateFile `
      (Join-Path $Identity.package_path $Entry.name) $Entry.sha256 `
      "Private staged Azure Artifact Signing Dlib package file")
  }
  Assert-MicrosoftPublisherPinned $Identity "Private staged Azure Artifact Signing Dlib" "Azure.CodeSigning.Dlib.dll"
}
