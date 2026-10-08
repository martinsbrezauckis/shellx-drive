[CmdletBinding(PositionalBinding = $false)]
param(
  [string[]] $Artifacts = @(),
  [string] $MetadataPath = $env:SHELLX_WINDOWS_SIGNING_METADATA_PATH,
  [string] $SignToolPath = $env:SHELLX_WINDOWS_SIGNTOOL_PATH,
  [string] $DlibPath = $env:SHELLX_WINDOWS_SIGNING_DLIB_PATH,
  [string] $ReceiptPath = $env:SHELLX_WINDOWS_SIGNING_RECEIPT_PATH,
  [string] $ExpectedArtifactSha256 = "",
  [string] $ExpectedMetadataSha256 = "",
  [string] $ExpectedSignerSha256 = "",
  [string] $ExpectedSecurityHelperSha256 = "",
  [string] $ExpectedComponentsHelperSha256 = "",
  [string] $ExpectedIdentityHelperSha256 = "",
  [string] $SigningStageParentPath = $env:SHELLX_WINDOWS_SIGNING_STAGE_PARENT,
  [string] $PublishDirectoryPath = "",
  [string] $PublishLeafName = "",
  [string] $CaptureDirectoryPath = "",
  [string] $CaptureLeafName = "",
  [switch] $RequirePrivateArtifact,
  [switch] $VerifyOnly,
  [switch] $ValidateToolsOnly
)

$ErrorActionPreference = "Stop"

function Get-ExactStagedReleaseHelper(
  [string] $Path,
  [string] $ExpectedSha256,
  [string] $Label
) {
  if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$' -or
      -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label staged identity is missing"
  }
  $Item = Get-Item -LiteralPath $Path -Force
  if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "$Label staged path must not be a reparse point"
  }
  $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Item.FullName).Hash.ToLowerInvariant()
  if ($ActualSha256 -ne $ExpectedSha256) {
    throw "$Label staged bytes changed before execution"
  }
  return $Item
}

$script:ReleaseHelperIdentities = [ordered]@{}
$SignerItem = Get-ExactStagedReleaseHelper `
  $PSCommandPath $ExpectedSignerSha256 "Windows artifact signer"
$script:ReleaseHelperIdentities.signer = [ordered]@{
  resolved_path = $SignerItem.FullName
  sha256 = $ExpectedSignerSha256
}
$SecurityHelperPath = Join-Path $PSScriptRoot "windows-release-security.ps1"
$SecurityHelperItem = Get-ExactStagedReleaseHelper `
  $SecurityHelperPath $ExpectedSecurityHelperSha256 "Windows release security helper"
$SecurityHelperPath = $SecurityHelperItem.FullName
$script:ReleaseHelperIdentities.release_security = [ordered]@{
  resolved_path = $SecurityHelperPath
  sha256 = $ExpectedSecurityHelperSha256
}
. $SecurityHelperPath

$ComponentsHelperPath = Join-Path $PSScriptRoot "windows-signing-components.ps1"
$ComponentsHelperItem = Get-ExactStagedReleaseHelper `
  $ComponentsHelperPath $ExpectedComponentsHelperSha256 "Windows signing components helper"
$ComponentsHelperPath = $ComponentsHelperItem.FullName
$script:ReleaseHelperIdentities.signing_components = [ordered]@{
  resolved_path = $ComponentsHelperPath
  sha256 = $ExpectedComponentsHelperSha256
}
. $ComponentsHelperPath

$IdentityHelperPath = Join-Path $PSScriptRoot "windows-artifact-identity.ps1"
$IdentityHelperItem = Get-ExactStagedReleaseHelper `
  $IdentityHelperPath $ExpectedIdentityHelperSha256 "Windows artifact identity helper"
$IdentityHelperPath = $IdentityHelperItem.FullName
$script:ReleaseHelperIdentities.artifact_identity = [ordered]@{
  resolved_path = $IdentityHelperPath
  sha256 = $ExpectedIdentityHelperSha256
}
. $IdentityHelperPath

if ($Artifacts.Count -eq 1) {
  $EarlyArtifact = Get-RegularNonReparseFile $Artifacts[0] "Artifact"
  if ($EarlyArtifact.FullName -match '\\nsis\\.*\\Plugins\\.*\.dll$') {
    Write-Host "Skipping NSIS plugin helper: $($EarlyArtifact.FullName)"
    return
  }
}

$SigningStagePath = ""
$ArtifactStagePath = ""
$FailedPublishedArtifactPath = ""
$FailedPublishedArtifactSha256 = ""
try {
  if (-not $SignToolPath) {
    $SignToolPath = First-ExistingPath @(
      "${env:ProgramFiles(x86)}\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe",
      "${env:ProgramFiles(x86)}\Windows Kits\10\App Certification Kit\signtool.exe"
    )
  }
  if (-not $SignToolPath -or -not (Test-Path -LiteralPath $SignToolPath -PathType Leaf)) {
    throw "signtool.exe was not found. Set SHELLX_WINDOWS_SIGNTOOL_PATH."
  }

  if (-not $DlibPath) {
    $DlibPath = First-ExistingPath @(
      "$env:USERPROFILE\shellx-signing-tools-private\Microsoft.ArtifactSigning.Client\1.0.128\bin\x64\Azure.CodeSigning.Dlib.dll",
      "$env:USERPROFILE\.shellx\tools\artifact-signing\Microsoft.ArtifactSigning.Client\bin\x64\Azure.CodeSigning.Dlib.dll",
      "$env:USERPROFILE\.nuget\packages\microsoft.artifactsigning.client\1.0.128\bin\x64\Azure.CodeSigning.Dlib.dll"
    )
  }
  if (-not $DlibPath -or -not (Test-Path -LiteralPath $DlibPath -PathType Leaf)) {
    throw "Azure Artifact Signing Dlib was not found. Set SHELLX_WINDOWS_SIGNING_DLIB_PATH."
  }

  $SourceSignToolIdentity = Get-TrustedMicrosoftSigningComponent `
    -Path $SignToolPath `
    -Label "signtool.exe" `
    -ExpectedLeafName "signtool.exe" `
    -ExpectedOriginalFilename "signtool.exe"
  $SourceDlibIdentity = Get-TrustedMicrosoftSigningComponent `
    -Path $DlibPath `
    -Label "Azure Artifact Signing Dlib" `
    -ExpectedLeafName "Azure.CodeSigning.Dlib.dll"

  if (-not $SigningStageParentPath) {
    $SigningStageParentPath = $PublishDirectoryPath
  }
  if (-not $SigningStageParentPath -or
      -not (Test-Path -LiteralPath $SigningStageParentPath -PathType Container)) {
    throw "Signing requires a protected -SigningStageParentPath."
  }
  $SigningStageParent = Get-Item -LiteralPath $SigningStageParentPath -Force
  Assert-PrivateWindowsAcl $SigningStageParent "Signing stage parent"
  $SigningStage = New-PrivateWindowsDirectory `
    -ParentPath $SigningStageParent.FullName `
    -Prefix "shellx-drive-signing-$PID-"
  $SigningStagePath = $SigningStage.FullName
  $SignToolIdentity = Stage-TrustedMicrosoftSigningComponent `
    -SourceIdentity $SourceSignToolIdentity `
    -StagePath $SigningStagePath `
    -LeafName "signtool.exe" `
    -Label "signtool.exe" `
    -ExpectedOriginalFilename "signtool.exe"
  $DlibIdentity = Stage-TrustedDlibPackage $SourceDlibIdentity $SigningStagePath
  $SignToolPath = $SignToolIdentity.resolved_path
  $DlibPath = $DlibIdentity.resolved_path

  if ($ValidateToolsOnly) {
    Write-SigningComponentReceipt $ReceiptPath $SignToolIdentity $DlibIdentity
    [PSCustomObject]@{
      signtool = $SignToolIdentity
      artifact_signing_dlib = $DlibIdentity
    } | ConvertTo-Json -Compress -Depth 4
    return
  }

  if (-not $MetadataPath) {
    throw "SHELLX_WINDOWS_SIGNING_METADATA_PATH or -MetadataPath is required."
  }
  if ($Artifacts.Count -eq 0) {
    throw "At least one -Artifacts path is required unless -ValidateToolsOnly is used."
  }
  if ($Artifacts.Count -ne 1) {
    throw "Artifact signing accepts exactly one artifact identity per operation."
  }
  if ($ExpectedArtifactSha256 -notmatch '^[0-9a-f]{64}$') {
    throw "Artifact signing requires an exact lowercase pre-operation SHA-256."
  }
  if ($ExpectedMetadataSha256 -notmatch '^[0-9a-f]{64}$') {
    throw "Artifact signing requires an exact lowercase metadata SHA-256."
  }
  $Publishing = [bool] ($PublishDirectoryPath -or $PublishLeafName)
  $Capturing = [bool] ($CaptureDirectoryPath -or $CaptureLeafName)
  if ($Publishing -and (-not $PublishDirectoryPath -or -not $PublishLeafName)) {
    throw "Final artifact publication requires both directory and leaf name."
  }
  if ($Capturing -and (-not $CaptureDirectoryPath -or -not $CaptureLeafName)) {
    throw "Signed artifact capture requires both directory and leaf name."
  }
  if ($Capturing -and ($Publishing -or $VerifyOnly)) {
    throw "Signed artifact capture cannot be combined with publication or verify-only mode."
  }
  foreach ($CandidateLeaf in @($PublishLeafName, $CaptureLeafName)) {
    if ($CandidateLeaf -and (
        [System.IO.Path]::IsPathRooted($CandidateLeaf) -or
        [System.IO.Path]::GetFileName($CandidateLeaf) -cne $CandidateLeaf -or
        $CandidateLeaf -notmatch '^[A-Z0-9][A-Z0-9 _().-]*\.(EXE|MSI|PS1)$'
      )) {
      throw "Signed artifact destination leaf name is invalid."
    }
  }
  $MetadataItem = Get-RegularNonReparseFile $MetadataPath "Signing metadata file"
  $MetadataPath = (Copy-PinnedFileToPrivateStage `
    -SourcePath $MetadataItem.FullName `
    -DestinationPath (Join-Path $SigningStagePath "artifact-signing-metadata.json") `
    -ExpectedSha256 $ExpectedMetadataSha256 `
    -Label "Signing metadata file").FullName
  if (-not $VerifyOnly -and -not $ReceiptPath) {
    throw "Signing requires SHELLX_WINDOWS_SIGNING_RECEIPT_PATH or -ReceiptPath."
  }
  Write-SigningComponentReceipt $ReceiptPath $SignToolIdentity $DlibIdentity

  function Assert-ArtifactDigest(
    [string] $Artifact,
    [string] $ExpectedSha256,
    [bool] $PrivateArtifact
  ) {
    if ($PrivateArtifact) {
      return (Assert-PinnedPrivateFile $Artifact $ExpectedSha256 "Private staged artifact")
    }
    $Item = Get-RegularNonReparseFile $Artifact "Artifact"
    $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Item.FullName).Hash.ToLowerInvariant()
    if ($ActualSha256 -ne $ExpectedSha256) {
      throw "Artifact no longer matches its expected SHA-256"
    }
    return $Item
  }

  function Assert-AuthenticodeValid(
    [string] $Artifact,
    [string] $ExpectedSha256,
    [bool] $PrivateArtifact
  ) {
    # A new signature written through the WSL UNC provider can take a fraction
    # of a second to become visible to a second Windows process. Retry only the
    # independent verification; signing itself is never repeated implicitly.
    for ($Attempt = 1; $Attempt -le 5; $Attempt++) {
      # Reopen and hash the exact private copy immediately before every verify.
      [void] (Assert-ArtifactDigest $Artifact $ExpectedSha256 $PrivateArtifact)
      Assert-SignToolPinned $SignToolIdentity
      $VerifyOutput = & $SignToolPath verify /pa /v $Artifact
      $VerifyExitCode = $LASTEXITCODE
      $VerifyOutput | ForEach-Object { Write-Host $_ }
      if ($VerifyExitCode -eq 0) {
        return (Assert-ApprovedArtifactAuthenticode $Artifact)
      }
      if ($Attempt -lt 5) {
        Start-Sleep -Milliseconds (250 * $Attempt)
      }
    }
    throw "signtool verify failed for $Artifact"
  }

  foreach ($Artifact in $Artifacts) {
    $ArtifactItem = Get-RegularNonReparseFile $Artifact "Artifact"
    $Artifact = $ArtifactItem.FullName
    $PrivateArtifact = [bool] $RequirePrivateArtifact
    if ($Publishing) {
      $PublishDirectory = Get-Item -LiteralPath $PublishDirectoryPath -Force
      if (-not $PublishDirectory.PSIsContainer) {
        throw "Final artifact publication parent is not a directory."
      }
      Assert-PrivateWindowsAcl $PublishDirectory "Final artifact publication parent"
      $ArtifactStage = New-PrivateWindowsDirectory `
        -ParentPath $PublishDirectory.FullName `
        -Prefix ".shellx-drive-artifact-"
      $ArtifactStagePath = $ArtifactStage.FullName
      $StagedPath = Join-Path $ArtifactStagePath $PublishLeafName
      $Artifact = (Copy-PinnedFileToPrivateStage `
        -SourcePath $Artifact `
        -DestinationPath $StagedPath `
        -ExpectedSha256 $ExpectedArtifactSha256 `
        -Label "Pre-sign release artifact").FullName
      $PrivateArtifact = $true
    }

    [void] (Assert-ArtifactDigest $Artifact $ExpectedArtifactSha256 $PrivateArtifact)

    if (-not $VerifyOnly) {
      Write-Host "Authenticode signing $Artifact"
      # The admitted source components are never executed in place. Reopen and
      # hash both owner-only staged copies immediately before the signing sink.
      Assert-DlibPinned $DlibIdentity
      Assert-SignToolPinned $SignToolIdentity
      & $SignToolPath sign /v /fd SHA256 /tr "http://timestamp.acs.microsoft.com" /td SHA256 /dlib $DlibPath /dmdf $MetadataPath $Artifact
      if ($LASTEXITCODE -ne 0) {
        throw "signtool sign failed for $Artifact"
      }
    }

    $OperationSha256 = if ($VerifyOnly) {
      $ExpectedArtifactSha256
    } else {
      (Get-FileHash -Algorithm SHA256 -LiteralPath $Artifact).Hash.ToLowerInvariant()
    }
    Write-Host "Authenticode verifying $Artifact"
    $AuthenticodeObservation = Assert-AuthenticodeValid `
      $Artifact $OperationSha256 $PrivateArtifact

    if ($Capturing) {
      $CaptureDirectory = Get-Item -LiteralPath $CaptureDirectoryPath -Force
      Assert-PrivateWindowsAcl $CaptureDirectory "Signed artifact capture parent"
      $CapturedPath = Join-Path $CaptureDirectory.FullName $CaptureLeafName
      $Captured = Copy-PinnedFileToPrivateStage `
        $Artifact $CapturedPath $OperationSha256 "Signed release artifact capture"
      $FailedPublishedArtifactPath = $Captured.FullName
      $FailedPublishedArtifactSha256 = $OperationSha256
      Write-SignedArtifactReceipt `
        $ReceiptPath $CaptureLeafName $ExpectedArtifactSha256 $OperationSha256 `
        $AuthenticodeObservation
      $FailedPublishedArtifactPath = ""
      $FailedPublishedArtifactSha256 = ""
    }

    if ($Publishing) {
      $PublishedPath = Join-Path $PublishDirectory.FullName $PublishLeafName
      if (Test-Path -LiteralPath $PublishedPath) {
        throw "Final artifact publication destination already exists: $PublishedPath"
      }
      [System.IO.File]::Move($Artifact, $PublishedPath)
      $FailedPublishedArtifactPath = $PublishedPath
      $FailedPublishedArtifactSha256 = $OperationSha256
      [void] (Assert-PinnedPrivateFile `
        $PublishedPath $OperationSha256 "Published signed artifact")
      Write-SignedArtifactReceipt `
        $ReceiptPath $PublishLeafName $ExpectedArtifactSha256 $OperationSha256 `
        $AuthenticodeObservation
      $FailedPublishedArtifactPath = ""
      $FailedPublishedArtifactSha256 = ""
    }
  }
} finally {
  if ($FailedPublishedArtifactPath -and
      (Test-Path -LiteralPath $FailedPublishedArtifactPath -PathType Leaf)) {
    [void] (Assert-PinnedPrivateFile `
      $FailedPublishedArtifactPath `
      $FailedPublishedArtifactSha256 `
      "Failed published signed artifact")
    [System.IO.File]::Delete($FailedPublishedArtifactPath)
  }
  if ($ArtifactStagePath) {
    Remove-PrivateWindowsDirectory $ArtifactStagePath "Private artifact stage"
  }
  if ($SigningStagePath) {
    Remove-PrivateWindowsDirectory $SigningStagePath "Private signing component stage"
  }
}
