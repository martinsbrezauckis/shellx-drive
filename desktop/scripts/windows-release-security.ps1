[CmdletBinding(PositionalBinding = $false)]
param(
  [string] $ClaimPrivateDirectoryPath = "",
  [string] $VerifyPrivateDirectoryPath = ""
)

# Shared Windows filesystem controls for the release builder and Authenticode
# helper. Keep this file free of signing side effects when it is dot-sourced.

$script:CurrentReleaseUserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$script:TrustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
$script:TrustedReleasePrincipalSids = @(
  $script:CurrentReleaseUserSid.Value,
  "S-1-5-18",        # LocalSystem
  "S-1-5-32-544",    # BUILTIN\Administrators
  $script:TrustedInstallerSid
)
$script:FileMutationRights = [int64](
  [System.Security.AccessControl.FileSystemRights]::WriteData -bor
  [System.Security.AccessControl.FileSystemRights]::AppendData -bor
  [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
  [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
  [System.Security.AccessControl.FileSystemRights]::Delete -bor
  [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
  [System.Security.AccessControl.FileSystemRights]::TakeOwnership
)
$script:ParentReplacementRights = [int64](
  [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
  [System.Security.AccessControl.FileSystemRights]::Delete -bor
  [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
  [System.Security.AccessControl.FileSystemRights]::TakeOwnership
)
$script:DirectoryMutationRights = [int64](
  $script:FileMutationRights -bor
  $script:ParentReplacementRights
)

function Test-TrustedReleasePrincipal(
  [System.Security.Principal.SecurityIdentifier] $Sid
) {
  return $script:TrustedReleasePrincipalSids -contains $Sid.Value
}

function Assert-NoReparsePoint([System.IO.FileSystemInfo] $Item, [string] $Label) {
  $Current = $Item
  while ($null -ne $Current) {
    if (($Current.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "$Label traverses a reparse point: $($Current.FullName)"
    }
    if ($Current -is [System.IO.FileInfo]) {
      $Current = $Current.Directory
    } else {
      $Current = $Current.Parent
    }
  }
}

function Get-RegularNonReparseFile([string] $Path, [string] $Label) {
  if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "$Label does not exist: $Path"
  }
  $Item = Get-Item -LiteralPath $Path -Force
  Assert-NoReparsePoint $Item $Label
  return $Item
}

function Assert-TrustedWindowsPathAcl(
  [System.IO.FileSystemInfo] $Item,
  [string] $Label
) {
  $Current = $Item
  $Leaf = $true
  while ($null -ne $Current) {
    $Acl = Get-Acl -LiteralPath $Current.FullName
    $OwnerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier])
    if (-not (Test-TrustedReleasePrincipal $OwnerSid)) {
      throw "$Label has an untrusted Windows owner: $($Current.FullName)"
    }

    $DangerousRights = if ($Leaf) {
      if ($Current -is [System.IO.FileInfo]) {
        $script:FileMutationRights
      } else {
        $script:DirectoryMutationRights
      }
    } else {
      $script:ParentReplacementRights
    }
    foreach ($Rule in $Acl.GetAccessRules(
      $true,
      $true,
      [System.Security.Principal.SecurityIdentifier]
    )) {
      if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
        continue
      }
      if (($Rule.PropagationFlags -band
          [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) {
        continue
      }
      $RuleSid = [System.Security.Principal.SecurityIdentifier] $Rule.IdentityReference
      $GrantedRights = [int64] $Rule.FileSystemRights
      if (-not (Test-TrustedReleasePrincipal $RuleSid) -and
          (($GrantedRights -band $DangerousRights) -ne 0)) {
        throw "$Label is replaceable by an untrusted Windows principal at $($Current.FullName)"
      }
    }

    $Current = $Current.Parent
    $Leaf = $false
  }
}

function Assert-PrivateWindowsAcl(
  [System.IO.FileSystemInfo] $Item,
  [string] $Label
) {
  Assert-NoReparsePoint $Item $Label
  $Acl = Get-Acl -LiteralPath $Item.FullName
  $OwnerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier])
  if ($OwnerSid.Value -ne $script:CurrentReleaseUserSid.Value) {
    throw "$Label is not owned by the current Windows user"
  }
  if (-not $Acl.AreAccessRulesProtected) {
    throw "$Label has an inheritable Windows DACL"
  }

  $CurrentHasFullControl = $false
  $FullControl = [int64] [System.Security.AccessControl.FileSystemRights]::FullControl
  foreach ($Rule in $Acl.GetAccessRules(
    $true,
    $true,
    [System.Security.Principal.SecurityIdentifier]
  )) {
    if ($Rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
      continue
    }
    $RuleSid = [System.Security.Principal.SecurityIdentifier] $Rule.IdentityReference
    if ($RuleSid.Value -ne $script:CurrentReleaseUserSid.Value) {
      throw "$Label grants access to a foreign Windows principal"
    }
    $GrantedRights = [int64] $Rule.FileSystemRights
    if (($GrantedRights -band $FullControl) -eq $FullControl) {
      $CurrentHasFullControl = $true
    }
  }
  if (-not $CurrentHasFullControl) {
    throw "$Label does not grant the current Windows user full control"
  }
}

function New-PrivateWindowsDirectory(
  [string] $ParentPath,
  [string] $Prefix
) {
  $Parent = Get-Item -LiteralPath $ParentPath -Force
  if (-not $Parent.PSIsContainer) {
    throw "Private release directory parent is not a directory: $ParentPath"
  }
  Assert-NoReparsePoint $Parent "Private release directory parent"
  Assert-TrustedWindowsPathAcl $Parent "Private release directory parent"

  $Security = [System.Security.AccessControl.DirectorySecurity]::new()
  $Security.SetOwner($script:CurrentReleaseUserSid)
  $Security.SetAccessRuleProtection($true, $false)
  $Inheritance = (
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  )
  $Rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $script:CurrentReleaseUserSid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $Inheritance,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  [void] $Security.AddAccessRule($Rule)

  for ($Attempt = 0; $Attempt -lt 32; $Attempt++) {
    $Candidate = Join-Path $Parent.FullName ($Prefix + [Guid]::NewGuid().ToString("N"))
    if (Test-Path -LiteralPath $Candidate) {
      continue
    }
    $Directory = [System.IO.Directory]::CreateDirectory($Candidate, $Security)
    $Item = Get-Item -LiteralPath $Directory.FullName -Force
    Assert-PrivateWindowsAcl $Item "Private release directory"
    return $Item
  }
  throw "Could not allocate a private Windows release directory"
}

function Set-PrivateWindowsFileAcl([string] $Path, [string] $Label) {
  $Security = [System.Security.AccessControl.FileSecurity]::new()
  $Security.SetOwner($script:CurrentReleaseUserSid)
  $Security.SetAccessRuleProtection($true, $false)
  $Rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
    $script:CurrentReleaseUserSid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
  [void] $Security.AddAccessRule($Rule)
  $Item = Get-RegularNonReparseFile $Path $Label
  $Item.SetAccessControl($Security)
  $Item = Get-RegularNonReparseFile $Path $Label
  Assert-PrivateWindowsAcl $Item $Label
  return $Item
}

function Test-WslUncPath([string] $Path) {
  # The WSL provider has no Windows ACL surface. Its sources enter only through
  # Copy-PinnedFileToPrivateStage's exact-digest copy into protected NTFS.
  return $Path.StartsWith('\\wsl.localhost\', [System.StringComparison]::OrdinalIgnoreCase) -or
    $Path.StartsWith('\\wsl$\', [System.StringComparison]::OrdinalIgnoreCase)
}

function Claim-PrivateWindowsDirectory([string] $Path) {
  if (-not $Path) {
    throw "Private candidate output path is required"
  }
  $FullPath = [System.IO.Path]::GetFullPath($Path)
  if (Test-Path -LiteralPath $FullPath) {
    throw "Candidate output directory already exists: $FullPath"
  }
  $ParentPath = Split-Path -Parent $FullPath
  if (-not $ParentPath) {
    throw "Candidate output directory must have an absolute parent"
  }
  [void] [System.IO.Directory]::CreateDirectory($ParentPath)
  $Parent = Get-Item -LiteralPath $ParentPath -Force
  Assert-NoReparsePoint $Parent "Candidate output parent"
  Assert-TrustedWindowsPathAcl $Parent "Candidate output parent"

  $Temporary = New-PrivateWindowsDirectory $Parent.FullName ".shellx-drive-output-"
  try {
    # Directory.Move is the exclusive publication step: it fails if the final
    # candidate path appeared after the initial absence check.
    [System.IO.Directory]::Move($Temporary.FullName, $FullPath)
  } catch {
    if (Test-Path -LiteralPath $Temporary.FullName) {
      [System.IO.Directory]::Delete($Temporary.FullName, $true)
    }
    throw
  }
  $Claimed = Get-Item -LiteralPath $FullPath -Force
  Assert-PrivateWindowsAcl $Claimed "Candidate output directory"
  return $Claimed
}

function Copy-PinnedFileToPrivateStage(
  [string] $SourcePath,
  [string] $DestinationPath,
  [string] $ExpectedSha256,
  [string] $Label
) {
  if ($ExpectedSha256 -notmatch '^[0-9a-f]{64}$') {
    throw "$Label expected SHA-256 is invalid"
  }
  $Source = Get-RegularNonReparseFile $SourcePath $Label
  if (-not (Test-WslUncPath $Source.FullName)) {
    Assert-TrustedWindowsPathAcl $Source $Label
  }
  $SourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Source.FullName).Hash.ToLowerInvariant()
  if ($SourceHash -ne $ExpectedSha256) {
    throw "$Label bytes changed before private staging"
  }
  if (Test-Path -LiteralPath $DestinationPath) {
    throw "$Label private staging destination already exists"
  }
  [System.IO.File]::Copy($Source.FullName, $DestinationPath, $false)
  # A new file can inherit the private parent ACE while its own DACL remains
  # unprotected. Make the staged file's current-user-only DACL explicit before
  # treating it as the component later reopened for execution or native load.
  $Staged = Set-PrivateWindowsFileAcl $DestinationPath "Staged $Label"
  $StagedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Staged.FullName).Hash.ToLowerInvariant()
  if ($StagedHash -ne $ExpectedSha256) {
    throw "$Label private staged copy does not match its pinned SHA-256"
  }
  return $Staged
}

function Assert-PinnedPrivateFile(
  [string] $Path,
  [string] $ExpectedSha256,
  [string] $Label
) {
  $Item = Get-RegularNonReparseFile $Path $Label
  Assert-PrivateWindowsAcl $Item $Label
  $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $Item.FullName).Hash.ToLowerInvariant()
  if ($ActualSha256 -ne $ExpectedSha256) {
    throw "$Label no longer matches its pinned SHA-256"
  }
  return $Item
}

function Remove-PrivateWindowsDirectory([string] $Path, [string] $Label) {
  if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
    return
  }
  $Item = Get-Item -LiteralPath $Path -Force
  if (-not $Item.PSIsContainer) {
    throw "$Label cleanup target is not a directory"
  }
  Assert-PrivateWindowsAcl $Item $Label
  [System.IO.Directory]::Delete($Item.FullName, $true)
}

if ($ClaimPrivateDirectoryPath -and $VerifyPrivateDirectoryPath) {
  throw "Choose either -ClaimPrivateDirectoryPath or -VerifyPrivateDirectoryPath"
}
if ($ClaimPrivateDirectoryPath) {
  $ErrorActionPreference = "Stop"
  $Claimed = Claim-PrivateWindowsDirectory $ClaimPrivateDirectoryPath
  Write-Output "WINDOWS_PRIVATE_DIRECTORY_CLAIMED path=$($Claimed.FullName)"
} elseif ($VerifyPrivateDirectoryPath) {
  $ErrorActionPreference = "Stop"
  $Verified = Get-Item -LiteralPath $VerifyPrivateDirectoryPath -Force
  if (-not $Verified.PSIsContainer) {
    throw "Private candidate output is not a directory"
  }
  Assert-PrivateWindowsAcl $Verified "Candidate output directory"
  Write-Output "WINDOWS_PRIVATE_DIRECTORY_VERIFIED path=$($Verified.FullName)"
}
