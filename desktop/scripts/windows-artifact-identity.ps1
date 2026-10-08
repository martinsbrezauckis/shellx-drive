# Stable ShellX Drive publisher verification for final Windows artifacts.
# Azure Artifact Signing rotates short-lived leaf certificates, so admission
# pins the publisher and Microsoft issuer identities while recording each
# observed certificate for the release receipt.

$script:ExpectedDrivePublisher = [ordered]@{
  common_name = "U1C"
  organization = "U1C"
  country = "LV"
  signer_issuer_organization = "Microsoft Corporation"
  timestamp_issuer_organization = "Microsoft Corporation"
}

function Get-DistinguishedNameValue([string] $DistinguishedName, [string] $Name) {
  $Pattern = "(?:^|,\s*)$([regex]::Escape($Name))=([^,]+)"
  $Match = [regex]::Match($DistinguishedName, $Pattern, "IgnoreCase")
  if (-not $Match.Success) { return "" }
  return $Match.Groups[1].Value.Trim()
}

function Get-CertificateObservation(
  [Security.Cryptography.X509Certificates.X509Certificate2] $Certificate
) {
  return [PSCustomObject][ordered]@{
    subject = $Certificate.Subject
    issuer = $Certificate.Issuer
    thumbprint = $Certificate.Thumbprint.ToLowerInvariant()
    serial_number = $Certificate.SerialNumber.ToLowerInvariant()
    not_before = $Certificate.NotBefore.ToUniversalTime().ToString("o")
    not_after = $Certificate.NotAfter.ToUniversalTime().ToString("o")
  }
}

function Assert-ApprovedArtifactAuthenticode([string] $Artifact) {
  $Signature = Get-AuthenticodeSignature -LiteralPath $Artifact
  if ($Signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
      $null -eq $Signature.SignerCertificate -or
      $null -eq $Signature.TimeStamperCertificate) {
    throw "Final artifact must have a valid Authenticode signature and timestamp"
  }
  $Signer = $Signature.SignerCertificate
  $Timestamp = $Signature.TimeStamperCertificate
  $ObservedPublisher = [ordered]@{
    common_name = (Get-DistinguishedNameValue $Signer.Subject "CN")
    organization = (Get-DistinguishedNameValue $Signer.Subject "O")
    country = (Get-DistinguishedNameValue $Signer.Subject "C")
    signer_issuer_organization = (Get-DistinguishedNameValue $Signer.Issuer "O")
    timestamp_issuer_organization = (Get-DistinguishedNameValue $Timestamp.Issuer "O")
  }
  foreach ($Name in $script:ExpectedDrivePublisher.Keys) {
    if ($ObservedPublisher[$Name] -cne $script:ExpectedDrivePublisher[$Name]) {
      throw "Final artifact signer does not match the approved ShellX Drive publisher profile"
    }
  }
  return [PSCustomObject][ordered]@{
    status = $Signature.Status.ToString()
    verified_at = (Get-Date).ToUniversalTime().ToString("o")
    publisher = [PSCustomObject]$ObservedPublisher
    signer_certificate = (Get-CertificateObservation $Signer)
    timestamp_certificate = (Get-CertificateObservation $Timestamp)
  }
}
