<#
.SYNOPSIS
  Crée gratuitement un certificat de signature de code interne pour Chiffrium.

.DESCRIPTION
  Génère une paire de clés RSA 3072 dans le magasin de l'utilisateur, puis exporte :
    - Chiffrium-signature.pfx : clé privée + certificat, protégé par mot de passe (à garder secret) ;
    - Chiffrium-signature.cer : certificat public, à faire approuver par les postes (trust-signing-cert.ps1
      ou stratégie de groupe).
  Les installateurs signés avec ce certificat ne déclenchent plus d'avertissement sur les postes qui l'approuvent.
  Hors de l'organisation, Windows continue d'avertir (seuls les certificats d'une autorité publique l'évitent).

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File new-signing-cert.ps1 -Organisation "Mon entreprise"
#>
param(
    [string] $Organisation = "Chiffrium",
    [int] $Years = 3,
    [string] $OutDir = (Join-Path $PSScriptRoot "..\signing")
)
$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$password = Read-Host -AsSecureString "Mot de passe de protection du fichier .pfx (au moins 12 caractères)"

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=$Organisation (signature Chiffrium), O=$Organisation" `
    -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 `
    -KeyExportPolicy Exportable `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears($Years)

$pfx = Join-Path $OutDir "Chiffrium-signature.pfx"
$cer = Join-Path $OutDir "Chiffrium-signature.cer"
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $password | Out-Null
Export-Certificate -Cert $cert -FilePath $cer | Out-Null
# La clé privée ne reste que dans le .pfx protégé.
Remove-Item -Path ("Cert:\CurrentUser\My\" + $cert.Thumbprint)

Write-Host ""
Write-Host "Certificat créé (empreinte $($cert.Thumbprint), valable jusqu'au $($cert.NotAfter.ToString('d')))."
Write-Host "  Clé privée  : $pfx  (NE PAS commiter, NE PAS partager)"
Write-Host "  Certificat  : $cer  (à distribuer aux postes)"
Write-Host ""
Write-Host "Signer un build local :"
Write-Host "  `$env:CSC_LINK = '$pfx'; `$env:CSC_KEY_PASSWORD = '<mot de passe>'; npm run dist"
Write-Host "Signer les releases GitHub : voir docs/code-signing.md (secrets WINDOWS_CSC_LINK / WINDOWS_CSC_KEY_PASSWORD)."
