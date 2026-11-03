<#
.SYNOPSIS
  Fait approuver par ce poste le certificat de signature interne de Chiffrium (à exécuter en administrateur).

.DESCRIPTION
  Ajoute le certificat public (.cer) aux magasins "Autorités de certification racines de confiance" et
  "Éditeurs approuvés" de l'ordinateur. Pour un parc entier, préférer une stratégie de groupe
  (voir docs/code-signing.md) : même effet, sans passer sur chaque poste.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File trust-signing-cert.ps1 -Certificate .\Chiffrium-signature.cer
#>
param(
    [Parameter(Mandatory = $true)] [string] $Certificate
)
$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Exécuter ce script dans une console PowerShell ouverte en tant qu'administrateur."
}
Import-Certificate -FilePath $Certificate -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $Certificate -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
Write-Host "Certificat approuvé : les installateurs Chiffrium signés ne déclencheront plus d'avertissement sur ce poste."
