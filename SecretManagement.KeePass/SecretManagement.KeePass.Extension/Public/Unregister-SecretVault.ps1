using namespace System.Management.Automation
function Unregister-SecretVault {
    [CmdletBinding()]
    param(
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    if ($AdditionalParameters.Verbose) {$VerbosePreference = 'continue'}
    try {
        Remove-Variable -Name "Vault_$VaultName" -Scope Script -Force -ErrorAction Stop
    } catch [ItemNotFoundException] {
        Write-Verbose "Vault ${VaultName}: Vault was not loaded at time of deregistration"
    }
}