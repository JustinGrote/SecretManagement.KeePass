function Unregister-SecretVault {
    [CmdletBinding()]
    param(
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    try {
        Remove-Variable -Name "Vault_$VaultName" -Scope Script -Force -ErrorAction Stop
    } catch [ItemNotFoundException] {
        Write-Verbose "Vault ${VaultName}: Vault was not loaded at time of deregistration"
    }
}