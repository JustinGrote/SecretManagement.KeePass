function Unregister-SecretVault {
    param(
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    Remove-Variable -Name "Vault_$VaultName" -Scope Script -Force -ErrorAction SilentlyContinue
}