function Unregister-SecretVault {
    param(
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    trap {
        write-VaultError $PSItem
    }
    Remove-Variable -Name "Vault_$VaultName" -Scope Script -Force -ErrorAction SilentlyContinue
}