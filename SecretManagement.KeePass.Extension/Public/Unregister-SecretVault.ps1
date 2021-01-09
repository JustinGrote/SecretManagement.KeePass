function Unregister-SecretVault {
    param(
        [string] $VaultName,
        [hashtable] $AdditionalParameters
    )
    Remove-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName -Confirm:$false
}