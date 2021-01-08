function GetKeepassParams ([String]$VaultName, [Hashtable]$AdditionalParameters) {
    $KeepassParams = @{}
    if ($VaultName) { $KeepassParams.DatabaseProfileName = $VaultName }
    $SecureVaultPW = (Get-Variable -Scope Script -Name "Vault_$VaultName" -ErrorAction SilentlyContinue).Value.Password
    if (-not $SecureVaultPW) {throw "${VaultName}: Error retrieving the master key from cache"}
    $KeePassParams.MasterKey = $SecureVaultPW
    return $KeepassParams
}
