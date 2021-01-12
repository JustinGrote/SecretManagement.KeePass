function GetKeepassParams ([String]$VaultName, [Hashtable]$AdditionalParameters) {
    $KeepassParams = @{}
    if ($VaultName) { 
        $KeepassParams.KeePassConnection = (Get-Variable -Scope Script -Name "Vault_$VaultName").Value 
    }
    return $KeepassParams
}