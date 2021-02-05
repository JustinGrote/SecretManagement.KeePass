function Get-Secret {
    param (
        [string]$Name,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    trap {
        write-VaultError $PSItem
    }

    if (-not $Name) {throw "You must specify a secret Name";throw}
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    if ($Name) { $KeePassParams.Title = $Name }
    $keepassGetResult = Get-SecretInfo -Vault $vaultName -Filter $Name -AsKPPSObject

    if ($keepassGetResult.count -gt 1) { throw "Multiple ambiguous entries found for $Name, please remove the duplicate entry" }
    $result = if (-not $keepassGetResult.Username) {
        $keepassGetResult.Password
    } else {
        [PSCredential]::new($KeepassGetResult.UserName, $KeepassGetResult.Password)
    }
    return $result
}
