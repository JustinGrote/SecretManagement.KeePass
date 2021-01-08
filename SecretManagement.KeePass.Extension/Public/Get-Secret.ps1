function Get-Secret {
    param (
        [string]$Name,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    $ErrorActionPreference = 'Stop'
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    if ($Name) { $KeePassParams.Title = $Name }
    $keepassGetResult = Get-KeePassEntry @KeepassParams | Where-Object ParentGroup -NotMatch 'RecycleBin'
    if ($keepassGetResult.count -gt 1) { throw "Multiple ambiguous entries found for $Name, please remove the duplicate entry" }
    if (-not $keepassGetResult.Username) {
        $keepassGetResult.Password
    } else {
        [PSCredential]::new($KeepassGetResult.UserName, $KeepassGetResult.Password)
    }
}
