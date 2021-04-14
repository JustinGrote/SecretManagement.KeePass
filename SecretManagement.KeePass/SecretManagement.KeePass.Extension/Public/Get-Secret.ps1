function Get-Secret {
    [CmdletBinding()]
    param (
        [string]$Name,
        [Alias('Vault')][string]$VaultName,
        [Alias('VaultParameters')][hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    trap {
        VaultError $PSItem
        throw $PSItem
    }
    if ($AdditionalParameters.Verbose) {$VerbosePreference = 'continue'}

    if (-not (Test-SecretVault -VaultName $vaultName -AdditionalParameters $AdditionalParameters)) {
        throw 'There appears to be an issue with the vault (Test-SecretVault returned false)'
    }

    if (-not $Name) {throw "You must specify a secret Name"}

    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    if ($Name) { $KeePassParams.Title = $Name }
    $keepassGetResult = Get-SecretInfo -Vault $vaultName -Filter $Name -AsKPPSObject

    if ($keepassGetResult.count -gt 1) { throw "Multiple ambiguous entries found for $Name, please remove the duplicate entry or specify the full path of the secret" }
    $result = if (-not $keepassGetResult.Username) {
        $keepassGetResult.Password
    } else {
        [PSCredential]::new($KeepassGetResult.UserName, $KeepassGetResult.Password)
    }
    return $result
}
