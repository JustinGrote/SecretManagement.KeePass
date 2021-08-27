function Get-Secret {
    [CmdletBinding()]
    param (
        [string]$Name,
        [Alias('Vault')][string]$VaultName,
        [Alias('VaultParameters')][hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    if ($AdditionalParameters.Verbose) { $VerbosePreference = 'continue' }

    Write-PSFMessage "Searching Entry with Name=$Name"
    if (-not (Test-SecretVault -VaultName $vaultName -AdditionalParameters $AdditionalParameters)) {
        Write-PSFMessage -Level Error 'There appears to be an issue with the vault (Test-SecretVault returned false)' -Target "$Name"
        throw 'There appears to be an issue with the vault (Test-SecretVault returned false)'
    }

    if (-not $Name) { 
        Write-PSFMessage -Level Error 'You must specify a secret Name' -Target "$Name"
        throw 'You must specify a secret Name'
    }

    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    if ($Name) { $KeePassParams.Title = $Name }
    $keepassGetResult = Get-SecretInfo -Vault $vaultName -Filter $Name -AsKPPSObject

    if ($null -eq $keepassGetResult) {
        Write-PSFMessage "No Keepass Entry found" -Target $Name
        return 
    }
    if ($keepassGetResult.count -gt 1) {
        Write-PSFMessage -Level Error "Multiple ambiguous entries found for $Name, please remove the duplicate entry or specify the full path of the secret" -Target "$Name"
        throw "Multiple ambiguous entries found for $Name, please remove the duplicate entry or specify the full path of the secret"
    }
    $result = if (-not $keepassGetResult.Username) {
        $keepassGetResult.Password
    }
    else {
        [PSCredential]::new($KeepassGetResult.UserName, $KeepassGetResult.Password)
    }
    return $result
}
