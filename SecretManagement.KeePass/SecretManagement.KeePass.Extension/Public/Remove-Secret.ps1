function Remove-Secret {
    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()][string]$Name,
        [Alias('Vault')][string]$VaultName,
        [Alias('VaultParameters')][hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    trap {
        VaultError $PSItem
        throw $PSItem
    }
    if ($AdditionalParameters.Verbose) {$VerbosePreference = 'continue'}
    if (-not (Test-SecretVault -VaultName $vaultName)) {
        throw 'There appears to be an issue with the vault (Test-SecretVault returned false)'
    }
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    $GetKeePassResult = Get-SecretInfo -VaultName $VaultName -Name $Name -AsKPPSObject
    if ($GetKeePassResult.count -gt 1) {
        VaultError "There are multiple entries with the name $Name and Remove-Secret will not proceed for safety."
        return $false
    }
    if (-not $GetKeePassResult) { 
        VaultError "No Keepass Entry named $Name found"
        return $false
    }

    Remove-KPEntry @KeepassParams -KeePassEntry $GetKeePassResult.KPEntry -ErrorAction stop -Confirm:$false

    return $true
}