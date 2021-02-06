function Remove-Secret {
    [CmdletBinding()]
    param (
        [string]$Name,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    trap {
        VaultError $PSItem
        throw $PSItem
    }
    if (-not (Test-SecretVault -VaultName $vaultName)) {
        throw 'There appears to be an issue with the vault (Test-SecretVault returned false)'
    }
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    $GetKeePassResult = Get-SecretInfo -VaultName $VaultName -Name $Name -AsKPPSObject
    if ($GetKeePassResult.count -gt 1) {throw "Get-SecretInfo returned an ambiguous result for Remove-Secret and it should not do that"}
    if (-not $GetKeePassResult) { throw "No Keepass Entry named $Name found" }
    Remove-KPEntry @KeepassParams -KeePassEntry $GetKeePassResult.KPEntry -ErrorAction stop -Confirm:$false
    return $true
}