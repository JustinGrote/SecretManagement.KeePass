function Remove-Secret {
    param (
        [string]$Name,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    $GetKeePassResult = Get-SecretInfo -VaultName $VaultName -Title $Name -AsKPPSObject
    if ($GetKeePassResult.count -gt 1) {throw "Get-SecretInfo returned an ambiguous result for Remove-Secret and it should not do that"}
    if (-not $GetKeePassResult) { throw "No Keepass Entry named $Name found" }
    Remove-KPEntry @KeepassParams -KeePassEntry $GetKeePassResult.KPEntry -ErrorAction stop -Confirm:$false
    return $true
}