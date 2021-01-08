function Remove-Secret {
    param (
        [string]$Name,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    $GetKeePassResult = Get-KeePassEntry @KeepassParams -Title $Name
    if (-not $GetKeePassResult) { throw "No Keepass Entry named $Name found" }
    Remove-KeePassEntry @KeepassParams -KeePassEntry $GetKeePassResult -ErrorAction stop -Confirm:$false
    return $true
}