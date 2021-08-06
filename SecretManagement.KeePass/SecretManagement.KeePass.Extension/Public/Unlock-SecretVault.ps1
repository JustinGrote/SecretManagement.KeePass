function Unlock-SecretVault {
    param (
        [Parameter(Mandatory)][SecureString]$Password,
        [Parameter(Mandatory)][Alias('Vault')][Alias('Name')][String]$VaultName,
        [Alias('VaultParameters')][hashtable]$AdditionalParameters
    )

    Write-PSFMessage "Unlocking SecretVault $VaultName"
    $vault = Get-SecretVault -Name $VaultName -ErrorAction Stop
    $vaultName = $vault.Name
    if ($vault.ModuleName -ne 'SecretManagement.KeePass') {
        Write-PSFMessage -Level Error "$vaultName was found but is not a Keepass Vault."
        return $false
    }
    Set-Variable -Name "Vault_${vaultName}_MasterPassword" -Scope Script -Value $Password -Force
    #Force a reconnection
    Remove-Variable -Name "Vault_${vaultName}" -Scope Script -Force -ErrorAction SilentlyContinue
    if (-not (Test-SecretVault -Name $vaultName -AdditionalParameters $AdditionalParameters)) {
        Write-PSFMessage -Level Error "${vaultName}: Failed to unlock the vault"
        return $false
    }
    Write-PSFMessage "SecretVault $vault unlocked successfull"
    return $true
}