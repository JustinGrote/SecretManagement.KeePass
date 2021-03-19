function Unlock-SecretVault {
    param (
        [Parameter(Mandatory)][SecureString]$Password,
        [Parameter(Mandatory)][String]$Name
    )

    $vault = Get-SecretVault -Name $Name -ErrorAction Stop
    $vaultName = $vault.Name
    if ($vault.ModuleName -ne 'SecretManagement.KeePass') {throw "$vaultName was found but is not a Keepass Vault."}
    Set-Variable -Name "Vault_${vaultName}_MasterPassword" -Scope Script -Value $Password -Force
    #Force a reconnection
    Remove-Variable -Name "Vault_${vaultName}" -Scope Script -Force -ErrorAction SilentlyContinue
    if (-not (Microsoft.Powershell.SecretManagement\Test-SecretVault -Name $vaultName)) {throw "${vaultName}: Failed to unlock the vault"}
}