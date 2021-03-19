function Unlock-SecretVault {
    param (
        [Parameter(Mandatory)][SecureString]$Password,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][String]$Name
    )

    $vault = Get-SecretVault -Name $Name -ErrorAction Stop
    $vaultName = $vault.Name
    if ($vault.ModuleName -ne 'SecretManagement.KeePass') {throw "$vaultName was found but is not a Keepass Vault."}
    Set-Variable -Name "Vault_${vaultName}_MasterPassword" -Scope Script -Value $Password -Force
}