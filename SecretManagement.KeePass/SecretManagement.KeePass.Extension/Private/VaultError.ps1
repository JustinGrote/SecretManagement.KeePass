function VaultError ([String]$Message) {
    <#
    .SYNOPSIS
    Takes a terminating error and first writes it as a non-terminating error to the user to better surface the issue.
    #>

    #FIXME: Use regular errors if https://github.com/PowerShell/SecretManagement/issues/102 is resolved
    Write-PSFMessage -Level Error "Vault ${VaultName}: $Message"
    throw "Vault ${VaultName}: $Message"
}