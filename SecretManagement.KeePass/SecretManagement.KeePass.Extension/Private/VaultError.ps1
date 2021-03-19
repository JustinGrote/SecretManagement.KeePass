function VaultError ([String]$Message) {
    <#
    .SYNOPSIS
    Takes a terminating error and first writes it as a non-terminating error to the user to better surface the issue.
    #>

    #FIXME: Use regular errors if https://github.com/PowerShell/SecretManagement/issues/102 is resolved
    $ErrorActionPreference = 'Continue'
    Write-Error "Vault ${VaultName}: $Message"
    $ErrorActionPreference = 'Stop'
}