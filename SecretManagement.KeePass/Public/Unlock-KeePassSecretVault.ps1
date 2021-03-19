function Unlock-KeePassSecretVault {
<#
    .SYNOPSIS
    Enables the entry of a master password prior to vault activities for unattended scenarios. 
    If registering a vault for the first time unattended, be sure to use the -SkipValidate parameter of Register-KeepassSecretVault
    .EXAMPLE
    Get-SecretVault 'MyKeepassVault' | Unlock-KeePassSecretVault -Password $MySecureString
    .EXAMPLE
    Unlock-KeePassSecretVault -Name 'MyKeepassVault' -Password $MySecureString
#>
    param (
        [Parameter(Mandatory)][SecureString]$Password,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)][String]$Name
    )
    
    Unlock-SecretVault -Password $Password -Name $Name
}