#This file normally is intentionally left blank for https://github.com/pester/Pester/issues/1456
function Get-KPSecretManagementConnection {
    <#
    .SYNOPSIS
    Compatibility function for the nested poshkeepass function to fetch the keepass config object
    #>
    param (
        $VaultName
    )
    Get-Module (SecretManagement.Keepass.Extension) {
        (Get-Variable -Scope Script -Name "VAULT_$VaultName").Value
    }
    
}