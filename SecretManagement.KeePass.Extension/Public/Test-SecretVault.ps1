function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName,Mandatory)]
        [string]$VaultName,
        [Parameter(ValueFromPipelineByPropertyName)]
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $vaultName).VaultParameters
    )

    $VaultParameters = $AdditionalParameters
    $ErrorActionPreference = 'Stop'
    Write-Verbose "SecretManagement: Testing Vault ${VaultName}"

    if (-not $VaultName) { throw 'Keepass: You must specify a Vault Name to test' }

    if (-not $VaultParameters.Path) {
        #TODO: Add ThrowUser to throw outside of module scope
        throw "Vault ${VaultName}: You must specify the Path vault parameter as a path to your KeePass Database"
    }
    
    if (-not (Test-Path $VaultParameters.Path)) {
        throw "Vault ${VaultName}: Could not find the keepass database $($VaultParameters.Path). Please verify the file exists or re-register the vault"
    }

    try {
        $VaultMasterKey = (Get-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction Stop).Value
        Write-Verbose "Vault ${VaultName}: Master Key found in Cache, skipping user prompt"
    } catch {
        $GetCredentialParams = @{
            Username = 'VaultMasterKey'
            Message  = "Enter the Vault Master Password for Vault $VaultName"
        }
        $VaultMasterKey = (Get-Credential @GetCredentialParams)
        if (-not $VaultMasterKey.Password) { throw 'You must specify a vault master key to unlock the vault' }
        Set-Variable -Name "Vault_$VaultName" -Scope Script -Value $VaultMasterKey
    }
    
    if (-not (Get-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName)) {
        New-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName -DatabasePath $AdditionalParameters.Path -UseMasterKey
        Write-Verbose "Vault ${VaultName}: A PoshKeePass database configuration was not found but was created."
        return $true
    }
    try {
        Get-KeePassEntry -DatabaseProfileName $VaultName -MasterKey $VaultMasterKey -Title '__SECRETMANAGEMENT__TESTSECRET_SHOULDNOTEXIST' -ErrorAction Stop
    } catch {
        Clear-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction SilentlyContinue
        throw $PSItem
    }

    #If the above doesn't throw an error, we are good
    return $true
}