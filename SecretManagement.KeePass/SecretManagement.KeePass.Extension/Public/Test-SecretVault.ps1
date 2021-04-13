function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName,Mandatory)]
        [Alias('Vault')][Alias('Name')][string]$VaultName,

        #This intelligent default is here because if you call test-secretvault from other commands it doesn't populate like it does when called from SecretManagement
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('VaultParameters')][hashtable]$AdditionalParameters = (get-secretvault $VaultName).VaultParameters
    )
    trap {
        VaultError $PSItem
        return $false
    }
    if ($AdditionalParameters.Verbose) {$VerbosePreference = 'continue'}

    Write-Verbose "SecretManagement: Testing Vault ${VaultName}"
    #TODO: Hash vault parameter settings and reset vault state if they change. May be a bug if user changes vault parameters in same session

    #Test if connection already open, no need to do further testing if so
    try {
        $DBConnection = (Get-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction Stop).Value
        if (-not $DBConnection.isOpen) {throw 'Connection closed, starting a new connection'}
        if (Test-DBChanged $DBConnection) {
            $dbConnection.close()
            throw 'Database file on disk has changed, starting a new connection'
        }
        Write-Verbose "Vault ${VaultName}: Connection already open, using existing connection"
        return $dbConnection.isOpen
    } catch {
        Write-Verbose "${VaultName}: $PSItem"
    }

    #Basic Sanity Checks
    if (-not $VaultName) { throw 'Keepass: You must specify a Vault Name to test' }

    if (-not $AdditionalParameters.Path) {
        #TODO: Create a default vault if path isn't supplied
        #TODO: Add ThrowUser to throw outside of module scope
        throw "You must specify the Path vault parameter as a path to your KeePass Database"
    }
    
    if (-not (Test-Path $AdditionalParameters.Path)) {
        throw "Could not find the keepass database $($AdditionalParameters.Path). Please verify the file exists or re-register the vault"
    }

    #3 Scenarios Supported: Master PW, Keyfile, PW + Keyfile
    $ConnectKPDBParams = @{
        Path = $AdditionalParameters.Path
        KeyPath = $AdditionalParameters.KeyPath
        UseWindowsAccount = $AdditionalParameters.UseWindowsAccount
        UseMasterPassword = $AdditionalParameters.UseMasterPassword
    }

    [SecureString]$vaultMasterPassword = Get-Variable -Name "Vault_${VaultName}_MasterPassword" -ValueOnly -ErrorAction SilentlyContinue
    if ($vaultMasterPassword) {
        Write-Verbose "Cached Master Password Found for $VaultName"
        $ConnectKPDBParams.MasterPassword = $vaultMasterPassword
    }

    $DBConnection = Connect-KeePassDatabase @ConnectKPDBParams

    if ($DBConnection.IsOpen) {
        Set-Variable -Name "Vault_$VaultName" -Scope Script -Value $DBConnection
        return $DBConnection.IsOpen
    }

    #If we get this far something went wrong
    Write-Error "Unable to open connection to the database"
    return $false

    # if (-not $AdditionalParameters.Keypath -or $AdditionalParameters.UseMasterKey) {

    # }
    # if (-not (Get-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName)) {
    #     New-KeePassDatabaseConfiguration @KeePassDBConfigParams
    #     Write-Verbose "Vault ${VaultName}: A PoshKeePass database configuration was not found but was created."
    #     return $true
    # }
    # try {
    #     Get-KeePassEntry -DatabaseProfileName $VaultName -MasterKey $VaultMasterKey -Title '__SECRETMANAGEMENT__TESTSECRET_SHOULDNOTEXIST' -ErrorAction Stop
    # } catch {
    #     Clear-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction SilentlyContinue
    #     throw $PSItem
    # }
}