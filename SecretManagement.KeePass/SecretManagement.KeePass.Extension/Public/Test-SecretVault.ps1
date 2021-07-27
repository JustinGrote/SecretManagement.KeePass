function Test-SecretVault {
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipelineByPropertyName,Mandatory)]
        [Alias('Vault')][Alias('Name')][string]$VaultName,

        #This intelligent default is here because if you call test-secretvault from other commands it doesn't populate like it does when called from SecretManagement
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('VaultParameters')][hashtable]$AdditionalParameters = (get-secretvault $VaultName).VaultParameters
    )
    if ($AdditionalParameters.Verbose) {$VerbosePreference = 'continue'}

    Write-PSFMessage -Level Verbose "SecretManagement: Testing Vault ${VaultName}"
    #TODO: Hash vault parameter settings and reset vault state if they change. May be a bug if user changes vault parameters in same session

    #Test if connection already open, no need to do further testing if so
    try {
        $DBConnection = (Get-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction Stop).Value
        if (-not $DBConnection.isOpen) {
            Write-PSFMessage -Level Error 'Connection closed, starting a new connection'
            return $false
        }
        if (Test-DBChanged $DBConnection) {
            $dbConnection.close()
            Write-PSFMessage -Level Error 'Database file on disk has changed, starting a new connection'
            return $false
        }
        Write-PSFMessage -Level Verbose "Vault ${VaultName}: Connection already open, using existing connection"
        return $dbConnection.isOpen
    } catch {
        Write-PSFMessage -Level Verbose "${VaultName}: $PSItem"
    }

    #Basic Sanity Checks
    if (-not $VaultName) {
        Write-PSFMessage -Level Error 'Keepass: You must specify a Vault Name to test'
        return $false
    }

    if (-not $AdditionalParameters.Path) {
        #TODO: Create a default vault if path isn't supplied
        #TODO: Add ThrowUser to throw outside of module scope
        Write-PSFMessage -Level Error 'You must specify the Path vault parameter as a path to your KeePass Database'
        return $false
    }

    if (-not (Test-Path $AdditionalParameters.Path)) {
        Write-PSFMessage -Level Error "Could not find the keepass database $($AdditionalParameters.Path). Please verify the file exists or re-register the vault"
        return $false
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
        Write-PSFMessage -Level Verbose "Cached Master Password Found for $VaultName"
        $ConnectKPDBParams.MasterPassword = $vaultMasterPassword
    }

    try {
        $DBConnection = Connect-KeePassDatabase @ConnectKPDBParams
    } catch {
        Write-PSFMessage -Level Error $PSItem
    }


    if ($DBConnection.IsOpen) {
        Set-Variable -Name "Vault_$VaultName" -Scope Script -Value $DBConnection
        return $DBConnection.IsOpen
    }

    #If we get this far something went wrong
    Write-PSFMessage -Level Error "Unable to open connection to the database"
    return $false

    # if (-not $AdditionalParameters.Keypath -or $AdditionalParameters.UseMasterKey) {

    # }
    # if (-not (Get-KeePassDatabaseConfiguration -DatabaseProfileName $VaultName)) {
    #     New-KeePassDatabaseConfiguration @KeePassDBConfigParams
    #     Write-PSFMessage -Level Verbose "Vault ${VaultName}: A PoshKeePass database configuration was not found but was created."
    #     return $true
    # }
    # try {
    #     Get-KeePassEntry -DatabaseProfileName $VaultName -MasterKey $VaultMasterKey -Title '__SECRETMANAGEMENT__TESTSECRET_SHOULDNOTEXIST' -ErrorAction Stop
    # } catch {
    #     Clear-Variable -Name "Vault_$VaultName" -Scope Script -ErrorAction SilentlyContinue
    #     throw $PSItem
    # }
}