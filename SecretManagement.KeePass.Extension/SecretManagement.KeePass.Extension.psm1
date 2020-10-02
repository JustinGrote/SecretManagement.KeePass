# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#requires -module PoshKeePass
using namespace Microsoft.PowerShell.SecretManagement

function GetKeepassParams ([String]$VaultName, [Hashtable]$AdditionalParameters) {
    $KeepassParams = @{}
    if ($VaultName) { $KeepassParams.DatabaseProfileName = $VaultName }
    $SecureVaultPW = (Get-Variable -Scope Script -Name "Vault_$VaultName" -ErrorAction SilentlyContinue).Value.Password
    if (-not $SecureVaultPW) {throw "${VaultName}: Error retrieving the master key from cache"}
    $KeePassParams.MasterKey = $SecureVaultPW
    return $KeepassParams
}

function Get-Secret {
    param (
        [string]$Name,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    $ErrorActionPreference = 'Stop'
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    if ($Name) { $KeePassParams.Title = $Name }
    $keepassGetResult = Get-KeePassEntry @KeepassParams | Where-Object ParentGroup -NotMatch 'RecycleBin'
    if ($keepassGetResult.count -gt 1) { throw "Multiple ambiguous entries found for $Name, please remove the duplicate entry" }
    if (-not $keepassGetResult.Username) {
        $keepassGetResult.Password
    } else {
        [PSCredential]::new($KeepassGetResult.UserName, $KeepassGetResult.Password)
    }
}

function Set-Secret {
    param (
        [string]$Name,
        [object]$Secret,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )

    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    #Set default group
    [String]$KeepassParams.KeePassEntryGroupPath = Get-KeePassGroup @KeepassParams | 
        Where-Object fullpath -NotMatch '/' | 
        ForEach-Object fullpath | 
        Select-Object -First 1

    switch ($Secret.GetType()) {
        ([String]) {
            $KeepassParams.Username = $null
            $KeepassParams.KeepassPassword = $Secret
        }
        ([PSCredential]) {
            $KeepassParams.Username = $Secret.Username
            $KeepassParams.KeepassPassword = $Secret.Password
        }
        default {
            throw 'This vault provider only accepts string and PSCredential secrets'
        }
    }

    return [Bool](New-KeePassEntry @KeepassParams -Title $Name -PassThru)
}

function Remove-Secret {
    param (
        [string]$Name,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    $GetKeePassResult = Get-KeePassEntry @KeepassParams -Title $Name
    if (-not $GetKeePassResult) { throw "No Keepass Entry named $Name found" }
    Remove-KeePassEntry @KeepassParams -KeePassEntry $GetKeePassResult -ErrorAction stop -Confirm:$false
    return $true
}

function Get-SecretInfo {
    param(
        [string]$Filter,
        [string]$VaultName = (Get-SecretVault).VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}

    $KeepassParams = GetKeepassParams -VaultName $VaultName -AdditionalParameters $AdditionalParameters
    $KeepassGetResult = Get-KeePassEntry @KeepassParams | Where-Object {$_ -notmatch '^.+?/Recycle Bin/'}

    [Object[]]$secretInfoResult = $KeepassGetResult.where{ 
        $PSItem.Title -like $filter 
    }.foreach{
        [SecretInformation]::new(
            $PSItem.Title, #string name
            [SecretType]::PSCredential, #SecretType type
            $VaultName #string vaultName
        )
    }

    [Object[]]$sortedInfoResult = $secretInfoResult | Sort-Object -Unique Name
    if ($sortedInfoResult.count -lt $secretInfoResult.count) {
        $filteredRecords = (Compare-Object $sortedInfoResult $secretInfoResult | Where-Object SideIndicator -eq '=>').InputObject
        Write-Warning "Vault ${VaultName}: Entries with non-unique titles were detected, the duplicates were filtered out. Duplicate titles are currently not supported with this extension, ensure your entry titles are unique in the database."
        Write-Warning "Vault ${VaultName}: Filtered Non-Unique Titles: $($filteredRecords -join ', ')"
    }
    $sortedInfoResult
}

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