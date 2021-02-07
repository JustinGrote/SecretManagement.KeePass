function Register-KeepassSecretVault {
    <#
    .SYNOPSIS
        Registers a Keepass Vault with the Secret Management engine
    .DESCRIPTION
        Enables you to register a keepass vault with the secret management engine, with more discoverable parameters and
        safety checks
    .EXAMPLE
        PS C:\> Register-KeepassSecretVault -Path $HOME/Desktop/MyVault.kdbx
        Explanation of what the example does
    #>

    [CmdletBinding(DefaultParameterSetName = 'UseMasterPassword')]
    param(
        #Path to your kdbx database file
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName)][String]$Path,
        #Name of your secret management vault. Defaults to the base filename
        [String]$Name,
        #Path to your kdbx keyfile path if you use one. Only v1 keyfiles (2.44 and older) are currently supported
        [String]$KeyPath,
        #Prompt for a master password for the vault
        [Switch]$UseMasterPassword,
        #Use your Windows Login account as an authentication factor for the vault
        [Switch]$UseWindowsAccount,
        #Automatically create a keepass database with the specifications you provided
        [Switch]$Create,
        #Report key titles as full paths including folders. Useful if you want to view conflicting Keys
        [Switch]$ShowFullTitle,
        #Don't validate the vault operation upon registration, which is the default. This is useful for pre-staging 
        #vaults or vault configurations in deployments.
        [Switch]$SkipValidate
    )

    $ErrorActionPreference = 'Stop'
    if (-not $SkipValidate) {$Path = Resolve-Path $Path}
    if (-not $Name) { $Name = ([IO.FileInfo]$Path).BaseName }

    if (-not $UseMasterPassword -and -not $UseWindowsAccount -and -not $KeyPath) {
        throw 'No authentication methods specified. You must specify at least one of: UseMasterPassword, UseWindowsAccount, or KeyPath'
    }
    if ($Create) { throw [NotImplementedException]'Work in Progress' }

    
    Register-SecretVault -ModuleName 'SecretManagement.KeePass' -Name $Name -VaultParameters @{
        Path              = $Path
        UseMasterPassword = $UseMasterPassword.IsPresent
        UseWindowsAccount = $UseWindowsAccount.IsPresent
        KeyPath           = $KeyPath
    }

    if (-not (Get-SecretVault -Name $Name)) { throw 'Register-SecretVault did not return an error but the vault is not registered.' }
    if (-not $SkipValidate) {
        if (-not (Test-SecretVault -Name $Name)) {
            Unregister-SecretVault -Name $Name -ErrorAction SilentlyContinue
            throw "$Name is an invalid vault configuration, removing. Consider using -SkipValidate if you wish to pre-load a configuration without testing it"
        }
    }

}