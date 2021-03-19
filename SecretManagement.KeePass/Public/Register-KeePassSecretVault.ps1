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
        [Parameter(ParameterSetName='Create')][Switch]$Create,
        #Specify the master password to use when automatically creating a vault
        [Parameter(ParameterSetName='Create')][SecureString]$MasterPassword,
        #Report key titles as full paths including folders. Useful if you want to view conflicting Keys
        [Switch]$ShowFullTitle,
        #Show Recycle Bin entries
        [Switch]$ShowRecycleBin,
        #Don't validate the vault operation upon registration. This is useful for pre-staging 
        #vaults or vault configurations in deployments.
        [Parameter(ParameterSetName='SkipValidate')][Switch]$SkipValidate
    )

    $ErrorActionPreference = 'Stop'
    if (-not ($SkipValidate -or $Create)) {
        $Path = Resolve-Path $Path
    }
    if (-not $Name) { $Name = ([IO.FileInfo]$Path).BaseName }
    if ($UseWindowsAccount -and -not ($PSEdition -eq 'Desktop' -or $IsWindows)) {
        throw [NotSupportedException]'-UseWindowsAccount parameter is only supported on Windows'
    }
    if (-not $UseMasterPassword -and -not $UseWindowsAccount -and -not $KeyPath) {
        throw [InvalidOperationException]'No authentication methods specified. You must specify at least one of: UseMasterPassword, UseWindowsAccount, or KeyPath'
    }
    if ($Create) {
        $ConnectKPDBParams = @{
            Path = $Path
            KeyPath = $KeyPath
            UseWindowsAccount = $UseWindowsAccount
            Create = $Create
            MasterPassword = $MasterPassword
        }
        $dbConnection = Connect-KeePassDatabase @ConnectKPDBParams
        if (-not $dbConnection) {throw 'Connect-KeePassDatabase was executed but a database connection was not returned. This should not happen.'}
    }

    #BUG: Workaround for https://github.com/PowerShell/SecretManagement/issues/103
    if (Get-Module SecretManagement.KeePass -ErrorAction SilentlyContinue -OutVariable KeePassModule) {
        $ModuleName = $KeePassModule.Path
    } else {
        $ModuleName = 'SecretManagement.KeePass'
    }

    Register-SecretVault -ModuleName $ModuleName -Name $Name -VaultParameters @{
        Path              = $Path
        UseMasterPassword = $UseMasterPassword.IsPresent
        UseWindowsAccount = $UseWindowsAccount.IsPresent
        KeyPath           = $KeyPath
        ShowFullTitle     = $ShowFullTitle.IsPresent
        ShowRecycleBin    = $ShowRecycleBin.IsPresent
    }

    if (-not (Get-SecretVault -Name $Name)) { throw 'Register-SecretVault did not return an error but the vault is not registered.' }
    #Create does the same validation
    if (-not $SkipValidate -and -not $Create) {
        if (-not (Test-SecretVault -VaultName $Name)) {
            Unregister-SecretVault -Name $Name -ErrorAction SilentlyContinue
            throw "$Name is an invalid vault configuration, removing. Consider using -SkipValidate if you wish to pre-load a configuration without testing it"
        }
    }

}