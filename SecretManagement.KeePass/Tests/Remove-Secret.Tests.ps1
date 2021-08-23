Describe 'Remove-Secret' {
    BeforeAll {
        #Setup Testing Environment and mock calls to/from parent SecretManagement Module
        #Remove SecretManagement Parent Module if Present
        Get-Module 'SecretManagement.KeePass' | Remove-Module -Force
        Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force

        $ExtensionModule = Import-Module "$PSScriptRoot/../*.psd1" -Force -PassThru
        $Mocks = Join-Path $PSScriptRoot '../Tests/Mocks' | Resolve-Path
        $BaseKeepassDatabaseName = 'Testdb'
        $DoubleEntryExceptionMessage = 'Multiple ambiguous entries found for double entry, please remove the duplicate entry or specify the full path of the secret'
        $ExtModuleName = $ExtensionModule.Name

        Mock -ModuleName $ExtModuleName 'Get-SecretVault' {
            @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path = $vaultPath
                }
            }
        }
    }
    BeforeEach {
        $BaseKeepassDatabaseName = 'Testdb'
        $ModulePath = (Resolve-Path $PSScriptRoot/../..)
        $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
        $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))

        $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
        $KeePassDatabaseSuffix = 'PathOnly'
        $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
        $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
        Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath
        $vaultParams = @{
            VaultName = $VaultName
            VaultParameters = @{
                Path = $vaultPath
            }
        }
        Mock -Verifiable -ModuleName $ExtModuleName 'Get-Credential' -MockWith { $VaultMasterKey }

        #Create one test key to remove
        $TestSecretName = 'PesterTestSecret'
        Set-Secret @vaultParams -Name $TestSecretName -Secret 'supersafe'
        $TestSecretParams = @{
            Vault = $VaultName
            Name  = $TestSecretName
        }
    }

    It 'Fails if name not specified' {
        { Remove-Secret @vaultParams -Name $null } |
            Should -Throw -ErrorId 'ParameterArgumentValidationError*'
    }
    It 'Removes predefined secret' {
        Remove-Secret @vaultParams -Name $TestSecretName
        Get-SecretInfo @TestSecretParams | Should -BeNullOrEmpty
    }
    It 'Fails on removing already removed secret' {
        Remove-Secret @vaultParams -Name $TestSecretName
        {
            Remove-Secret @vaultParams -Name $TestSecretName -ErrorVariable err 2>$null
        } | Should -Throw "Vault * No Keepass Entry named $TestSecretName found"
    }
    It 'Fails on duplicate secrets' {
        {
            Remove-Secret @vaultParams -Name 'Double Entry' -ErrorVariable err 2>$null
        } | Should -Throw 'Vault * There are multiple entries*'
    }
}