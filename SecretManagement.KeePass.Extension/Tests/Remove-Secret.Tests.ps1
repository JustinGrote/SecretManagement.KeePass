
Describe 'Remove-Secret' {
    BeforeAll {
        Import-Module -Name 'Microsoft.PowerShell.SecretManagement'
        Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -Force
        $SCRIPT:Mocks = Join-Path $PSScriptRoot 'Mocks'
    }
    BeforeEach {
        $BaseKeepassDatabaseName = 'Testdb'
        $ModulePath = (Resolve-Path $PSScriptRoot/../..)
        $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
        $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))

        $SCRIPT:VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
        $KeePassDatabaseSuffix = 'PathOnly'
        $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
        $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
        Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath

        $RegisterSecretVaultPathOnlyParams = @{
            Name            = $VaultName
            ModuleName      = $ModulePath
            PassThru        = $true
            VaultParameters = @{
                Path = $VaultPath
            }
        }
        Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null
        Mock -Verifiable -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
        if (-not (Test-SecretVault -Name $VaultName)) { throw "Test Setup: Failed to initialize vault $VaultPath" }

        #Create one test key to remove
        $SCRIPT:TestSecretName = 'PesterTestSecret'
        Set-Secret -Name $TestSecretName -Vault $VaultName -Secret 'supersafe'
        $SCRIPT:TestSecretParams = @{
            Vault = $VaultName
            Name  = $TestSecretName
        }
    }

    AfterEach {
        try {
            Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
        } catch [system.Exception] { }
    }
    
    It 'Fails if name not specified' {
        {
            InModuleScope 'SecretManagement.KeePass.Extension' {
                Remove-Secret -Name $null -Vault $VaultName
            }
        } | Should -Throw -ErrorId 'ParameterArgumentValidationError*'
    }
    It 'Removes predefined secret' {
        InModuleScope 'SecretManagement.KeePass.Extension' {
            Remove-Secret @TestSecretParams
        }
        Get-SecretInfo @TestSecretParams | Should -BeNullOrEmpty
    }
    It 'Fails on removing already removed secret' {
        InModuleScope 'SecretManagement.KeePass.Extension' {
            Remove-Secret @TestSecretParams
            Invoke-Command -ErrorVariable err { Remove-Secret @TestSecretParams } 2>$null | 
                Should -Be $false
            $err[-1] | Should -Match "No Keepass Entry named $TestSecretName found"
        }
    }
    It 'Fails on duplicate secrets' {
        InModuleScope 'SecretManagement.KeePass.Extension' {
            Invoke-Command -ErrorVariable err { Remove-Secret -Name 'Double Entry' -VaultName $VaultName } 2>$null | 
                Should -Be $false
            $err[-1] | Should -Match 'There are multiple entries*'
        }
    }
}