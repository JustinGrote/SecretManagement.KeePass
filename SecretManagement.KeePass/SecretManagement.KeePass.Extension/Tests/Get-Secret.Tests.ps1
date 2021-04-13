Describe 'Get-Secret' {
    BeforeAll {
        #Setup Testing Environment and mock calls to/from parent SecretManagement Module
        $ExtensionModule = Import-Module "$PSScriptRoot/../*.psd1" -Force -PassThru
        $Mocks = Join-Path $PSScriptRoot 'Mocks' | Resolve-Path
        $BaseKeepassDatabaseName = 'Testdb'
        $DoubleEntryExceptionMessage = 'Multiple ambiguous entries found for double entry, please remove the duplicate entry or specify the full path of the secret'
        $ExtModuleName = $ExtensionModule.Name

        Mock -CommandName 'Get-SecretVault' {
            @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path = $vaultPath
                }
            }
        }
        $Test_SecretVault = Get-Command -ModuleName $ExtModuleName -Name 'Test-SecretVault'
        $Get_Secret = Get-Command -ModuleName $ExtModuleName -Name 'Get-Secret'
    }
    AfterAll {
        Remove-Module $ExtensionModule -Force
    }

    Context 'Function Parameter Validation' {
        BeforeAll {
            $SCRIPT:FunctionName = 'Get-Secret'
        }

        It 'has a parameter "<Name>"' {
            $allParameterNames = (Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters.Keys
            $Name | Should -BeIn $AllParameterNames
        } -TestCases @(
            @{Name = 'Name' }
            @{Name = 'VaultName' }
            @{Name = 'AdditionalParameters' }
        )

        It 'has the mandatory value of parameter "<Name>" set to "<Mandatory>"' {
            $testAttribute = ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].Attributes | 
                Where-Object { $PSItem -is [System.Management.Automation.ParameterAttribute] }).Mandatory
            $testAttribute | Should -Be $Mandatory
        } -TestCases @(
            @{Name = 'Name'; Mandatory = $False }
            @{Name = 'VaultName'; Mandatory = $False }
            @{Name = 'AdditionalParameters'; Mandatory = $False }
        ) 

        It 'has parameter <Name> of type <Type>' {
            ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].ParameterType) | 
                Should -BeExactly $Type
        } -TestCases @(
            @{Name = 'Name'; Type = 'string' }
            @{Name = 'VaultName'; Type = 'string' }
            @{Name = 'AdditionalParameters'; Type = 'hashtable' }
        )

        It 'has one parameter set' {
            (Get-Command -Module $ExtModuleName -Name $FunctionName).ParameterSets.Count | Should -BeExactly 1
        }
    }

    Context 'Get Secret information from MasterPassword protected KeePass' {
        BeforeAll {
            $masterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $vaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $masterKey))

            $vaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $keePassDatabaseSuffix = 'PathOnly'
            $keePassDatabaseFileName = "$($baseKeepassDatabaseName)$($keePassDatabaseSuffix).kdbx"
            $vaultPath = Join-Path -Path $TestDrive -ChildPath $keePassDatabaseFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path = $vaultPath
                }
            }
            Mock -Verifiable -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
        }

        It 'should return a <PSType> for entry <SecretName>' {
            $Secret = & $Get_Secret @vaultParams -Name $SecretName 
            $Secret | Should -BeOfType $PSType
        } -TestCases @(
            @{SecretName = 'New Entry 1';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'New Entry 2';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'No UserName';PSType = 'System.Security.SecureString' }
        )

        It 'should return <username> for <SecretName>' {
            $getSecretResult = . $Get_Secret @vaultParams -Name $SecretName
            $getSecretResult.UserName | Should -BeExactly $UserName
        } -TestCases @(
            @{SecretName = 'New Entry 1';UserName = 'myusername 1' }
            @{SecretName = 'New Entry 2';UserName = 'Some Administrator account' }
        )

        It 'should throw when multiple secrets are returned' -Tag 'CurrentTest' {
            { . $Get_Secret @vaultParams -Name 'double entry' 2>$null } | 
                Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
        }
        It 'should return nothing when entry is not found in the KeePass DB' {
            . $Get_Secret @vaultParams -Name 'not present' | Should -BeNullOrEmpty
        }
    }

    Context 'Get Secret information from KeyFile protected KeePass' {
        BeforeAll {
            $KeyFileName = 'TestdbKeyFile.key'
            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseSuffix = 'KeyFile'
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath
            Copy-Item -Path (Join-Path $Mocks $KeyFileName) -Destination $KeyPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path    = $VaultPath
                    KeyPath = $KeyPath
                }
            }
        }

        It 'should return a <PSType> for entry <SecretName>' {
            $Secret = . $Get_Secret @vaultParams -Name $SecretName
            $Secret | Should -Not -BeNullOrEmpty
            $Secret | Should -BeOfType $PSType
        } -TestCases @(
            @{SecretName = 'New Entry 1';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'New Entry 2';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'No UserName';PSType = 'System.Security.SecureString' }
        )

        It 'should return <username> for <SecretName>' {
            $secretResult = . $Get_Secret @vaultParams -Name $SecretName
            $secretResult.UserName | Should -BeExactly $UserName
        } -TestCases @( 
            @{SecretName = 'New Entry 1';UserName = 'myusername 1' }
            @{SecretName = 'New Entry 2';UserName = 'Some Administrator account' }
        )

        It 'should throw when multiple secrets are returned' {
            { . $Get_Secret @vaultParams -Name 'double entry' 2>$null } | 
                Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
        }
        It 'should return nothing when entry is not found in the KeePass DB' {
            . $Get_Secret @vaultParams -Name 'not present' | 
                Should -BeNullOrEmpty
        }
    }

    Context 'Get Secret information from MasterPassword and KeyFile protected KeePass' {
        BeforeAll {
            $KeyFileName = 'TestdbKeyFileAndMasterPassword.key'
            $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseSuffix = 'KeyFileAndMasterPassword'
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath
            Copy-Item -Path (Join-Path $Mocks $KeyFileName) -Destination $KeyPath

            $vaultParams = @{
                VaultName       = $VaultName
                VaultParameters = @{
                    Path              = $VaultPath
                    UseMasterPassword = $true
                    KeyPath           = $KeyPath
                }
            }
            Mock -Verifiable -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
        }

        It 'should return a <PSType> for entry <SecretName>' {
            $Secret = & $Get_Secret @vaultParams -Name $SecretName 
            $Secret | Should -BeOfType $PSType
        } -TestCases @(
            @{SecretName = 'New Entry 1';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'New Entry 2';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'No UserName';PSType = 'System.Security.SecureString' }
        )

        It 'should return <username> for <SecretName>' {
            $getSecretResult = . $Get_Secret @vaultParams -Name $SecretName
            $getSecretResult.UserName | Should -BeExactly $UserName
        } -TestCases @(
            @{SecretName = 'New Entry 1';UserName = 'myusername 1' }
            @{SecretName = 'New Entry 2';UserName = 'Some Administrator account' }
        )

        It 'should throw when multiple secrets are returned' -Tag 'CurrentTest' {
            { . $Get_Secret @vaultParams -Name 'double entry' 2>$null } | 
                Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
        }
        
        It 'should return nothing when entry is not found in the KeePass DB' {
            . $Get_Secret @vaultParams -Name 'not present' | Should -BeNullOrEmpty
        }
    }
}