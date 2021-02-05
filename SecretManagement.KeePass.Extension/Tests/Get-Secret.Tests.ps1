BeforeAll {
    Import-Module -Name 'Microsoft.PowerShell.SecretManagement'
    Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -Force
    $SCRIPT:Mocks = Join-Path $PSScriptRoot 'Mocks'
}

Describe 'Get-Secret' {
    BeforeAll {
        $ModuleName = 'SecretManagement.KeePass'
        $ModulePath = (Get-Module $ModuleName).Path
        $BaseKeepassDatabaseName = 'Testdb'
        $DoubleEntryExceptionMessage = 'Multiple ambiguous entries found for double entry, please remove the duplicate entry'
    }
    AfterAll {
        try {
            Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
        } catch [system.Exception] { }
    }
    Context 'Function Parameter Validation' {
        BeforeAll {
            $SCRIPT:ExtModuleName = 'SecretManagement.KeePass.Extension'
            $SCRIPT:FunctionName = 'Get-Secret'
        }

        It 'has a parameter "<Name>"' {
            #TODO: Cut down on boilerplate after https://github.com/pester/Pester/issues/1603 is resolved
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{Name = $Name } {
                param($Name)
                $AllParameterNames = (Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters.Keys
                $Name | Should -BeIn $AllParameterNames
            }
        } -TestCases @(
            @{Name = 'Name' }
            @{Name = 'VaultName' }
            @{Name = 'AdditionalParameters' }
        )

        It 'has the mandatory value of parameter "<Name>" set to "<Mandatory>"' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{Name = $Name; Mandatory = $Mandatory } {
                param($Name,$Mandatory)
                $testAttribute = ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].Attributes | 
                    Where-Object { $PSItem -is [System.Management.Automation.ParameterAttribute] }).Mandatory
                $testAttribute | Should -Be $Mandatory
            }
        } -TestCases @(
            @{Name = 'Name'; Mandatory = $False }
            @{Name = 'VaultName'; Mandatory = $False }
            @{Name = 'AdditionalParameters'; Mandatory = $False }
        ) 

        It 'has parameter <Name> of type <Type>' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{Name = $Name; Type = $Type } {
                param($Name,$Type)
                ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].ParameterType) | Should -BeExactly $Type
            }
        } -TestCases @(
            @{Name = 'Name'; Type = 'string' }
            @{Name = 'VaultName'; Type = 'string' }
            @{Name = 'AdditionalParameters'; Type = 'hashtable' }
        )

        It 'has one parameter set' {
            InModuleScope 'SecretManagement.KeePass.Extension' {
                (Get-Command -Module $ExtModuleName -Name $FunctionName).ParameterSets.Count | Should -BeExactly 1
            }
        }
    }
    Context 'Get Secret information from MasterPassword protected KeePass' {
        BeforeAll {
            $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
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
            Test-SecretVault -Name $VaultName | Out-Null
        }
        AfterAll {
            try {
                Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
            } catch [system.Exception] { }
        }
        It 'should return a <PSType> for entry <SecretName>' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{SecretName = $SecretName; PSType = $PSType; VaultName = $VaultName } {
                param($SecretName,$PSType,$VaultName)
                $Secret = Get-Secret -Name $SecretName -VaultName $VaultName
                $Secret.Gettype().Fullname | Should -BeExactly $PSType
            }
        } -TestCases @(
            @{SecretName = 'New Entry 1';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'New Entry 2';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'No UserName';PSType = 'System.Security.SecureString' }
        )
 
        It 'should return <username> for <SecretName>' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{SecretName = $SecretName; UserName = $UserName; VaultName = $VaultName } {
                param($SecretName,$UserName,$VaultName)
                (Get-Secret -Name $SecretName -VaultName $VaultName).UserName | Should -BeExactly $UserName
            }
        } -TestCases @( 
            @{SecretName = 'New Entry 1';UserName = 'myusername 1' }
            @{SecretName = 'New Entry 2';UserName = 'Some Administrator account' }
        )

        It 'should throw when multiple secrets are returned' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{VaultName = $VaultName } {
                param($VaultName)
                { Get-Secret -Name 'double entry' -VaultName $VaultName } | 
                    Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
            }
        }
        It 'should return nothing when entry is not found in the KeePass DB' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{VaultName = $VaultName } {
                param($VaultName)
                ( Get-Secret -Name 'not present' -VaultName $VaultName) | Should -BeNullOrEmpty
            }
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

            $RegisterSecretVaultPathOnlyParams = @{
                Name            = $VaultName
                ModuleName      = $ModulePath
                PassThru        = $true
                VaultParameters = @{
                    Path    = $VaultPath
                    KeyPath = $KeyPath
                }
            }
            Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null

            Mock -Verifiable -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
            Test-SecretVault -Name $VaultName | Out-Null
        }
        AfterAll {
            try {
                Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
            } catch [system.Exception] { }
        }
        It 'should return a <PSType> for entry <SecretName>' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{ SecretName = $SecretName;PSType = $PSType;VaultName = $VaultName } {
                param($SecretName, $PSType, $VaultName)
                $Secret = Get-Secret -Name $SecretName -VaultName $VaultName
                $Secret | Should -Not -BeNullOrEmpty
                $Secret | Should -BeOfType $PSType
            }
        } -TestCases @(
            @{SecretName = 'New Entry 1';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'New Entry 2';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'No UserName';PSType = 'System.Security.SecureString' }
        )

        It 'should return <username> for <SecretName>' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{ SecretName = $SecretName;UserName = $UserName;VaultName = $VaultName } {
                param($SecretName,$UserName,$VaultName)
                (Get-Secret -Name $SecretName -VaultName $VaultName).UserName | Should -BeExactly $UserName
            }
        } -TestCases @( 
            @{SecretName = 'New Entry 1';UserName = 'myusername 1' }
            @{SecretName = 'New Entry 2';UserName = 'Some Administrator account' }
        )

        It 'should throw when multiple secrets are returned' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{ VaultName = $VaultName} {
                param($VaultName)
                { Get-Secret -Name 'double entry' -VaultName $VaultName } | 
                    Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
            }
        }
        It 'should return nothing when entry is not found in the KeePass DB' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{ VaultName = $VaultName} {
                param($VaultName)
                Get-Secret -Name 'not present' -VaultName $VaultName | Should -BeNullOrEmpty
            }
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

            $RegisterSecretVaultPathOnlyParams = @{
                Name            = $VaultName
                ModuleName      = $ModulePath
                PassThru        = $true
                VaultParameters = @{
                    Path              = $VaultPath
                    UseMasterPassword = $true
                    KeyPath           = $KeyPath
                }
            }
            Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null

            Mock -Verifiable -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
            Test-SecretVault -Name $VaultName | Out-Null
        }
        AfterAll {
            try {
                Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
            } catch [system.Exception] { }
        }
        It 'should return a <PSType> for entry <SecretName>' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{ SecretName = $SecretName;PSType = $PSType;VaultName = $VaultName } {
                param($SecretName, $PSType, $VaultName)
                $Secret = Get-Secret -Name $SecretName -VaultName $VaultName
                $Secret.Gettype().Fullname | Should -BeExactly $PSType
            }
        } -TestCases @(
            @{SecretName = 'New Entry 1';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'New Entry 2';PSType = 'System.Management.Automation.PSCredential' }
            @{SecretName = 'No UserName';PSType = 'System.Security.SecureString' }
        )

        It 'should return <username> for <SecretName>' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{ SecretName = $SecretName;UserName = $UserName;VaultName = $VaultName } {
                param($SecretName,$UserName,$VaultName)
                (Get-Secret -Name $SecretName -VaultName $VaultName).UserName | Should -BeExactly $UserName
            }
        } -TestCases @(
            @{SecretName = 'New Entry 1';UserName = 'myusername 1' }
            @{SecretName = 'New Entry 2';UserName = 'Some Administrator account' }
        )

        It 'should throw when multiple secrets are returned' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{ VaultName = $VaultName} {
                param($VaultName)
                { Get-Secret -Name 'double entry' -VaultName $VaultName } | 
                    Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
            }
        }
        It 'should return nothing when entry is not found in the KeePass DB' {
            InModuleScope 'SecretManagement.KeePass.Extension' -Parameters @{ VaultName = $VaultName} {
                param($VaultName)
                Get-Secret -Name 'not present' -VaultName $VaultName | Should -BeNullOrEmpty
            }
        }
    }
}