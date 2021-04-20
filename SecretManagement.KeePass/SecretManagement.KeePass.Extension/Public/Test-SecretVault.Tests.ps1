$CommonTests = Join-Path $PSScriptRoot '../Tests/TestSecretVault-CommonTests.include.ps1'

Describe 'Test-SecretVault' {
    BeforeAll {
        #Setup Testing Environment and mock calls to/from parent SecretManagement Module
        #Remove SecretManagement Parent Module if Present
        Get-Module 'SecretManagement.KeePass' | Remove-Module -Force
        Get-Module 'Microsoft.Powershell.SecretManagement' | Remove-Module -Force
        
        $ExtensionModule = Import-Module "$PSScriptRoot/../*.psd1" -Force -PassThru
        $Mocks = Join-Path $PSScriptRoot '../Tests/Mocks' | Resolve-Path

        $BaseKeepassDatabaseName = 'Testdb'
        $ExtModuleName = $ExtensionModule.Name
        $DoubleEntryExceptionMessage = 'Multiple ambiguous entries found for double entry, please remove the duplicate entry or specify the full path of the secret'
        $KeePassCompositeError = '*The composite key is invalid!*Make sure the composite key is correct and try again.*'
        $KeePassMasterKeyError = '*The master key is invalid!*'

        Mock -ModuleName $ExtModuleName 'Get-SecretVault' {
            @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path = $vaultPath
                }
            }
        }
    }

    Context 'Function Parameter Validation' {
        BeforeAll {
            $ExtModuleName = $ExtensionModule.Name
            $FunctionName = 'Test-SecretVault'
            $ParameterCount = 2
        }
        It 'has a parameter "<Name>"' -TestCases @(
            @{Name = 'VaultName' }
            @{Name = 'AdditionalParameters' }
        ) {
            $AllParameterNames = (Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters.Keys
            $Name | Should -BeIn $AllParameterNames
        }
        It 'has the mandatory value of parameter "<Name>" set to "<Mandatory>"' -TestCases @(
            @{Name = 'VaultName'; Mandatory = $True }
            @{Name = 'AdditionalParameters'; Mandatory = $False }
        ) {
            ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].Attributes | Where-Object { $_.GetType().FullName -eq 'System.Management.Automation.ParameterAttribute' }).Mandatory | Should -Be $Mandatory
        }
        It 'has parameter <Name> of type <Type>' -TestCases @(
            @{Name = 'VaultName'; Type = 'string' }
            @{Name = 'AdditionalParameters'; Type = 'hashtable' }
        ) {
            ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].ParameterType) | Should -BeExactly $Type
        }
        It 'has one parameter set' {
            (Get-Command -Module $ExtModuleName -Name $FunctionName).ParameterSets.Count | Should -BeExactly 1
        }
    }

    Context 'Validating with correct MasterPassword' {
        BeforeAll {
            $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))
            $KeePassDatabaseSuffix = 'PathOnly'

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path = $vaultPath
                }
            }

            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
        }

        . $CommonTests -Credential
    }

    Context 'Validating with incorrect MasterPassword' {
        BeforeAll {
            $MasterKey = 'ThisIsAnInvalidMasterKey'
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

            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
        }
        . $CommonTests -Invalid -Credential
    }

    Context 'Validating with Path and correct UseMasterPassword' {
        BeforeAll {
            $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseSuffix = 'PathAndUseMasterPassword'
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path = $vaultPath
                    UseMasterPassword = $true
                }
            }

            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
        }
        . $CommonTests -Credential
    }
    Context 'Validating with path and incorrect MasterPassword' {
        BeforeAll {
            $MasterKey = 'ThisIsAnInvalidMasterKey'
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
                    UseMasterPassword = $true
                }
            }

            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
        }
        . $CommonTests -Invalid -Credential 
    }

    Context 'Validating with correct Keyfile' {
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
                    Path = $vaultPath
                    KeyPath = $KeyPath
                }
            }
        }
        . $CommonTests -KeyFile
    }

    Context 'Validating with incorrect Keyfile' {
        BeforeAll {
            $KeyFileName = 'TestdbKeyFileAndMasterPassword.key'

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
                    Path = $vaultPath
                    KeyPath = $KeyPath
                }
            }
        }
        . $CommonTests -Invalid -KeyFile
    }

    Context 'Validating with correct Keyfile v2' {
        BeforeAll {
            $KeyFileName = 'TestdbKeyFileV2.keyx'
            $KeePassDatabaseSuffix = 'KeyFileV2'

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath
            Copy-Item -Path (Join-Path $Mocks $KeyFileName) -Destination $KeyPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path = $vaultPath
                    KeyPath = $KeyPath
                }
            }
        }
        . $CommonTests -KeyFile
    }

    Context 'Validating with correct Keyfile and correct master password' {
        BeforeAll {
            $KeyFileName = 'TestdbKeyFileAndMasterPassword.key'
            $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))
            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
            $KeePassDatabaseSuffix = 'KeyFileAndMasterPassword'

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath
            Copy-Item -Path (Join-Path $Mocks $KeyFileName) -Destination $KeyPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path              = $VaultPath
                    UseMasterPassword = $true
                    KeyPath           = $KeyPath
                }
            }
        }
        . $CommonTests -Credential
    }

    Context 'Validating with correct Keyfile and incorrect master password' {
        BeforeAll {
            $KeyFileName = 'TestdbKeyFileAndMasterPassword.key'
            $MasterKey = 'NotTheCorrectMasterKey'
            $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))
            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
            $KeePassDatabaseSuffix = 'KeyFileAndMasterPassword'

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath
            Copy-Item -Path (Join-Path $Mocks $KeyFileName) -Destination $KeyPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path              = $VaultPath
                    UseMasterPassword = $true
                    KeyPath           = $KeyPath
                }
            }
        }
        . $CommonTests -Credential -Invalid
    }

    
    Context 'Validating with incorrect Keyfile and correct master password' {
        BeforeAll {
            $KeyFileName = 'TestdbKeyFile.key'
            $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))
            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
            $KeePassDatabaseSuffix = 'KeyFileAndMasterPassword'

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath
            Copy-Item -Path (Join-Path $Mocks $KeyFileName) -Destination $KeyPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path              = $VaultPath
                    UseMasterPassword = $true
                    KeyPath           = $KeyPath
                }
            }
        }
        . $CommonTests -Credential -Invalid
    }

    Context 'Validating with incorrect Keyfile and incorrect master password' {
        BeforeAll {
            $KeyFileName = 'TestdbKeyFile.key'
            $MasterKey = 'You can not enter with this password!'
            $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))
            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
            $KeePassDatabaseSuffix = 'KeyFileAndMasterPassword'

            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
            $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
            Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath
            Copy-Item -Path (Join-Path $Mocks $KeyFileName) -Destination $KeyPath

            $vaultParams = @{
                VaultName = $VaultName
                VaultParameters = @{
                    Path              = $VaultPath
                    UseMasterPassword = $true
                    KeyPath           = $KeyPath
                }
            }
        }
        . $CommonTests -Credential -Invalid
    }
}