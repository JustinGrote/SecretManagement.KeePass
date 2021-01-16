Get-Module *Secret* | Remove-Module -ErrorAction SilentlyContinue -Force
Import-Module -Name 'Microsoft.PowerShell.SecretManagement'
Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -Force

InModuleScope -ModuleName 'SecretManagement.KeePass.Extension' {
    Describe "Test-SecretVault" {
        BeforeAll {
            $ModuleName = 'SecretManagement.KeePass'
            $ModulePath = (Get-Module $ModuleName).Path
            $BaseKeepassDatabaseName = "Testdb"
        }
        AfterAll {
            try {
                Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
            } catch [system.Exception] { }
        }
        Context "Function Parameter Validation" {
            BeforeAll {
                $ExtModuleName = 'SecretManagement.KeePass.Extension'
                $FunctionName = 'Test-SecretVault'
                $ParameterCount = 2
            }
            It 'has a parameter "<Name>"' -TestCases @(
                @{Name='VaultName'}
                @{Name='AdditionalParameters'}
                ) {
                $AllParameterNames= (Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters.Keys
                $Name | Should -BeIn $AllParameterNames
            }
            It 'has the mandatory value of parameter "<Name>" set to "<Mandatory>"' -TestCases @(
                @{Name='VaultName';Mandatory=$True}
                @{Name='AdditionalParameters';Mandatory=$False}
                ) {
                    ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].Attributes | Where-Object { $_.GetType().FullName -eq 'System.Management.Automation.ParameterAttribute'}).Mandatory | Should -Be $Mandatory
            }
            It 'has parameter <Name> of type <Type>' -TestCases @(
                @{Name='VaultName';Type='string'}
                @{Name='AdditionalParameters';Type='hashtable'}
            ) {
                ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].ParameterType) | Should -BeExactly $Type
            }
            It "has one parameter set" {
                (Get-Command -Module $ExtModuleName -Name $FunctionName).ParameterSets.Count | Should -BeExactly 1
            }
        }
        Context "Validating Path Parameter Only" {
            BeforeAll {
                $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
                $VaultMasterKey = [PSCredential]::new('vaultkey',(ConvertTo-SecureString -AsPlainText -Force $MasterKey))

                $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
                $KeePassDatabaseSuffix = 'PathOnly'
                $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
                $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
                Copy-Item -Path "$($PSScriptRoot)/$($KeePassDatabaseFileName)" -Destination $VaultPath

                $RegisterSecretVaultPathOnlyParams = @{
                    Name            = $VaultName
                    ModuleName      = $ModulePath
                    PassThru        = $true
                    VaultParameters = @{
                        Path = $VaultPath
                    }
                }
                Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null

                Mock -Verifiable -CommandName 'Get-Credential' -MockWith {$VaultMasterKey}
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
            It "should not have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Throw
            }
            It "should request a credential on the first pass" {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1 -Scope Context
            }
            It 'Should not request a credential on the second pass' {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1 -Scope Context
            }
            It "should have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Not -Throw
            }
        }
        Context "Validating Path and UseMasterPassword Parameters" {
            BeforeAll {
                $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
                $VaultMasterKey = [PSCredential]::new('vaultkey',(ConvertTo-SecureString -AsPlainText -Force $MasterKey))

                $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
                $KeePassDatabaseSuffix = 'PathAndUseMasterPassword'
                $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
                $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
                Copy-Item -Path "$($PSScriptRoot)/$($KeePassDatabaseFileName)" -Destination $VaultPath

                $RegisterSecretVaultPathOnlyParams = @{
                    Name            = $VaultName
                    ModuleName      = $ModulePath
                    PassThru        = $true
                    VaultParameters = @{
                        Path = $VaultPath
                        UseMasterPassword = $true
                    }
                }
                Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null

                Mock -Verifiable -CommandName 'Get-Credential' -MockWith {$VaultMasterKey}
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
            It "should not have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Throw
            }
            It "should request a credential on the first pass" {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1 -Scope Context
            }
            It 'Should not request a credential on the second pass' {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1 -Scope Context
            }
            It "should have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Not -Throw
            }
        }
        Context "Validating Keyfile" {
            BeforeAll {
                $KeyFileName = 'TestdbKeyFile.key'

                $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
                $KeePassDatabaseSuffix = 'KeyFile'
                $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
                $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
                $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
                Copy-Item -Path "$($PSScriptRoot)/$($KeePassDatabaseFileName)" -Destination $VaultPath
                Copy-Item -Path "$($PSScriptRoot)/$($KeyFileName)" -Destination $KeyPath

                $RegisterSecretVaultPathOnlyParams = @{
                    Name            = $VaultName
                    ModuleName      = $ModulePath
                    PassThru        = $true
                    VaultParameters = @{
                        Path = $VaultPath
                        KeyPath = $KeyPath
                    }
                }
                Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null

                Mock -Verifiable -CommandName 'Get-Credential' -MockWith {$VaultMasterKey}
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
                It "should not have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Throw
            }
            It 'Should not request a credential' {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 0 -Scope Context
            }
            It "should have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Not -Throw
            }
        }
        Context "Validating Keyfile with master password" {
            BeforeAll {
                $KeyFileName = 'TestdbKeyFileAndMasterPassword.key'
                $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
                $VaultMasterKey = [PSCredential]::new('vaultkey',(ConvertTo-SecureString -AsPlainText -Force $MasterKey))

                $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
                $KeePassDatabaseSuffix = 'KeyFile'
                $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
                $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
                $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
                Copy-Item -Path "$($PSScriptRoot)/$($KeePassDatabaseFileName)" -Destination $VaultPath
                Copy-Item -Path "$($PSScriptRoot)/$($KeyFileName)" -Destination $KeyPath

                $RegisterSecretVaultPathOnlyParams = @{
                    Name            = $VaultName
                    ModuleName      = $ModulePath
                    PassThru        = $true
                    VaultParameters = @{
                        Path = $VaultPath
                        UseMasterPassword = $true
                        KeyPath = $KeyPath
                    }
                }
                Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null

                Mock -Verifiable -CommandName 'Get-Credential' -MockWith {$VaultMasterKey}
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
            It "should not have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Throw
            }
            It 'Should request a credential on the first pass' {
                Test-SecretVault -VaultName $VaultName | Should -invoke -CommandName 'Get-Credential' -Times 1 -Exactly -Scope Context
            }
            It 'Should not request a credential on the second pass' {
                Test-SecretVault -VaultName $VaultName | Should -invoke -CommandName 'Get-Credential' -Times 1 -Exactly -Scope Context
            }
            It "should have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Not -Throw
            }
        }
    }
}