Get-Module *Secret* | Remove-Module -ErrorAction SilentlyContinue -Force
Import-Module -Name 'Microsoft.PowerShell.SecretManagement'
Write-Verbose "$($PSScriptRoot)/../SecretManagement.KeePass.Extension.psd1"
Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -Force

foreach ($mod in (get-module -name *secret*)) { write-verbose $mod.name -verbose}

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
                $TheVault = Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams

                Mock -Verifiable -CommandName 'Get-Credential' -MockWith {$VaultMasterKey}
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
                It "Should not have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Throw
            }
            It "Should request a credential on the first pass" {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1 -Scope Context
            }
            It 'Should not request a credential on the second pass' {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1 -Scope Context
            }
            It "Should have a variable 'Vault_$($VaultName)'" {
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
                $TheVault = Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams

                Mock -Verifiable -CommandName 'Get-Credential' -MockWith {$VaultMasterKey}
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
                It "Should not have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Throw
            }
            It "Should request a credential on the first pass" {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1 -Scope Context
            }
            It 'Should not request a credential on the second pass' {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1 -Scope Context
            }
            It "Should have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Not -Throw
            }
        }
    }
}