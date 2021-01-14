Get-Module *Secret* | Remove-Module -ErrorAction SilentlyContinue -Force
Import-Module -Name 'Microsoft.PowerShell.SecretManagement'
Import-Module -Name "$($PSScriptRoot)/../SecretManagement.KeePass.Extension.psd1" -Force
Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -force

InModuleScope -ModuleName 'SecretManagement.KeePass.Extension' {
    Describe "Test-SecretVault" {
        BeforeAll {
            Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -Force
            $ModuleName = 'SecretManagement.Keepass.Extension'
            $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $KeepassDatabase = "Testdb.kdbx"
    
            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeepassDatabase
            Copy-Item -Path "$($psscriptroot)/Testdb.kdbx" -Destination $VaultPath
            $VaultKey = [PSCredential]::new('vaultkey',(ConvertTo-SecureString -AsPlainText -Force $MasterKey))
    
            $RegisterSecretVaultParams = @{
                Name            = $VaultName
                ModuleName      = 'SecretManagement.KeePass'
                PassThru        = $true
                VaultParameters = @{
                    Path = $VaultPath
                }
            }

            Mock -Verifiable -CommandName 'Get-Credential' -MockWith {$VaultKey}
        }
        Context "Validating Master Key rules" {
            BeforeAll {
                $TheVault = Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultParams
            }
            It "Should not have a variable 'Vault_$($VaultName)'" {
                { (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value } | Should -Throw
            }
            It "Should request a credential on the first pass" {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1
            }
            It 'Should not request a credential on the second pass' {
                Test-SecretVault -VaultName $VaultName
                Assert-MockCalled -CommandName 'Get-Credential' -Exactly 1
            }
        }
    }
}