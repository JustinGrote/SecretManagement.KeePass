#Get-Module SecretManagement.KeePass | Remove-Module -ErrorAction SilentlyContinue
Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name KeepassPesterTest* | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
Import-Module -Name "$($PSScriptRoot)/../SecretManagement.KeePass.Extension.psd1" -Force
Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -force
get-module

InModuleScope -ModuleName 'SecretManagement.KeePass.Extension' {
    Describe "Test-SecretVault" {
        BeforeAll {
            $ModuleName = 'SecretManagement.Keepass.Extension'
            $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
            $KeepassDatabase = "Testdb.kdbx"
    
            $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
            $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeepassDatabase
            Copy-Item -Path "$($psscriptroot)/Testdb.kdbx" -Destination $VaultPath
            $VaultKey = [PSCredential]::new('vaultkey',(ConvertTo-SecureString -AsPlainText -Force $MasterKey))
    
            $RegisterSecretVaultParams = @{
                Name            = $VaultName
                ModuleName      = 'SecretManagement.Keepass'
                PassThru        = $true
                VaultParameters = @{
                    Path = $VaultPath
                }
            }

            Mock -Verifiable -CommandName 'Get-Credential' -MockWith {$VaultKey}
        }
        AfterAll {
            try { $Vaults = Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName } catch [System.Management.Automation.ItemNotFoundException] { }
            if ($Vaults) { $Vaults | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault}
        }
        Context "Validating Master Key rules" {
            BeforeAll {
                $TheVault = Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultParams
            }
            AfterAll {
                try { $Vaults = Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName } catch [System.Management.Automation.ItemNotFoundException] { }
                if ($Vaults) { $Vaults | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault}
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
            It "Should have a variable 'Vault_$($VaultName)' " {
                (Get-Variable -Name "Vault_$VaultName" -Scope Script).Value | Should -Not -BeNullOrEmpty
            }
        }
    }
}