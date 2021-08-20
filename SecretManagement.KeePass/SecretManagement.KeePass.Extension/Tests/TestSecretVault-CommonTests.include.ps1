param(
    [Switch]$Credential,
    [Switch]$KeyFile,
    [Switch]$Invalid
)

It "should not have a vault variable by default" {
    {
        InModuleScope $ExtensionModule {
            param($vaultName)
            Get-Variable "Vault_$vaultName" -ErrorAction 'Stop'
        } @{
            vaultName = $vaultParams.VaultName
        }
    } | Should -Throw 'Cannot find a variable with the name*'
}

if (-not $Invalid) {
    if ($KeyFile) {
        It 'Should not request a credential' {
            Set-ItResult -Skipped -Because 'Broken by SecretManagement 1.1.0 new runspace behavior'
            Test-SecretVault @vaultParams
            Should -Invoke -CommandName 'Get-Credential' -Exactly 0 -Scope Context
        }
    }

    if ($Credential) {
        It 'should request a credential on the first pass' {
            Set-ItResult -Skipped -Because 'Broken by SecretManagement 1.1.0 new runspace behavior'
            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }

            Test-SecretVault @vaultParams
            Should -ModuleName $ExtModuleName -Invoke -CommandName 'Get-Credential' -Exactly 1 -Scope Context
        }
        It 'Should not request a credential on the second pass' {
            Set-ItResult -Skipped -Because 'Broken by SecretManagement 1.1.0 new runspace behavior'
            Test-SecretVault @vaultParams
            Test-SecretVault @vaultParams
            Should -ModuleName $ExtModuleName -Invoke -CommandName 'Get-Credential' -Exactly 1 -Scope Context
        }
    }

    It "should have a Vault variable upon unlock" {
        Test-SecretVault @vaultParams | Should -BeTrue
        $vaultVars = InModuleScope $ExtensionModule {
            (Get-Variable -Name Vault_*).Name
        }
        "Vault_$($vaultParams.VaultName)" | Should -BeIn $vaultVars
    }

    It 'should return true' {
        Test-SecretVault @vaultParams | Should -BeTrue
    }

} else {
    It 'Detects Invalid Composite Key and does not set a vault variable' {
        $infoString=Get-Module microsoft.powershell.secretmanagement | Format-Table | Out-String 
        Write-PSFMessage -Level Host -Message "$infoString"
        $result = Test-SecretVault @vaultParams -ErrorVariable myerr 2>$null
        $myerr[-2] | Should -BeLike $KeePassMasterKeyError
        $result | Should -BeFalse
    }
}