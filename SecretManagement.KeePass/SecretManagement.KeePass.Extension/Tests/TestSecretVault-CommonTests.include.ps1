param(
    [Switch]$Credential,
    [Switch]$KeyFile,
    [Switch]$Invalid
)

It "should not have a vault variable by default" {
    {
        InModuleScope $ExtensionModule {
            param($vaultName)
            Get-Variable "Vault_$vaultName"
        } @{
            vaultName = $vaultParams.VaultName
        }
    } | Should -Throw 'Cannot find a variable with the name*'
}

if (-not $Invalid) {
    if ($KeyFile) {
        It 'Should not request a credential' {
            Test-SecretVault @vaultParams
            Should -Invoke -CommandName 'Get-Credential' -Exactly 0 -Scope Context
        }
    }

    if ($Credential) {
        It 'should request a credential on the first pass' {
            Mock -Verifiable -ModuleName $ExtModuleName -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }

            Test-SecretVault @vaultParams
            Should -ModuleName $ExtModuleName -Invoke -CommandName 'Get-Credential' -Exactly 1 -Scope Context
        }
        It 'Should not request a credential on the second pass' {
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
        $result = Test-SecretVault @vaultParams -ErrorVariable myerr 2>$null
        $myerr[-1] | Should -BeLike $KeePassMasterKeyError
        $result | Should -BeFalse
    }
}



