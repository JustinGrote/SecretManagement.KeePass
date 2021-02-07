
Describe 'Register-KeepassSecretVault' {
    BeforeAll {
        Import-Module "$PSScriptRoot/../SecretManagement.KeePass.psd1" -Force
        
        $SCRIPT:Mocks = Resolve-Path "$PSScriptRoot/../SecretManagement.KeePass.Extension/Tests/Mocks"
        $SCRIPT:TestDB = Join-Path $Mocks 'TestdbKeyFile.kdbx'
        $SCRIPT:TestDBKey = Join-Path $Mocks 'TestdbKeyFile.key'
        $SCRIPT:TestDBName = ([io.fileinfo]$TestDB).Basename
        Unregister-SecretVault -Name $TestDBName -ErrorAction SilentlyContinue
    }
    AfterEach {
        Unregister-SecretVault -Name $TestDBName -ErrorAction SilentlyContinue
    }

    It 'Registers a Vault' {
        Register-KeepassSecretVault -ErrorAction Stop -Path $TestDB -KeyPath $TestDBKey
        Get-SecretVault -Name $TestDBName -OutVariable myvault | Should -not -BeNullOrEmpty
        $myvault.Name | Should -Be $TestDBName
        $myvault.ModuleName | Should -Be 'SecretManagement.KeePass'
        $myVault.VaultParameters.UseMasterPassword | Should -BeFalse
        $myVault.VaultParameters.UseWindowsAccount | Should -BeFalse
        $myVault.VaultParameters.Path | Should -Be $TestDB
        $myVault.VaultParameters.KeyPath | Should -Be $TestDBKey
    }
    It 'Fails if bad path specified' {
        {Register-KeepassSecretVault -ErrorAction Stop -Path "C:\Path\To\Nowhere.kdbx"} |
            Should -Throw -ErrorId 'PathNotFound,Microsoft.PowerShell.Commands.ResolvePathCommand'
    }
    It 'Fails if no auth method specified' {
        {Register-KeepassSecretVault -ErrorAction Stop -Path $TestDB} |
            Should -Throw 'No authentication methods specified*'
    }



    It 'Creates a vault if Create is specified' {Set-ItResult -Pending}
    It 'Doesnt Clobber an existing vault if Create is specified' {Set-ItResult -Pending}
    It 'Doesnt Clobber an existing keyfile if Create is specified' {Set-ItResult -Pending}
    It 'Uses full titles if showfulltitle is specified' {Set-ItResult -Pending}
    It 'Configures Correct Vault Parameters for scenario <Scenario>' {Set-ItResult -Pending}
    It 'Succeeds with bad path but SkipValidate' {Set-ItResult -Pending}


}