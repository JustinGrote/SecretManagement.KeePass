
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
        if (-not $testdrive) {throw 'TestDrive Missing! This should not happen, bailing out for safety.'}
        Get-ChildItem $testdrive | Remove-Item -Force
    }
    AfterAll {
        Remove-Module SecretManagement.KeePass
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
        {Register-KeepassSecretVault -ErrorAction Stop -Path "$HOME\Path\To\Nowhere.kdbx"} |
            Should -Throw -ErrorId 'PathNotFound,Microsoft.PowerShell.Commands.ResolvePathCommand'
    }
    It 'Fails if no auth method specified' {
        {Register-KeepassSecretVault -ErrorAction Stop -Path $TestDB} |
            Should -Throw 'No authentication methods specified*'
    }

    It 'Creates a new vault if Create is specified' {
        $RegisterParams = @{
            Create = $true
            Path = (Join-Path $TestDrive "$TestDBName.kdbx")
            KeyPath = (Join-Path $TestDrive "$TestDBName.key")
        }

        Register-KeePassSecretVault @RegisterParams
        
        Get-SecretVault -Name $TestDBName -OutVariable DB | Should -Not -BeNullOrEmpty
        $expectedVaultParameters = @{
            Path = $RegisterParams.Path
            KeyPath = $RegisterParams.KeyPath
            UseMasterPassword = 'False'
            UseWindowsAccount = 'False'
        }
        
        $expectedVaultParameters.keys.foreach{
            $DB.VaultParameters.$PSItem | Should -Be $expectedVaultParameters.$PSItem
        }
    }

    It 'Doesnt Clobber an existing vault if Create is specified' {
        $RegisterParams = @{
            Create = $true
            Path = (Join-Path $TestDrive "$TestDBName.kdbx")
            KeyPath = (Join-Path $TestDrive "$TestDBName.key")
        }

        #Simulate an already present vault
        New-Item $RegisterParams.Path

        {Register-KeePassSecretVault @RegisterParams} |
            Should -Throw '-Create was specified but a database already exists*'
    }
    It 'Doesnt Clobber an existing keyfile if Create is specified' {
        $RegisterParams = @{
            Create = $true
            Path = (Join-Path $TestDrive "$TestDBName.kdbx")
            KeyPath = $TestDBKey
        }
        $dbKeyHash = (Get-FileHash $TestDBKey).Hash
        $dbKeyDateModified = (Get-Item $TestDBKey).LastWriteTime
        Register-KeePassSecretVault @RegisterParams
        (Get-FileHash $TestDBKey).Hash | Should -Be $dbKeyHash
        (Get-Item $TestDBKey).LastWriteTime | Should -Be $dbKeyDateModified
    }
    It 'Uses full titles if showfulltitle is specified' {
        Register-KeepassSecretVault -ErrorAction Stop -Path $TestDB -KeyPath $TestDBKey -ShowFullTitle
        (Get-SecretInfo 'General/New Entry 1' -Vault $TestDBName 3>$null).Name | Should -Be 'General/New Entry 1'
    }
    It 'Succeeds with bad path but SkipValidate specified' {
        Register-KeePassSecretVault -Name $TestDBName -Path "$TestDrive/NotArealPath" -SkipValidate -KeyPath "$TestDrive/NotARealKey"
        Get-SecretVault -Name $TestDBName | Should -Not -BeNullOrEmpty
    }
}