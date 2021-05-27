#requires -modules @{ModuleName="Pester"; ModuleVersion="5.1.0"}
Describe 'SecretManagement.Keepass' {
    BeforeAll {
        Remove-Module SecretManagement.Keepass,SecretManagement.KeePass.Extension -ErrorAction SilentlyContinue

        #Fetch helper function
        . $PSScriptRoot/../SecretManagement.KeePass.Extension/Private/Unlock-SecureString.ps1

        #Would use TestDrive but the PoshKeePass Module doesn't understand it for purposes of new-keepassdatabase
        $VaultName = 'SecretManagement.Tests'
        $VaultExtensionName = 'SecretManagement.KeePass'
        $VaultPath = Join-Path $TestDrive.FullName 'KeepassTestVault.kdbx'
        $SCRIPT:VaultKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force 'ThisIsATestVaultYouShouldNotUseIt'))

        Import-Module "$PSScriptRoot/../PoshKeePass/PoShKeePass.psd1"

        #Create three variations of databases: Master Key only, keyfile, and both
        $VaultKeyFilePath = Join-Path $TestDrive.FullName 'KeepassTestKeyFileVault.key'
        $VaultKeyDBPath = $VaultPath -replace 'Vault','KeyVault'
        $VaultKeyPWDBPath = $VaultPath -replace 'Vault','KeyPWVault'
        [KeePassLib.Keys.KcpKeyFile]::Create($VaultKeyFilePath, $null)
        New-KeePassDatabase -DatabasePath $VaultPath -MasterKey $VaultKey
        New-KeePassDatabase -DatabasePath $VaultKeyDBPath -KeyPath $VaultKeyFilePath
        New-KeePassDatabase -DatabasePath $VaultKeyPWDBPath -KeyPath $VaultKeyFilePath -MasterKey $VaultKey

        Remove-Module PoshKeePass

        Import-Module "$PSScriptRoot/../SecretManagement.KeePass.psd1" -Force

        $SCRIPT:RegisterSecretVaultParams = @{
            Name            = $VaultName
            ModuleName      = (Get-Module $VaultExtensionName).Path
            PassThru        = $true
            VaultParameters = @{
                Path = $VaultPath
            }
        }
        try {
            $SCRIPT:TestVault = Register-SecretVault @RegisterSecretVaultParams
        } catch [InvalidOperationException] {
            if ($PSItem -match 'Provided Name for vault is already being used') {
                Unregister-SecretVault -Name $RegisterSecretVaultParams.Name
                $SCRIPT:TestVault = Register-SecretVault @RegisterSecretVaultParams
            } else {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        }
    }

    AfterAll {
        $TestVault | Unregister-SecretVault -ErrorAction SilentlyContinue
        Get-Item $VaultPath -ErrorAction SilentlyContinue | Remove-Item
    }

    BeforeEach {
        $secretName = "tests/$((New-Guid).Guid)"
    }

    Context 'Unlock' {
        It 'Unattended Vault Unlock' {
            Unlock-SecretVault -Name $TestVault.Name -Password $VaultKey.Password
            Test-SecretVault -Name $TestVault.Name | Should -Be $true
        }
    }

    Context 'InvalidRegistration' {
        BeforeAll {
            $SCRIPT:InvalidVaultName = 'Pester.InvalidVault'
            Register-SecretVault -Name $InvalidVaultName -ModuleName (Resolve-Path $PSScriptRoot/..) -VaultParameters @{Path="$TestDrive\NotARealDB.kdbx"}
        }
        AfterAll {
            Unregister-SecretVault -Name $InvalidVaultName
        }
        It 'Test-SecretVault should fail on uninitalized vault' {
            Test-SecretVault -Name $InvalidVaultName -ErrorVariable mytest 2>$null | Should -Be $False
        }
    }

    Context 'SecretManagement' {
        BeforeAll {
            #Unlock the vault
            Test-SecretVault -Name $TestVault.Name
        }

        It 'Get-SecretVault' {
            Get-SecretVault -Name $TestVault.Name | Should -Not -BeNullOrEmpty
        }
        It 'Test-SecretVault' {
            Test-SecretVault -Name $TestVault.Name | Should -Be $true
        }

        It 'Get/Set/Remove String' {
            $secretText = 'This is my string secret'
            Set-Secret -Name $secretName -Vault $VaultName -Secret $secretText
            $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
            $secretInfo.Name | Should -BeExactly $secretName
            $secretInfo.VaultName | Should -BeExactly $VaultName

            #Metadata
            $secretInfo.Metadata.IconName | Should -Be 'Key'
            $secretInfo.Metadata.ParentGroup | Should -Be 'KeePassTestVault'

            $secret = Get-Secret -Name $secretName -Vault $VaultName
            $secret | Should -Be 'System.Security.SecureString'
            Unlock-SecureString $secret | Should -BeExactly $secretText

            Remove-Secret -Name $secretName -Vault $VaultName
            {
                Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop
            } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }

        It 'Get/Set/Remove SecureString' {
            $secretText = 'This is my securestring secret'
            Set-Secret -Name $secretName -Vault $VaultName -Secret ($secretText | ConvertTo-SecureString -AsPlainText -Force)

            $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
            $secretInfo.Name | Should -BeExactly $secretName
            $secretInfo.VaultName | Should -BeExactly $VaultName

            $secret = Get-Secret -Name $secretName -AsPlainText -Vault $VaultName
            $secret | Should -BeExactly $secretText

            Remove-Secret -Name $secretName -Vault $VaultName
            { Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }

        It 'Get/Set/Remove PSCredential' {
            $secretPassword = 'PesterPassword'
            $secret = [PSCredential]::new('PesterUser',($secretPassword | ConvertTo-SecureString -AsPlainText -Force))
            Set-Secret -Name $secretName -Vault $VaultName -Secret $secret
            $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
            $secretInfo.Name | Should -BeLike $secretName
            $secretInfo.VaultName | Should -BeExactly $VaultName
            $storedSecret = Get-Secret -Name $secretName -Vault $VaultName
            $storedSecret | Should -BeOfType [PSCredential]
            $storedSecret.GetNetworkCredential().Password | Should -BeExactly $secretPassword
            $storedSecret.Username | Should -BeExactly $secret.UserName
            Remove-Secret -Name $secretName -Vault $VaultName
            {
                Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop
            } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
        }

        It 'Should not create a duplicate entry with Set-Secret' {
            Set-ItResult -Skipped -Because 'Broken by 1.1.0 - https://github.com/PowerShell/SecretManagement/issues/151'
            $secretPassword = 'PesterPassword'
            $secret = [PSCredential]::new('PesterUser',($secretPassword | ConvertTo-SecureString -AsPlainText -Force))
            Set-Secret -Name $secretName -Vault $VaultName -Secret $secret
            [String]$DuplicateSecretWarning = Set-Secret -Name $secretName -Vault $VaultName -Secret $secret -WarningAction Continue *>&1
            [String]$DuplicateSecretWarning | Should -BeLike "*A secret with the title $secretName already exists*"
        }

        It 'Register-SecretVault -AllowClobber' {
            $RegisterSecretVaultParams.VaultParameters.Pester = $true
            $RegisterSecretVaultParams.AllowClobber = $true
            $newVault = Register-SecretVault @RegisterSecretVaultParams
            $newVault.VaultParameters.Pester | Should -BeTrue
        }
    }
}