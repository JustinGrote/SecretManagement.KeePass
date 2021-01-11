Describe 'SecretManagement.Keepass' {
    BeforeAll {
        Remove-Module SecretManagement.Keepass,SecretManagement.KeePass.Extension -ErrorAction SilentlyContinue

        #Would use TestDrive but the PoshKeePass Module doesn't understand it for purposes of new-keepassdatabase
        $SCRIPT:VaultName = 'SecretManagement.Tests'
        $SCRIPT:VaultPath = Join-Path $TestDrive.FullName 'KeepassTestVault.kdbx'
        $SCRIPT:VaultKey = [PSCredential]::new('vaultkey',(ConvertTo-SecureString -AsPlainText -Force 'ThisIsATestVaultYouShouldNotUseIt'))

        #BUG: For some reason there's an issue with using the nested module exported commands in Pester, this is workaround
        Import-Module $PSScriptRoot/../SecretManagement.KeePass.psd1 -Force
        & (Get-Module SecretManagement.Keepass) {
            Import-Module "$PSScriptRoot\..\PoshKeePass\PoShKeePass.psd1"
            
            #Create three variations of databases: Master Key only, keyfile, and both
            $VaultKeyFilePath = Join-Path $TestDrive.FullName 'KeepassTestKeyFileVault.key'
            $VaultKeyDBPath = $VaultPath -replace 'Vault','KeyVault'
            $VaultKeyPWDBPath = $VaultPath -replace 'Vault','KeyPWVault'
            [KeePassLib.Keys.KcpKeyFile]::Create($VaultKeyFilePath, $null)
            New-KeePassDatabase -DatabasePath $VaultPath -MasterKey $VaultKey
            New-KeePassDatabase -DatabasePath $VaultKeyDBPath -KeyPath $VaultKeyFilePath
            New-KeePassDatabase -DatabasePath $VaultKeyPWDBPath -KeyPath $VaultKeyFilePath -MasterKey $VaultKey

            Remove-Module PoshKeePass
        }

        $SCRIPT:RegisterSecretVaultParams = @{
            Name            = $VaultName
            ModuleName      = $(Split-Path -Parent $PSScriptRoot)
            PassThru        = $true
            VaultParameters = @{
                Path = $VaultPath
            }
        }
        try {
            Import-Module "$PSScriptRoot/../SecretManagement.KeePass.psd1"
            $SCRIPT:TestVault = Register-SecretVault @RegisterSecretVaultParams
        } catch [InvalidOperationException] {
            if ($PSItem -match 'Provided Name for vault is already being used') {
                Unregister-SecretVault -Name $RegisterSecretVaultParams.Name
                $SCRIPT:TestVault = Register-SecretVault @RegisterSecretVaultParams
            } else {
                $PSCmdlet.ThrowTerminatingError($PSItem)
            }
        }

        Mock -Verifiable Get-Credential {return $VaultKey}
    }

    AfterAll {
        $SCRIPT:TestVault | Unregister-SecretVault
        Get-Item $VaultPath -ErrorAction SilentlyContinue | Remove-Item
    }

    BeforeEach {
        $secretName = "tests/$((New-Guid).Guid)"
    }

    Context 'Unlock' {
        It 'Vault prompts for Master Key' {
            Test-SecretVault -Name $TestVault.Name | Out-Null
            Should -InvokeVerifiable
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
            $secret = Get-Secret -Name $secretName -AsPlainText -Vault $VaultName
            $secret | Should -BeExactly $secretText
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

        It 'Register-SecretVault -AllowClobber' {
            $RegisterSecretVaultParams.VaultParameters.Pester = $true
            $RegisterSecretVaultParams.AllowClobber = $true
            $newVault = Register-SecretVault @RegisterSecretVaultParams
            $newVault.VaultParameters.Pester | Should -BeTrue
        }
    }
}