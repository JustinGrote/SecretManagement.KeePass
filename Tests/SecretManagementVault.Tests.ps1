Describe 'SecretManagement.Keepass' {
    BeforeAll {
        Remove-Module SecretManagement.Keepass,SecretManagement.KeePass.Extension -ErrorAction SilentlyContinue

        #Would use TestDrive but the PoshKeePass Module doesn't understand it for purposes of new-keepassdatabase
        $SCRIPT:VaultPath = Join-Path $TestDrive.FullName 'KeepassTestVault.kdbx'
        $SCRIPT:VaultKey = [PSCredential]::new('vaultkey',(ConvertTo-SecureString -AsPlainText -Force 'ThisIsATestVaultYouShouldNotUseIt'))

        #BUG: For some reason there's an issue with using the nested module exported commands in Pester, this is workaround
        Import-Module $PSScriptRoot/../SecretManagement.KeePass.psd1 -Force
        & (Get-Module SecretManagement.Keepass) {
            Import-Module C:\Users\JGrote\Projects\SecretManagement.KeePass\PoshKeePass\PoShKeePass.psd1
            New-KeepassDatabase -DatabasePath $VaultPath -MasterKey $VaultKey
            Remove-Module PoshKeePass
        }

        $SCRIPT:RegisterSecretVaultParams = @{
            Name            = 'SecretManagement.Tests'
            ModuleName      = $(Split-Path -Parent $PSScriptRoot)
            PassThru        = $true
            VaultParameters = @{
                Path = $VaultPath
            }
        }
        try {
            Import-Module C:\Users\JGrote\Projects\SecretManagement.KeePass\SecretManagement.KeePass.psd1
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
        $SCRIPT:TestVault | Unregister-SecretVault
        Get-Item $VaultPath -ErrorAction SilentlyContinue | Remove-Item
    }

    BeforeEach {
        $secretName = "tests/$((New-Guid).Guid)"
    }

    It 'Vault is registered' {
        Get-SecretVault -Name $TestVault.Name | Should -Not -BeNullOrEmpty
    }

    It 'Vault prompts for Master Key' {
        Mock -Verifiable Get-Credential {return $VaultKey}
        write-host -fore magenta (Test-SecretVault -Name $TestVault.Name)
        Should -InvokeVerifiable
    }

    # It 'Can store a string secret which is treated like a securestring' {
    #     $secretText = 'This is my string secret'
    #     Set-Secret -Name $secretName -Vault $VaultName -Secret $secretText
    #     Sync-LastPassVault -Vault $VaultName

    #     $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
    #     $secretInfo.Name | Should -BeLike "$secretName (id:*)"
    #     $secretInfo.Type | Should -BeExactly 'Unknown'
    #     $secretInfo.VaultName | Should -BeExactly $VaultName
    #     $secret = Get-Secret -Name $secretName -AsPlainText -Vault $VaultName
    #     $secret | Should -BeExactly $secretText

    #     Remove-Secret -Name $secretName -Vault $VaultName
    #     { 
    #         Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop
    #     } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    # }

    # It 'Can store a secure string secret' {
    #     $secretText = 'This is my securestring secret'
    #     Set-Secret -Name $secretName -Vault $VaultName -Secret ($secretText | ConvertTo-SecureString -AsPlainText -Force)
    #     Sync-LastPassVault -Vault $VaultName

    #     $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
    #     $secretInfo.Name | Should -BeLike "$secretName (id:*)"
    #     $secretInfo.Type | Should -BeExactly 'Unknown'
    #     $secretInfo.VaultName | Should -BeExactly $VaultName

    #     $secret = Get-Secret -Name $secretName -AsPlainText -Vault $VaultName
    #     $secret | Should -BeExactly $secretText

    #     Remove-Secret -Name $secretName -Vault $VaultName
    #     { Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    # }

    # It 'Can store a PSCredential secret' {
    #     $secretText = 'This is my pscredential secret'
    #     $secret = [PSCredential]::new('myUser', ($secretText | ConvertTo-SecureString -AsPlainText -Force))
    #     Set-Secret -Name $secretName -Vault $VaultName -Secret $secret
    #     Sync-LastPassVault -Vault $VaultName

    #     $secretInfo = Get-SecretInfo -Name $secretName -Vault $VaultName
    #     $secretInfo.Name | Should -BeLike "$secretName (id:*)"
    #     $secretInfo.Type | Should -BeExactly 'PSCredential'
    #     $secretInfo.VaultName | Should -BeExactly $VaultName

    #     $secret = Get-Secret -Name $secretName -Vault $VaultName
    #     $secret.UserName | Should -BeExactly 'myUser'
    #     $secret.Password | ConvertFrom-SecureString -AsPlainText | Should -BeExactly $secretText

    #     Remove-Secret -Name $secretName -Vault $VaultName
    #     { Get-Secret -Name $secretName -Vault $VaultName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    # }

    # #region Tests to add back in later from Steve's module

    # # Skipping because I don't think this extension supports byte array.
    # It 'Can store a byte array secret' -Skip {
    #     $secretText = 'This is my byte array secret'
    #     $bytes = [System.Text.Encoding]::UTF8.GetBytes($secretText)
    #     Set-Secret -Name $secretName -Vault $VaultName -Secret $bytes
    #     Sync-LastPassVault -Vault $VaultName

    #     $secretInfo = Get-SecretInfo -Name $secretName
    #     $secretInfo.Name | Should -BeExactly $secretName
    #     $secretInfo.Type | Should -BeExactly 'ByteArray'
    #     $secretInfo.VaultName | Should -BeExactly $VaultName

    #     $secret = Get-Secret -Name $secretName
    #     [System.Text.Encoding]::UTF8.GetString($secret) | Should -BeExactly $secretText

    #     Remove-Secret -Name $secretName -Vault $VaultName
    #     { Get-Secret -Name $secretName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    # }

    # # Skipping because I don't think this extension supports arbitrary hashtables.
    # It 'Can store hashtable secret' -Skip {
    #     $secretText = 'This is my hashtable secret'
    #     $cred = [pscredential]::new('myUser', ($secretText | convertto-securestring -AsPlainText -Force))
    #     $securestring = $secretText | convertto-securestring -AsPlainText -Force
    #     $hashtable = @{
    #         a = 1
    #         b = $cred
    #         c = @{
    #             d = 'nested'
    #             e = $cred
    #             f = $securestring
    #         }
    #         g = $securestring
    #     }

    #     Set-Secret -Name $secretName -Vault $VaultName -Secret $hashtable
    #     Sync-LastPassVault -Vault $VaultName

    #     $secretInfo = Get-SecretInfo -Name $secretName
    #     $secretInfo.Name | Should -BeExactly $secretName
    #     $secretInfo.Type | Should -BeExactly 'Hashtable'
    #     $secretInfo.VaultName | Should -BeExactly $VaultName

    #     $secret = Get-Secret -Name $secretName -AsPlainText
    #     $secret.a | Should -Be 1
    #     $secret.b | Should -BeOfType [PSCredential]
    #     $secret.b.UserName | Should -BeExactly 'myUser'
    #     $secret.b.Password | ConvertFrom-SecureString -AsPlainText | Should -BeExactly $secretText
    #     $secret.c | Should -BeOfType [Hashtable]
    #     $secret.c.d | Should -BeExactly 'nested'
    #     $secret.c.e | Should -BeOfType [PSCredential]
    #     $secret.c.e.UserName | Should -BeExactly 'myUser'
    #     $secret.c.e.Password | ConvertFrom-SecureString -AsPlainText | Should -BeExactly $secretText
    #     $secret.c.f | Should -BeExactly $secretText
    #     $secret.g | Should -BeExactly $secretText

    #     Remove-Secret -Name $secretName -Vault $VaultName
    #     { Get-Secret -Name $secretName -ErrorAction Stop } | Should -Throw -ErrorId 'GetSecretNotFound,Microsoft.PowerShell.SecretManagement.GetSecretCommand'
    # }

    #endregion
}