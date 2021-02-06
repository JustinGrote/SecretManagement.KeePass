
Describe 'Remove-Secret' {
    BeforeAll {
        Import-Module -Name 'Microsoft.PowerShell.SecretManagement'
        Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -Force
        $SCRIPT:Mocks = Join-Path $PSScriptRoot 'Mocks'
    }
    BeforeEach {
        $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
        $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))

        $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
        $KeePassDatabaseSuffix = 'PathOnly'
        $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
        $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
        Copy-Item -Path (Join-Path $Mocks $KeePassDatabaseFileName) -Destination $VaultPath

        $RegisterSecretVaultPathOnlyParams = @{
            Name            = $VaultName
            ModuleName      = $ModulePath
            PassThru        = $true
            VaultParameters = @{
                Path = $VaultPath
            }
        }
        Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null
        Mock -Verifiable -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
        Test-SecretVault -Name $VaultName | Out-Null
    }

    AfterAll {
        try {
            Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
        } catch [system.Exception] { }
    }

}