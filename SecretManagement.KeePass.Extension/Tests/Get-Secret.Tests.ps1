Import-Module -Name 'Microsoft.PowerShell.SecretManagement'
Import-Module -Name "$($PSScriptRoot)/../../SecretManagement.KeePass.psd1" -Force

InModuleScope -ModuleName 'SecretManagement.KeePass.Extension' {
    Describe "Get-Secret" {
        BeforeAll {
            $ModuleName = 'SecretManagement.KeePass'
            $ModulePath = (Get-Module $ModuleName).Path
            $BaseKeepassDatabaseName = "Testdb"
            $DoubleEntryExceptionMessage = 'Multiple ambiguous entries found for double entry, please remove the duplicate entry'
        }
        AfterAll {
            try {
                Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
            } catch [system.Exception] { }
        }
        Context "Function Parameter Validation" {
            BeforeAll {
                $ExtModuleName = 'SecretManagement.KeePass.Extension'
                $FunctionName = 'Get-Secret'
            }
            It 'has a parameter "<Name>"' -TestCases @(
                @{Name = 'Name' }
                @{Name = 'VaultName' }
                @{Name = 'AdditionalParameters' }
            ) {
                $AllParameterNames = (Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters.Keys
                $Name | Should -BeIn $AllParameterNames
            }
            It 'has the mandatory value of parameter "<Name>" set to "<Mandatory>"' -TestCases @(
                @{Name = 'Name'; Mandatory = $False }
                @{Name = 'VaultName'; Mandatory = $False }
                @{Name = 'AdditionalParameters'; Mandatory = $False }
            ) {
                ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].Attributes | Where-Object { $_.GetType().FullName -eq 'System.Management.Automation.ParameterAttribute' }).Mandatory | Should -Be $Mandatory
            }
            It 'has parameter <Name> of type <Type>' -TestCases @(
                @{Name = 'Name'; Type = 'string' }
                @{Name = 'VaultName'; Type = 'string' }
                @{Name = 'AdditionalParameters'; Type = 'hashtable' }
            ) {
                ((Get-Command -Module $ExtModuleName -Name $FunctionName).Parameters[$Name].ParameterType) | Should -BeExactly $Type
            }
            It "has one parameter set" {
                (Get-Command -Module $ExtModuleName -Name $FunctionName).ParameterSets.Count | Should -BeExactly 1
            }
        }
        Context "Get Secret information from MasterPassword protected KeePass" {
            BeforeAll {
                $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
                $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))

                $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
                $KeePassDatabaseSuffix = 'PathOnly'
                $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
                $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
                Copy-Item -Path "$($PSScriptRoot)/$($KeePassDatabaseFileName)" -Destination $VaultPath

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
                Test-SecretVault -VaultName $VaultName | Out-Null
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
            It 'should return a <PSType> for entry <SecretName>' -TestCases @(@{SecretName = 'New Entry 1';PSType='System.Management.Automation.PSCredential'},@{SecretName = 'New Entry 2';PSType='System.Management.Automation.PSCredential'},@{SecretName='No UserName';PSType='System.Security.SecureString'}) {
                $Secret = Get-Secret -Name $SecretName -VaultName $VaultName
                $Secret.Gettype().Fullname | Should -BeExactly $PSType
            }
            It 'should return <username> for <SecretName>' -TestCases @( @{SecretName='New Entry 1';UserName='myusername 1'},@{SecretName='New Entry 2';UserName='Some Administrator account'} ) { 
                (Get-Secret -Name $SecretName -VaultName $VaultName).UserName | Should -BeExactly $UserName
            }
            It 'should throw when multiple secrets are returned' {
                { (Get-Secret -Name 'double entry' -VaultName $VaultName) } | Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
            }
            It 'should return nothing when entry is not found in the KeePass DB' {
                ( Get-Secret -Name 'not present' -VaultName $VaultName) | Should -BeNullOrEmpty
            }
        }
        Context "Get Secret information from KeyFile protected KeePass" {
            BeforeAll {
                $KeyFileName = 'TestdbKeyFile.key'

                $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
                $KeePassDatabaseSuffix = 'KeyFile'
                $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
                $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
                $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
                Copy-Item -Path "$($PSScriptRoot)/$($KeePassDatabaseFileName)" -Destination $VaultPath
                Copy-Item -Path "$($PSScriptRoot)/$($KeyFileName)" -Destination $KeyPath

                $RegisterSecretVaultPathOnlyParams = @{
                    Name            = $VaultName
                    ModuleName      = $ModulePath
                    PassThru        = $true
                    VaultParameters = @{
                        Path    = $VaultPath
                        KeyPath = $KeyPath
                    }
                }
                Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null

                Mock -Verifiable -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
                Test-SecretVault -VaultName $VaultName | Out-Null
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
            It 'should return a <PSType> for entry <SecretName>' -TestCases @(@{SecretName = 'New Entry 1';PSType='System.Management.Automation.PSCredential'},@{SecretName = 'New Entry 2';PSType='System.Management.Automation.PSCredential'},@{SecretName='No UserName';PSType='System.Security.SecureString'}) {
                $Secret = Get-Secret -Name $SecretName -VaultName $VaultName
                $Secret.Gettype().Fullname | Should -BeExactly $PSType
            }
            It 'should return <username> for <SecretName>' -TestCases @( @{SecretName='New Entry 1';UserName='myusername 1'},@{SecretName='New Entry 2';UserName='Some Administrator account'} ) { 
                (Get-Secret -Name $SecretName -VaultName $VaultName).UserName | Should -BeExactly $UserName
            }
            It 'should throw when multiple secrets are returned' {
                { (Get-Secret -Name 'double entry' -VaultName $VaultName) } | Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
            }
            It 'should return nothing when entry is not found in the KeePass DB' {
                ( Get-Secret -Name 'not present' -VaultName $VaultName) | Should -BeNullOrEmpty
            }
        }
        Context "Get Secret information from MasterPassword and KeyFile protected KeePass" {
            BeforeAll {
                $KeyFileName = 'TestdbKeyFileAndMasterPassword.key'
                $MasterKey = '"1}`.2R{LX1`Jm8%XX2/'
                $VaultMasterKey = [PSCredential]::new('vaultkey', (ConvertTo-SecureString -AsPlainText -Force $MasterKey))

                $VaultName = "KeepassPesterTest_$([guid]::NewGuid())"
                $KeePassDatabaseSuffix = 'KeyFileAndMasterPassword'
                $KeePassDatabaseFileName = "$($BaseKeepassDatabaseName)$($KeePassDatabaseSuffix).kdbx"
                $VaultPath = Join-Path -Path $TestDrive -ChildPath $KeePassDatabaseFileName
                $KeyPath = Join-Path -Path $TestDrive -ChildPath $KeyFileName
                Copy-Item -Path "$($PSScriptRoot)/$($KeePassDatabaseFileName)" -Destination $VaultPath
                Copy-Item -Path "$($PSScriptRoot)/$($KeyFileName)" -Destination $KeyPath

                $RegisterSecretVaultPathOnlyParams = @{
                    Name            = $VaultName
                    ModuleName      = $ModulePath
                    PassThru        = $true
                    VaultParameters = @{
                        Path              = $VaultPath
                        UseMasterPassword = $true
                        KeyPath           = $KeyPath
                    }
                }
                Microsoft.PowerShell.SecretManagement\Register-SecretVault @RegisterSecretVaultPathOnlyParams | Out-Null

                Mock -Verifiable -CommandName 'Get-Credential' -MockWith { $VaultMasterKey }
                Test-SecretVault -VaultName $VaultName | Out-Null
            }
            AfterAll {
                try {
                    Microsoft.PowerShell.SecretManagement\Get-SecretVault -Name $VaultName -ErrorAction SilentlyContinue | Microsoft.PowerShell.SecretManagement\Unregister-SecretVault -ErrorAction SilentlyContinue
                } catch [system.Exception] { }
            }
            It 'should return a <PSType> for entry <SecretName>' -TestCases @(@{SecretName = 'New Entry 1';PSType='System.Management.Automation.PSCredential'},@{SecretName = 'New Entry 2';PSType='System.Management.Automation.PSCredential'},@{SecretName='No UserName';PSType='System.Security.SecureString'}) {
                $Secret = Get-Secret -Name $SecretName -VaultName $VaultName
                $Secret.Gettype().Fullname | Should -BeExactly $PSType
            }
            It 'should return <username> for <SecretName>' -TestCases @( @{SecretName='New Entry 1';UserName='myusername 1'},@{SecretName='New Entry 2';UserName='Some Administrator account'} ) { 
                (Get-Secret -Name $SecretName -VaultName $VaultName).UserName | Should -BeExactly $UserName
            }
            It 'should throw when multiple secrets are returned' {
                { (Get-Secret -Name 'double entry' -VaultName $VaultName) } | Should -Throw -ExpectedMessage $DoubleEntryExceptionMessage
            }
            It 'should return nothing when entry is not found in the KeePass DB' {
                ( Get-Secret -Name 'not present' -VaultName $VaultName) | Should -BeNullOrEmpty
            }
        }
    }
}