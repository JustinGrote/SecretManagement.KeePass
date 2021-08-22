@{
    ModuleVersion = '0.9.1.3'
    RootModule = 'SecretManagement.KeePass.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault','Unregister-SecretVault','Connect-KeepassDatabase','Unlock-SecretVault')
    RequiredModules   = @(
        @{ ModuleName = 'PSFramework'; ModuleVersion = '1.6.205' }
    )
    NestedModules     = @(
        '../PoshKeePass/PoShKeePass.psd1'
    )
}
