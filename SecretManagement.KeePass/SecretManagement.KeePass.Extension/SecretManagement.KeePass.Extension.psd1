@{
    ModuleVersion = '0.9.1.3'
    RootModule = 'SecretManagement.KeePass.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault','Unregister-SecretVault','Connect-KeepassDatabase','Unlock-SecretVault')
    NestedModules = @(
        '../PoshKeePass/PoShKeePass.psd1'
    )
}
