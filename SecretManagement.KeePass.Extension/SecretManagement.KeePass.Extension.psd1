@{
    ModuleVersion = '0.0.9.3'
    RootModule = 'SecretManagement.KeePass.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault','Unregister-SecretVault','Connect-KeepassDatabase')
    NestedModules = @(
        '../PoshKeePass/PoShKeePass.psd1'
    )
}
