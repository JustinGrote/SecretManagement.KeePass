@{
    ModuleVersion = '0.0.4.4'
    RootModule = '.\SecretManagement.KeePass.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault','Unregister-SecretVault')
    NestedModules = @(
        '../PoshKeePass/PoshKeePass.psd1'
    )
}
