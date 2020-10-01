@{
    ModuleVersion = '0.0.3'
    RootModule = '.\SecretManagement.KeePass.Extension.psm1'
    FunctionsToExport = @('Set-Secret','Get-Secret','Remove-Secret','Get-SecretInfo','Test-SecretVault')
    NestedModules = @(
        '../PoshKeePass/PoshKeePass.psd1'
    )
}
