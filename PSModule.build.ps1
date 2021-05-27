
if (-not (Get-Module PowerConfig -ErrorAction SilentlyContinue)) {
    try {
        Import-Module PowerConfig -ErrorAction Stop
    } catch {
        Install-Module PowerConfig -AllowPrerelease -Force
        Import-Module PowerConfig -ErrorAction Stop
    }
}
if (-not (Get-Module Press -ErrorAction SilentlyContinue)) {
    try {
        Import-Module Press -ErrorAction Stop
    } catch {
        Install-Module Press -AllowPrerelease -Force
        Import-Module Press -ErrorAction Stop
    }
}
if (-not (Get-Module 'Microsoft.Powershell.SecretManagement' -ErrorAction SilentlyContinue)) {
    try {
        Import-Module 'Microsoft.Powershell.SecretManagement' -ErrorAction Stop
    } catch {
        Install-Module 'Microsoft.Powershell.SecretManagement' -AllowPrerelease -RequiredVersion '1.1.0-preview' -Force
        Import-Module 'Microsoft.Powershell.SecretManagement' -ErrorAction Stop
    }
}

. Press.Tasks

Task Press.CopyModuleFiles @{
    Inputs  = {
        Get-ChildItem -File -Recurse $PressSetting.General.SrcRootDir
        $SCRIPT:IncludeFiles = (
            (Get-ChildItem -File -Recurse "$($PressSetting.General.SrcRootDir)\SecretManagement.KeePass.Extension") |
                Resolve-Path
        )
        $IncludeFiles
    }
    Outputs = {
        $buildItems = Get-ChildItem -File -Recurse $PressSetting.Build.ModuleOutDir
        if ($buildItems) { $buildItems } else { 'EmptyBuildOutputFolder' }
    }
    Jobs    = {
        Remove-BuildItem $PressSetting.Build.ModuleOutDir

        $copyResult = Copy-PressModuleFiles @commonParams `
            -Destination $PressSetting.Build.ModuleOutDir `
            -PSModuleManifest $PressSetting.BuildEnvironment.PSModuleManifest

        $PressSetting.OutputModuleManifest = $copyResult.OutputModuleManifest
    }
}

Task CopyKeePassExtension -After Press.CopyModuleFiles {
    #KeePass Extension Files
    $KPExtensionPath = "$($PressSetting.General.SrcRootDir)\SecretManagement.KeePass.Extension"
    Copy-Item $KPExtensionPath -Recurse -Force -Exclude '*.Tests.ps1' -Destination $PressSetting.Build.ModuleOutDir -Container
    Remove-Item -Recurse -Force (Join-Path $PressSetting.Build.ModuleOutDir 'SecretManagement.KeePass.Extension/Tests')
}

Task CopyPoshKeePass -After Press.CopyModuleFiles {
    #KeePass Extension Files
    $PKPExtensionPath = "$($PressSetting.General.SrcRootDir)\PoshKeePass"
    Copy-Item $PKPExtensionPath -Recurse -Force -Exclude '*.Tests.ps1' -Destination $PressSetting.Build.ModuleOutDir -Container
}

Task Package Press.Package.Zip