if (-not (Get-Module Press -ErrorAction SilentlyContinue)) {
    Import-Module Press
}
. Press.Tasks

Task Press.CopyModuleFiles @{
    Inputs  = { 
        Get-ChildItem -File -Recurse $PressSetting.General.SrcRootDir
        $SCRIPT:IncludeFiles = (
            (Get-ChildItem -File -Recurse "$($PressSetting.General.SrcRootDir)\SecretManagement.KeePass.Extension")
            | Resolve-Path
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

        #KeePass Extension Files
        $KPExtensionPath = "$($PressSetting.General.SrcRootDir)\SecretManagement.KeePass.Extension"
        Copy-Item $KPExtensionPath -Recurse -Force -Exclude '*.Tests.ps1' -Destination $PressSetting.Build.ModuleOutDir -Container
        Remove-Item -Recurse -Force (Join-Path $PressSetting.Build.ModuleOutDir 'SecretManagement.KeePass.Extension/Tests')

        $PressSetting.OutputModuleManifest = $copyResult.OutputModuleManifest
    }
}

Task Package Press.Package.Zip