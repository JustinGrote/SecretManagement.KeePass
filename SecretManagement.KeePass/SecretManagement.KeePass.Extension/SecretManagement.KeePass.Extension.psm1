
using namespace Microsoft.PowerShell.SecretManagement

Get-ChildItem "$PSScriptRoot/Private" -Exclude "*.Tests.ps1"  | Foreach-Object {
    . $PSItem.FullName
}
$publicFunctions = Get-ChildItem "$PSScriptRoot/Public" -Exclude "*.Tests.ps1"  | Foreach-Object {
    . $PSItem.FullName
    #Output the name of the function assuming it is the same as the .ps1 file so it can be exported
    $PSItem.BaseName
}

Export-ModuleMember $publicFunctions