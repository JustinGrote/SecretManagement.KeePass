
using namespace Microsoft.PowerShell.SecretManagement

#Avoid unpredictable behavior from external $ErrorActionPreference
$ErrorActionPreference = 'Stop'

Get-ChildItem "$PSScriptRoot/Private" | Foreach-Object {
    . $PSItem.FullName
}
$publicFunctions = Get-ChildItem "$PSScriptRoot/Public" | Foreach-Object {
    . $PSItem.FullName
    #Output the name of the function assuming it is the same as the .ps1 file so it can be exported
    $PSItem.BaseName
}

Export-ModuleMember $publicFunctionsgit 