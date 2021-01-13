Install-Module Pester,Microsoft.Powershell.SecretManagement -Force -Scope CurrentUser
Write-Verbose "current location is $($PSScriptRoot)" -Verbose
Set-Location -Path "$($PSScriptRoot)/../../SecredManagement.Keepass.Extension/Tests"
$pesterResult = Invoke-Pester -Output Detailed -PassThru
if ($pesterResult.Result -ne 'Passed') {
    throw "There were $($pesterResult.FailedCount) failed tests."
}