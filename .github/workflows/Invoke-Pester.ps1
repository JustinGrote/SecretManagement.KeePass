Install-Module Pester,Microsoft.Powershell.SecretManagement -Force -Scope CurrentUser
$pesterResult = Invoke-Pester -Output Detailed -PassThru
if ($pesterResult.Result -ne 'Passed') {
    throw "There were $($pesterResult.FailedCount) failed tests."
}