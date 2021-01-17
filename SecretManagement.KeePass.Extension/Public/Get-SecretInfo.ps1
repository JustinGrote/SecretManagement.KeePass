using namespace Microsoft.PowerShell.SecretManagement
function Get-SecretInfo {
    param(
        [string]$Filter,
        [string]$VaultName = (Get-SecretVault).VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters,
        [Switch]$AsKPPSObject
    )
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}

    $KeepassParams = GetKeepassParams -VaultName $VaultName -AdditionalParameters $AdditionalParameters
    $KeepassGetResult = Get-KPEntry @KeepassParams | ConvertTo-KPPSObject
    if (-not $AdditionalParameters.ShowRecycleBin) {
        $KeepassGetResult = $KeepassGetResult | Where-Object FullPath -notmatch '^.+?/Recycle Bin'
    }

    #TODO: Split this off into private function for testing
    function Get-KPSecretName ([PSCustomObject]$KPPSObject) {
        <#
        .SYNOPSIS
        Gets the secret name for the vault context, contingent on some parameters
        WARNING: Relies on external context $AdditionalParameters
        #>
        if ($AdditionalParameters.ShowFullPath) {
            #Strip everything before the first /
            $i = $KPPSObject.FullPath.IndexOf('/')
            $prefix = if ($i -eq -1) {$null} else {
                $KPPSObject.FullPath.Substring($i+1)
            }
            #Output Prefix/Title
            if ($prefix) {
                return $prefix,$KPPSObject.Title -join '/'
            } else {
                return $KPPSObject.Title
            }
        } else {
            return $KPPSObject.Title
        }
    }

    if ($Filter) {
        $KeepassGetResult = $KeepassGetResult | Where-Object {
            (Get-KPSecretName $PSItem) -like $Filter
        } 
    }

    #Used by internal commands like Get-Secret
    if ($AsKPPSObject) {
        return $KeepassGetResult
    }

    [Object[]]$secretInfoResult = $KeepassGetResult | Foreach-Object {
        if (-not $PSItem.Title) {
            Write-Warning "Keepass Entry with blank title found at $($PSItem.FullPath). These are not currently supported and will be omitted"
            return
        }

        #TODO: Find out why the fully qualified is required on Linux even though using Namespace is defined above
        [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
            (Get-KPSecretName $PSItem), #string name
            #TODO: Add logic to mark as securestring if there is no username
            [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential, #SecretType type
            $VaultName #string vaultName
        )
    }

    [Object[]]$sortedInfoResult = $secretInfoResult | Sort-Object -Unique -Property Name
    if ($sortedInfoResult.count -lt $secretInfoResult.count) {
        $nonUniqueFilteredRecords = Compare-Object $sortedInfoResult $secretInfoResult -Property Name | Where-Object SideIndicator -eq '=>'
        Write-Warning "Vault ${VaultName}: Entries with non-unique titles were detected, the duplicates were filtered out. $(if (-not $additionalParameters.ShowFullPath) {'Consider adding the ShowFullPath VaultParameter to your vault registration'})"
        Write-Warning "Vault ${VaultName}: Filtered Non-Unique Titles: $($nonUniqueFilteredRecords.Name -join ', ')"
    }
    $sortedInfoResult
}