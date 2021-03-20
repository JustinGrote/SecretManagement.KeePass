using namespace Microsoft.PowerShell.SecretManagement
using namespace System.Collections.ObjectModel
function Get-SecretInfo {
    [CmdletBinding()]
    param(
        [Alias('Name')][string]$Filter,
        [Alias('Vault')][string]$VaultName = (Get-SecretVault).VaultName,
        [Alias('VaultParameters')][hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters,
        [Switch]$AsKPPSObject
    )
    if ($AdditionalParameters.Verbose) {$VerbosePreference = 'continue'}
    trap {
        VaultError $PSItem
        throw $PSItem
    }
    if (-not (Test-SecretVault -VaultName $vaultName)) {
        throw 'There appears to be an issue with the vault (Test-SecretVault returned false)'
    }

    $KeepassParams = GetKeepassParams -VaultName $VaultName -AdditionalParameters $AdditionalParameters
    $KeepassGetResult = Get-KPEntry @KeepassParams | ConvertTo-KPPSObject
    if (-not $AdditionalParameters.ShowRecycleBin) {
        $KeepassGetResult = $KeepassGetResult | Where-Object FullPath -notmatch '^[^/]+?/Recycle ?Bin$'
    }

    #TODO: Split this off into private function for testing
    function Get-KPSecretName ([PSCustomObject]$KPPSObject) {
        <#
        .SYNOPSIS
        Gets the secret name for the vault context, contingent on some parameters
        WARNING: Relies on external context $AdditionalParameters
        #>
        if ($AdditionalParameters.ShowFullTitle) {
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

        [ReadOnlyDictionary[String,Object]]$metadata = [ordered]@{
            UUID = $PSItem.uuid.ToHexString()
            Title = $PSItem.Title
            ParentGroup = $PSItem.ParentGroup
            Path = $PSItem.FullPath,$PSItem.Title -join '/'
            Notes = $PSItem.Notes
            URL = $PSItem.Url
            Tags = $PSItem.Tags -join ', '
            Created = $PSItem.CreationTime
            Accessed = $PSItem.LastAccessTimeUtc
            Modified = $PSItem.LastModifiedTimeUtc
            Moved = $PSItem.LocationChanged
            IconName = $PSItem.IconId
            UsageCount = $PSItem.UsageCount
            Expires = if ($Expires) {$PSItem.ExpireTime}
        } | ConvertTo-ReadOnlyDictionary

        #TODO: Find out why the fully qualified is required on Linux even though using Namespace is defined above
        [Microsoft.PowerShell.SecretManagement.SecretInformation]::new(
            (Get-KPSecretName $PSItem), #string name
            #TODO: Add logic to mark as securestring if there is no username
            [Microsoft.PowerShell.SecretManagement.SecretType]::PSCredential, #SecretType type
            $VaultName, #string vaultName
            $metadata #ReadOnlyDictionary[string,object] metadata
        )
    }

    [Object[]]$sortedInfoResult = $secretInfoResult | Sort-Object -Unique -Property Name
    if ($sortedInfoResult.count -lt $secretInfoResult.count) {
        $nonUniqueFilteredRecords = Compare-Object $sortedInfoResult $secretInfoResult -Property Name | Where-Object SideIndicator -eq '=>'
        Write-Warning "Vault ${VaultName}: Entries with non-unique titles were detected, the duplicates were filtered out. $(if (-not $additionalParameters.ShowFullTitle) {'Consider adding the ShowFullTitle VaultParameter to your vault registration'})"
        Write-Warning "Vault ${VaultName}: Filtered Non-Unique Titles: $($nonUniqueFilteredRecords.Name -join ', ')"
    }
    $sortedInfoResult
}