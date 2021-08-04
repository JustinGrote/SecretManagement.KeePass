using namespace KeepassLib.Security
function Set-Secret {
    [CmdletBinding()]
    param (
        [string]$Name,
        [object]$Secret,
        [Alias('Vault')][string]$VaultName,
        [Alias('VaultParameters')][hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    if ($AdditionalParameters.Verbose) { $VerbosePreference = 'continue' }

    if (-not $Name) {
        Write-PSFMessage -Level Error ([NotSupportedException]'The -Name parameter is mandatory for the KeePass vault')
        return $false
    }
    if (-not (Test-SecretVault -VaultName $vaultName)) {
        Write-PSFMessage -Level Error 'There appears to be an issue with the vault (Test-SecretVault returned false)'
        return $false
    }
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    
    
    switch ($Secret.GetType()) {
        ([String]) {
            $KeepassParams.Username = $null
            $KeepassParams.KeepassPassword = [ProtectedString]::New($true, $Secret)
            break
        }
        ([SecureString]) {
            $KeepassParams.Username = $null
            $KeepassParams.KeepassPassword = [ProtectedString]::New($true, (Unlock-SecureString $Secret))
            break
        }
        ([PSCredential]) {
            $KeepassParams.Username = $Secret.Username
            $KeepassParams.KeepassPassword = [ProtectedString]::New($true, $Secret.GetNetworkCredential().Password)
            break
        }
        default {
            Write-PSFMessage -Level Error ([NotImplementedException]'This vault provider only accepts string, securestring, and PSCredential secrets')
            return $false
        }
    }
    
    if (Get-SecretInfo -Name $Name -Vault $VaultName) {
        Write-PSFMessage "Updating Keepass Entry" -Target $Name -Tag Update
        
        try {
            # $KeepassEntry = Get-SecretInfo -Name $Name -Vault $VaultName -AsKPPSObject
            # Need to get the original KPEntry Object for modification
            $KeepassParamsGetKPEntry = GetKeepassParams $VaultName $AdditionalParameters
            # ToDo Sherlock: Got an array but need just one Object
            $KeepassResults = Get-KPEntry @KeepassParamsGetKPEntry -Title $Name
            # $fullPathes = $KeepassResults|Foreach-Object {
            #     $path=$_.ParentGroup.GetFullPath('/', $true)
            #     $title = $_.Strings.ReadSafe('Title')
            #     "Title= $title; Fullpath= $Path;"
            # }
            # Write-PSFMessage -level Host -Tag Sherlock "fullPathes=$fullPathes"
            if ($KeepassResults.count -gt 1){
                Write-PSFMessage -Level Error "Retrieved $($KeepassResults.count) Keepass-Entries, narrow down the criteria"
                return
            }
            $KeepassEntry = $KeepassResults #[1]
            # $KeepassEntry = Get-KPEntry -KeePassConnection $KeepassParams.KeepassConnection -Title $Title
            Write-PSFMessage "Found KeepassEntry=$KeepassEntry" -Level Debug
            # Write-PSFMessage "`$KeepassEntry.getType()=$($KeepassEntry.GetType())" -tag "Sherlock"
        }
        catch {
            Write-PSFMessage -Level Error "Fehler bei Get-KPEntry, $_"  
        }
        # Write-PSFMessage -Level Warning "Vault ${VaultName}: A secret with the title $Name already exists. This vault currently does not support overwriting secrets. Please remove the secret with Remove-Secret first."
        # return $false
       
        $KPEntry = Set-KPEntry @KeepassParams -Title $Name -PassThru -KeePassEntry $KeepassEntry -Confirm:$False
        
        # Write-PSFMessage -Level Warning "Vault ${VaultName}: A secret with the title $Name already exists. This vault currently does not support overwriting secrets. Please remove the secret with Remove-Secret first."
        # return $false
    }
    else {
        #Set default group
        #TODO: Support Creating Secrets with paths
        Write-PSFMessage "Adding Keepass Entry" -Target $Name -Tag Add
        $KeepassParams.KeePassGroup = (Get-Variable "VAULT_$VaultName").Value.RootGroup
        $KPEntry = Add-KPEntry @KeepassParams -Title $Name -PassThru
    }
    
    #Save the changes immediately
    #TODO: Consider making this optional as a vault parameter
    $KeepassParams.KeepassConnection.Save($null)

    return [Bool]($KPEntry)
}
