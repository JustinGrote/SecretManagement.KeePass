using namespace KeepassLib.Security
function Set-Secret {
    [CmdletBinding()]
    param (
        [string]$Name,
        [object]$Secret,
        [Alias('Vault')][string]$VaultName,
        [Alias('VaultParameters')][hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )
    trap {
        VaultError $PSItem
        throw $PSItem
    }
    if ($AdditionalParameters.Verbose) {$VerbosePreference = 'continue'}

    if (-not $Name) {throw [NotSupportedException]'The -Name parameter is mandatory for the KeePass vault'}
    if (-not (Test-SecretVault -VaultName $vaultName)) {
        throw throw 'There appears to be an issue with the vault (Test-SecretVault returned false)'
    }
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    if (Get-SecretInfo -Name $Name -Vault $VaultName) {
        Write-Warning "Vault ${VaultName}: A secret with the title $Name already exists. This vault currently does not support overwriting secrets. Please remove the secret with Remove-Secret first."
        return $false
    }

    #Set default group
    #TODO: Support Creating Secrets with paths
    $KeepassParams.KeePassGroup = (Get-Variable "VAULT_$VaultName").Value.RootGroup

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
            throw [NotImplementedException]'This vault provider only accepts string, securestring, and PSCredential secrets'
        }
    }

    $KPEntry = Add-KPEntry @KeepassParams -Title $Name -PassThru
    #Save the changes immediately
    #TODO: Consider making this optional as a vault parameter
    $KeepassParams.KeepassConnection.Save($null)
    
    return [Bool]($KPEntry)
}
