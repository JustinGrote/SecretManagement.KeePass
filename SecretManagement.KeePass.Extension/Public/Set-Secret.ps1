using namespace KeepassLib.Security
function Set-Secret {
    param (
        [string]$Name,
        [object]$Secret,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )

    if (-not $Name) {throw [NotSupportedException]'The -Name parameter is mandatory for the KeePass vault'}
    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    #Set default group
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
