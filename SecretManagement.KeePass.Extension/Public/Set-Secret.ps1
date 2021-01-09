function Set-Secret {
    param (
        [string]$Name,
        [object]$Secret,
        [string]$VaultName,
        [hashtable]$AdditionalParameters = (Get-SecretVault -Name $VaultName).VaultParameters
    )

    if (-not (Test-SecretVault -VaultName $vaultName)) {throw "Vault ${VaultName}: Not a valid vault configuration"}
    $KeepassParams = GetKeepassParams $VaultName $AdditionalParameters

    #Set default group
    [String]$KeepassParams.KeePassEntryGroupPath = Get-KeePassGroup @KeepassParams | 
        Where-Object fullpath -NotMatch '/' | 
        ForEach-Object fullpath | 
        Select-Object -First 1

    switch ($Secret.GetType()) {
        ([String]) {
            $KeepassParams.Username = $null
            $KeepassParams.KeepassPassword = ConvertTo-SecureString -AsPlainText -Force $Secret
            break
        }
        ([SecureString]) {
            $KeepassParams.Username = $null
            $KeepassParams.KeepassPassword = $Secret
            break
        }
        ([PSCredential]) {
            $KeepassParams.Username = $Secret.Username
            $KeepassParams.KeepassPassword = $Secret.Password
            break
        }
        default {
            throw [NotImplementedException]'This vault provider only accepts string, securestring, and PSCredential secrets'
        }
    }

    return [Bool](New-KeePassEntry @KeepassParams -Title $Name -PassThru)
}
