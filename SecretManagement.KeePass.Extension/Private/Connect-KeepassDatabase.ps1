using namespace KeePassLib
using namespace KeePassLib.Keys
using namespace KeePassLib.Serialization
using namespace KeePassLib.Interfaces
using namespace System.Runtime.InteropServices

function Connect-KeePassDatabase {
    <#
    .SYNOPSIS
    Open a connection to a keepass database
    #>
    param (
        #Path to the Keepass database
        [String]$Path,
        #The master password to unlock the database
        [SecureString]$MasterPassword,
        #The path to the key file for the database
        [String]$KeyPath,
        #Whether to use a secure key stored via DPAPI in your windows profile
        [Switch]$UseWindowsAccount
    )

    $DBCompositeKey = [CompositeKey]::new()
    
    #NOTE: Order in which the CompositeKey is created is important and must follow the order of : MasterKey, KeyFile, Windows Account
    if ($MasterPassword) {
        $DBCompositeKey.AddUserKey(
            [KcpPassword]::new(
                #Decode SecureString
                [Marshal]::PtrToStringUni([Marshal]::SecureStringToBSTR($MasterPassword))
            )
        )
    }
    if ($KeyFile) {
        $DBCompositeKey.AddUserKey([KcpKeyFile]::new($KeyPath,$true))
    }
    if ($UseWindowsAccount) {
        if ($PSVersionTable.PSVersion -gt '5.0.0' -and -not $IsWindows) {
            throw [NotSupportedException]'The -UseWindowsAccount parameter is only supported on a Windows Platform'
        }
        $DBCompositeKey.AddUserKey([KcpUserAccount]::new())
    }

    #Establish the connection
    $DBConnection = [PWDatabase]::new()
    $DBConnection.Open(
        [IOConnectionInfo]::FromPath($Path),
        $DBCompositeKey,
        [NullStatusLogger]::new()
    )
    if (-not $DBConnection.IsOpen) {throw "Unable to connect to the database at $Path. Please check you supplied proper credentials"}
    $DBConnection
}