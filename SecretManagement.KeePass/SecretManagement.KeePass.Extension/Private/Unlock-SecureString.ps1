function Unlock-SecureString ([SecureString]$SecureString) {
    <#
    .SYNOPSIS
    Compatibility function to convert a secure string to plain text
    .OUTPUT
    String
    #>
    if ($PSVersionTable.PSVersion -ge '6.0.0') {
        ConvertFrom-SecureString -AsPlainText -SecureString $SecureString
    } else {
        #Legacy Windows Powershell Workaround Method
        [PSCredential]::new('SecureString',$SecureString).GetNetworkCredential().Password
    }
}