function Test-DBChanged ($dbConnection) {
    [string]$currentDbFileHash = (Get-FileHash -Path $dbConnection.IOConnectionInfo.Path).Hash
    [byte[]]$dbHashBytes = $dbConnection.HashOfFileOnDisk

    #Convert to String
    [string]$dbHash = $dbHashBytes.foreach{[String]::Format('{0:X2}', $_)} -join ''


    #Return true or false
    $currentDbFileHash -ne $dbHash
}