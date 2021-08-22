function ConvertTo-KPPSObject
{
    <#
        .SYNOPSIS
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.
        .DESCRIPTION
            This Function will accept KeePass Entry Objects and Convert them to a Powershell Object for Ease of Use.

            It will get the Protected Strings from the database like, Title,UserName,Password,URL,Notes.

            It currently returns Most frequently used data about an entry and excludes extensive metadata such as-
            Foreground Color, Icon, ect.
        .EXAMPLE
            PS> ConvertTo-KPPsObject -KeePassEntry $Entry

            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .EXAMPLE
            PS> Get-KeePassEntry -KeePassonnection $DB -UserName "AUserName" | ConvertTo-KeePassPsObject

            This Example Converts one or more KeePass Entries to a defined Powershell Object.
        .PARAMETER KeePassEntry
            This is the one or more KeePass Entries to be converted.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Entry')]
    [OutputType([PSCustomObject])]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Entry')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry[]] $KeePassEntry,

        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup,

        [Parameter(Position = 1, ParameterSetName = 'Entry')]
        [switch] $WithCredential,

        [Parameter(Position = 2, ParameterSetName = 'Entry')]
        [switch] $AsPlainText,

        [Parameter(Position = 3, ValueFromPipelineByPropertyName)]
        [string] $DatabaseProfileName
    )
    process
    {
        if($PSCmdlet.ParameterSetName -eq 'Entry')
        {
            foreach ($_keepassItem in $KeePassEntry)
            {
                if($WithCredential)
                {
                    try
                    {
                        $SCRIPT:Credential = New-Object -TypeName PSCredential -ArgumentList @($_keepassItem.Strings.ReadSafe('UserName'), ($_keepassItem.Strings.ReadSafe('Password') | ConvertTo-SecureString -AsPlainText -Force -ea SilentlyContinue))
                    }
                    catch{}
                }

                if($AsPlainText)
                { $Password = $_keepassItem.Strings.ReadSafe('Password') }
                else
                { $Password = $_keepassItem.Strings.ReadSafe('Password') | ConvertTo-SecureString -AsPlainText -Force -ea SilentlyContinue }

                $KeePassPsObject = New-Object -TypeName PSObject -Property ([ordered]@{
                        'Uuid'                    = $_keepassItem.Uuid;
                        'CreationTime'            = $_keepassItem.CreationTime;
                        'Expires'                 = $_keepassItem.Expires;
                        'ExpireTime'              = $_keepassItem.ExpiryTime;
                        'LastAccessTimeUtc'       = $_keepassItem.LastAccessTime;
                        'LastModificationTimeUtc' = $_keepassItem.LastModificationTime;
                        'LocationChanged'         = $_keepassItem.LocationChanged;
                        'Tags'                    = $_keepassItem.Tags;
                        'Touched'                 = $_keepassItem.Touched;
                        'UsageCount'              = $_keepassItem.UsageCount;
                        'ParentGroup'             = $_keepassItem.ParentGroup.Name;
                        'FullPath'                = $_keepassItem.ParentGroup.GetFullPath('/', $true);
                        'Title'                   = $_keepassItem.Strings.ReadSafe('Title');
                        'UserName'                = $_keepassItem.Strings.ReadSafe('UserName');
                        'Password'                = $Password
                        'URL'                     = $_keepassItem.Strings.ReadSafe('URL');
                        'Notes'                   = $_keepassItem.Strings.ReadSafe('Notes');
                        'IconId'                  = $_keepassItem.IconId;
                        'Credential'              = $Credential;
                        'DatabaseProfileName'     = $DatabaseProfileName;
                        'KPEntry'                 = $_keepassItem;
                    })

                ## Custom Object Formatting and Type
                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Entry')

                $KeePassPsObject

                if($Password){ Remove-Variable -Name 'Password' }
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Group')
        {
            foreach ($_keepassItem in $KeePassGroup)
            {
                if($_keepassItem.ParentGroup.Name)
                { $FullPath = $_keepassItem.ParentGroup.GetFullPath('/', $true) }
                else
                { $FullPath = '' }

                $KeePassPsObject = New-Object -TypeName PSObject -Property ([ordered]@{
                        'Uuid'                    = $_keepassItem.Uuid;
                        'Name'                    = $_keepassItem.Name;
                        'CreationTime'            = $_keepassItem.CreationTime;
                        'Expires'                 = $_keepassItem.Expires;
                        'ExpireTime'              = $_keepassItem.ExpiryTime;
                        'LastAccessTimeUtc'       = $_keepassItem.LastAccessTime;
                        'LastModificationTimeUtc' = $_keepassItem.LastModificationTime;
                        'LocationChanged'         = $_keepassItem.LocationChanged;
                        'Notes'                   = $_keepassItem.Notes;
                        'Touched'                 = $_keepassItem.Touched;
                        'UsageCount'              = $_keepassItem.UsageCount;
                        'ParentGroup'             = $_keepassItem.ParentGroup.Name;
                        'FullPath'                = $_keepassItem.GetFullPath('/', $true);
                        'Groups'                  = $_keepassItem.Groups;
                        'EntryCount'              = $_keepassItem.Entries.Count;
                        'IconId'                  = $_keepassItem.IconId;
                        'DatabaseProfileName'     = $DatabaseProfileName;
                        'KPGroup'                 = $_keepassItem;
                    })

                ## Custom Object Formatting and Type
                $KeePassPsObject.PSObject.TypeNames.Insert(0, 'PSKeePass.Group')
                $PSKeePassGroupDisplaySet = 'Name', 'EntryCount', 'FullPath', 'IconId'
                $PSKeePassGroupDefaultPropertySet = New-Object -TypeName System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [String[]] $PSKeePassGroupDisplaySet)
                $PSKeePassGroupStandardMembers = [System.Management.Automation.PSMemberInfo[]] @($PSKeePassGroupDefaultPropertySet)

                $KeePassPsObject | Add-Member MemberSet PSStandardMembers $PSKeePassGroupStandardMembers

                $KeePassPsObject
            }
        }
    }
    end
    {
        if($SCRIPT:Credential){ Remove-Variable -Name 'Credential'  -Scope Script}
    }
}
function Get-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .DESCRIPTION
            Function to Retrieve a or all KeePass Database Configuration Profiles saved to the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to lookup.
        .EXAMPLE
            PS> Get-KeePassDatabaseConfiguration

            This Example will return all Database Configuration Profiles if any.
        .EXAMPLE
            PS> Get-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal'

            This Example returns the Database Configuration Profile with the name Personal.
        .INPUTS
            Strings
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding(DefaultParameterSetName = '__None')]
    param
    (
        [Parameter(Position = 0, ParameterSetName = '__Profile')]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1, ParameterSetName = '__DefaultDB')]
        [ValidateNotNullOrEmpty()]
        [Switch] $Default,

        [Parameter(Position = 2)]
        [Switch] $Stop
    )
    process
    {
        if(Test-Path -Path $SCRIPT:KeePassConfigurationFile)
        {
            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($SCRIPT:KeePassConfigurationFile)

            if($DatabaseProfileName)
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Name -ilike $DatabaseProfileName }
            }
            elseif($Default)
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Default -ieq 'true' }

                if($Stop -and -not $ProfileResults)
                {
                    throw 'Unable to find a default KeePass Configuration, please specify a database profile name or set a default profile.'
                }
            }
            else
            {
                $ProfileResults = $XML.Settings.DatabaseProfiles.Profile
            }

            if(-not $ProfileResults -and $Stop)
            {
                throw 'InvalidKeePassConfiguration : No KeePass Configuration has been created.'
            }

            foreach($ProfileResult in $ProfileResults)
            {
                $UseNetworkAccount = if($ProfileResult.UseNetworkAccount -eq 'True'){$true}else{$false}
                $UseMasterKey = if($ProfileResult.UseMasterKey -eq 'True'){$true}else{$false}
                $ProfileDefault = if($ProfileResult.Default -eq 'True'){$true}else{$false}

                [hashtable] $ProfileObject = [ordered]@{
                    'Name'               = $ProfileResult.Name;
                    'DatabasePath'       = $ProfileResult.DatabasePath;
                    'KeyPath'            = $ProfileResult.KeyPath;
                    'UseMasterKey'       = $UseMasterKey;
                    'UseNetworkAccount'  = $UseNetworkAccount;
                    'AuthenticationType' = $ProfileResult.AuthenticationType;
                    'Default'            = $ProfileDefault;
                }

                New-Object -TypeName PSObject -Property $ProfileObject
            }
        }
        else
        {
            Write-PSFMessage -Level Warning 'The specified KeePass Configuration does not exist.'
        }
    }
}
function Get-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to get keepass database entries.
        .DESCRIPTION
            This Function gets all keepass database entries or a specified group/folder subset if the -KeePassEntryGroupPath parameter is Specified.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the forward slash character '/'
        .PARAMETER AsPlainText
            Specify this parameter if you want the KeePass database entries to be returns in plain text objects.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER AsPSCredential
            Output Entry as an PSCredential Object
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -AsPlainText

            This Example will return all enties in plain text format from that keepass database that was saved to the config with the name TEST.
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General' -AsPlainText

            This Example will return all entries in plain text format from the General folder of the keepass database with the profile name TEST.
        .EXAMPLE
            PS> Get-KeePassEntry -DatabaseProfileName TEST -Title test -AsPSCredential

            This Example will return one entry as PSCredential Object
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 1, ValueFromPipelineByPropertyName)]
        [String] $Title,

        [Parameter(Position = 2)]
        [string] $UserName,

        [Parameter(Position = 3)]
        [Switch] $AsPlainText,

        [Parameter(Position = 4)]
        [Alias('AsPSCredential')]
        [Switch] $WithCredential,

        [Parameter(Position = 5, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        $MasterKey = $null

        [hashtable] $params = @{
            'KeePassConnection' = $KeePassConnectionObject;
        }

        if($KeePassEntryGroupPath)
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath -Stop

            $params.KeePassGroup = $KeePassGroup
        }

        if($Title){ $params.Title = $Title }

        if($UserName){ $params.UserName = $UserName }

        Get-KPEntry @params | ConvertTo-KpPsObject -AsPlainText:$AsPlainText -WithCredential:$WithCredential -DatabaseProfileName $DatabaseProfileName
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
function Get-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to get keepass database entries.
        .DESCRIPTION
            This Funciton gets all keepass database entries or a specified group/folder subset if the -KeePassEntryGroupPath parameter is Specified.
        .PARAMETER KeePassGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER AsPlainText
            Specify this parameter if you want the KeePass database entries to be returns in plain text objects.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName TEST -AsPlainText

            This Example will return all groups in plain text format from that keepass database that was saved to the config with the name TEST.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName TEST -KeePassGroupPath 'General' -AsPlainText

            This Example will return all groups in plain text format from the General folder of the keepass database with the profile name TEST.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassGroupPath,

        [Parameter(Position = 1)]
        [Switch] $AsPlainText,

        [Parameter(Position = 2, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
        if($AsPlainText)
        { Write-PSFMessage -Level Warning -Message 'The -AsPlainText switch parameter is deprecated and will be removed by end of year 2018!' }
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        $MasterKey = $null

        [hashtable] $getKpGroupSplat = @{
            'KeePassConnection' = $KeePassConnectionObject
        }

        if($KeePassGroupPath)
        { $getKpGroupSplat.FullPath = $KeePassGroupPath }

        Get-KPGroup @getKpGroupSplat | ConvertTo-KpPsObject -DatabaseProfileName $DatabaseProfileName
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}


function New-KeePassDatabase
{
    <#
        .SYNOPSIS
            Function to create a keepass database.
        .DESCRIPTION
            This function creates a new keepass database
        .PARAMETER DatabasePath
            Path to the Keepass database (.kdbx file)
        .PARAMETER KeyPath
            Not yet implemented
        .PARAMETER MasterKey
            The masterkey that provides access to the database
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabasePath,

        [String] $KeyPath,

        [Switch] $UseWindowsAccount,

        [PSCredential] $MasterKey
    )
    begin
    {
    }
    process
    {
        if(Test-Path -Path $DatabasePath)
        {
            throw ('The specified Database Path already exists: {0}.' -f $DatabasePath)
        }
        else
        {
            try
            {
                $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
            }
            catch
            {
                Import-KPLibrary
                $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
            }

            $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey

            if($MasterKey)
            {
                $KcpPassword = New-Object -TypeName KeePassLib.Keys.KcpPassword($MasterKey.GetNetworkCredential().Password)
                $CompositeKey.AddUserKey($KcpPassword)
            }

            if($UseNetworkAccount)
            {
                $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
            }

            if($keyPath)
            {
                $CompositeKey.AddUserKey([KeepassLib.Keys.KcpKeyFile]::new($keyPath,$true))
            }

            $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
            $IOInfo.Path = $DatabasePath

            $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

            $DatabaseObject.New($IOInfo, $CompositeKey) | Out-Null
            $DatabaseObject.Save($IStatusLogger)
        }
    }
}
function New-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to Create or Add a new KeePass Database Configuration Profile to the KeePassConfiguration.xml
        .DESCRIPTION
            The Profile Created will be accessible from the core functions Get,Update,New,Remove KeePassEntry and ect.
            The Profile stores database configuration for opening and authenticating to a keepass database.
            Using the configuration allows for speedier authentication and less complex commands.
        .PARAMETER DatabaseProfileName
            Specify the Name of the new Database Configuration Profile.
        .PARAMETER DatabasePath
            Specify the Path to the database (.kdbx) file.
        .PARAMETER KeyPath
            Specify the Path to the database (.key) key file if there is one.
        .PARAMETER UseMasterKey
            Specify this flag if the database uses a Master Key Password for Authentication.
        .PARAMETER PassThru
            Specify to return the new database configuration profile object.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -KeyPath 'c:\users\username\documents\personal.key' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Key File and Uses NetworkAccount.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Uses NetworkAccount.
        .NOTES
            1. Currently all authentication combinations are supported except keyfile, masterkey password, and network authentication together.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Key')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Network')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $DatabasePath,

        [Parameter(Position = 2, Mandatory, ParameterSetName = 'Key')]
        [Parameter(Position = 2, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        # [Parameter(Position = 3, ParameterSetName = 'Key')]
        # [Parameter(Position = 3, ParameterSetName = 'Master')]
        # [Parameter(Position = 3, ParameterSetName = 'Network')]
        # [Switch] $UseNetworkAccount,

        [Parameter(Position = 4, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 4, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [Switch] $UseMasterKey,

        [Parameter(Position = 5)]
        [Switch] $Default,

        [Parameter(Position = 6)]
        [Switch] $PassThru
    )
    begin
    {
        if($PSCmdlet.ParameterSetName -eq 'Network' -and -not $UseNetworkAccount)
        {
            Write-PSFMessage -Level Warning -Message '[BEGIN] Please Specify a valid Credential Combination.'
            Write-PSFMessage -Level Warning -Message '[BEGIN] You can not have a only a database file with no authentication options.'
            Throw 'Please Specify a valid Credential Combination.'
        }
    }
    process
    {
        if (-not (Test-Path -Path $SCRIPT:KeePassConfigurationFile))
        {
            Write-PSFMessage -Level Verbose -Message '[PROCESS] A KeePass Configuration File does not exist. One will be generated now.'
            New-KPConfigurationFile
        }
        else
        {
            $CheckIfProfileExists = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
        }

        if($CheckIfProfileExists)
        {
            Write-PSFMessage -Level Warning -Message ('[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: {0}.' -f $DatabaseProfileName)
            Throw '[PROCESS] A KeePass Database Configuration Profile Already exists with the specified name: {0}.' -f $DatabaseProfileName
        }
        else
        {
            try
            {
                if($Default)
                {
                    $defaultProfile = Get-KeePassDatabaseConfiguration -Default

                    if($defaultProfile)
                    {
                        throw ('{0} profile is already set to the default, if you would like to overwrite it as the default please use the Update-KeePassDatabaseConfiguration function and remove the default flag.' -f $defaultProfile.Name)
                    }
                }

                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($SCRIPT:KeePassConfigurationFile)
                ## Create New Profile Element with Name of the new profile
                $DatabaseProfile = $XML.CreateElement('Profile')
                $DatabaseProfileAtribute = $XML.CreateAttribute('Name')
                $DatabaseProfileAtribute.Value = $DatabaseProfileName
                $DatabaseProfile.Attributes.Append($DatabaseProfileAtribute) | Out-Null

                ## Build and Add Element Nodes
                $DatabasePathNode = $XML.CreateNode('element', 'DatabasePath', '')
                $DatabasePathNode.InnerText = $DatabasePath
                $DatabaseProfile.AppendChild($DatabasePathNode) | Out-Null

                $KeyPathNode = $XML.CreateNode('element', 'KeyPath', '')
                $KeyPathNode.InnerText = $KeyPath
                $DatabaseProfile.AppendChild($KeyPathNode) | Out-Null

                $UseNetworkAccountNode = $XML.CreateNode('element', 'UseNetworkAccount', '')
                $UseNetworkAccountNode.InnerText = $UseNetworkAccount
                $DatabaseProfile.AppendChild($UseNetworkAccountNode) | Out-Null

                $UseMasterKeyNode = $XML.CreateNode('element', 'UseMasterKey', '')
                $UseMasterKeyNode.InnerText = $UseMasterKey
                $DatabaseProfile.AppendChild($UseMasterKeyNode) | Out-Null

                $AuthenticationTypeNode = $XML.CreateNode('element', 'AuthenticationType', '')
                $AuthenticationTypeNode.InnerText = $PSCmdlet.ParameterSetName
                $DatabaseProfile.AppendChild($AuthenticationTypeNode) | Out-Null

                $DefaultNode = $XML.CreateNode('element', 'Default', '')
                $DefaultNode.InnerText = $Default
                $DatabaseProfile.AppendChild($DefaultNode) | Out-Null

                $XML.SelectSingleNode('/Settings/DatabaseProfiles').AppendChild($DatabaseProfile) | Out-Null

                $XML.Save($SCRIPT:KeePassConfigurationFile)

                $Script:KeePassProfileNames = (Get-KeePassDatabaseConfiguration).Name

                if($PassThru)
                {
                    Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
                }
            }
            catch
            {
                Write-PSFMessage -Level Warning -Message ('[PROCESS] An Exception Occured while trying to add a new KeePass database configuration ({0}) to the configuration file.' -f $DatabaseProfileName)
                Write-PSFMessage -Level Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}
function New-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to create a new KeePass Database Entry.
        .DESCRIPTION
            This function allows for the creation of KeePass Database Entries with basic properites available for specification.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER Title
            Specify the Title of the new KeePass Database Entry.
        .PARAMETER UserName
            Specify the UserName of the new KeePass Database Entry.
        .PARAMETER KeePassPassword
            *Specify the KeePassPassword of the new KeePass Database Entry.
            *Notes:
                *This Must be of the type SecureString or KeePassLib.Security.ProtectedString
        .PARAMETER Notes
            Specify the Notes of the new KeePass Database Entry.
        .PARAMETER URL
            Specify the URL of the new KeePass Database Entry.
        .PARAMETER PassThru
            Specify to return the newly created keepass database entry.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -upper -lower -digits -length 20)

            This example creates a new keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword is used to generated a random password with the specified options.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -PasswordProfileName 'Default' )

            This example creates a new keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword with a password profile specifed to create a new password genereated from options saved to a profile.
        .EXAMPLE
            PS> New-KeePassEntry -DatabaseProfileName TEST -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(ConvertTo-SecureString -String 'apassword' -AsPlainText -Force)

            This example creates a new keepass database entry with the specified Title, UserName and manually specified password converted to a securestring.
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 2)]
        [String] $UserName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.GetType().Name -eq 'ProtectedString' -or $_.GetType().Name -eq 'SecureString'})]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String] $URL,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName = 'Key',

        [Parameter(Position = 7)]
        [switch] $Expires,

        [Parameter(Position = 8)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 9, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 10)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 11)]
        [Switch] $PassThru
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        $MasterKey = $null

        try
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath -Stop

            $addKpEntrySplat = @{
                URL               = $URL
                UserName          = $UserName
                IconName          = $IconName
                KeePassGroup      = $KeePassGroup
                KeePassPassword   = $KeePassPassword
                PassThru          = $PassThru
                Title             = $Title
                KeePassConnection = $KeePassConnectionObject
                Notes             = $Notes
            }

            if(Test-Bound -ParameterName 'Expires'){ $addKpEntrySplat.Expires = $Expires }
            if($ExpiryTime){ $addKpEntrySplat.ExpiryTime = $ExpiryTime }

            Add-KpEntry @addKpEntrySplat | ConvertTo-KPPSObject -DatabaseProfileName $DatabaseProfileName
        }
        catch
        { Throw $_ }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
function New-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to create a new KeePass Database Entry.
        .DESCRIPTION
            This function allows for the creation of KeePass Database Entries with basic properites available for specification.
        .PARAMETER KeePassParentGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER KeePassGroupName
            Specify the Name of the new KeePass Group.
        .PARAMETER PassThru
            Specify to return the new group object.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> New-KeePassGroup -DatabaseProfileName TEST -KeePassParentGroupPath 'General/TestAccounts' -KeePassGroupName 'TestGroup'

            This Example Creates a Group Called 'TestGroup' in the Group Path 'General/TestAccounts'
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassGroupParentPath,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $KeePassGroupName,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName = 'Folder',

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 4)]
        [switch] $Expires,

        [Parameter(Position = 5)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 6, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 8)]
        [Switch] $PassThru
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        $MasterKey = $null

        $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroupParentPath -Stop

        $addKPGroupSplat = @{
            KeePassConnection  = $KeePassConnectionObject
            GroupName          = $KeePassGroupName
            IconName           = $IconName
            PassThru           = $PassThru
            KeePassParentGroup = $KeePassParentGroup
            Notes              = $Notes
        }

        # if($Notes){ $addKPGroupSplat.Notes = $Notes }
        if(Test-Bound -ParameterName 'Expires'){ $addKPGroupSplat.Expires = $Expires }
        if($ExpiryTime){ $addKPGroupSplat.ExpiryTime = $ExpiryTime }

        Add-KPGroup @addKPGroupSplat | ConvertTo-KpPsObject -DatabaseProfileName $DatabaseProfileName
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
function New-KeePassPassword
{
    <#
        .SYNOPSIS
            This Function will Generate a New Password.
        .DESCRIPTION
            This Function will Generate a New Password with the Specified rules using the KeePass-
            Password Generator.

            This Contains the Majority of the Options including the advanced options that the KeePass-
            UI provides in its "PasswordGenerator Form".

            Currently this function does not support the use of previously saved/created Password Profiles-
            aka KeePassLib.Security.PasswordGenerator.PwProfile. Nore does it support Saving a New Profile.

            This Simply Applies the Rules specified and generates a new password that is returned in the form-
            of a KeePassLib.Security.ProtectedString.
        .EXAMPLE
            PS> New-KeePassPassword

            This Example will generate a Password using the Default KeePass Password Profile.
            Which is is -UpperCase -LowerCase -Digites -Length 20
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -Length 20

            This Example will generate a 20 character password that contains Upper and Lower case letters ans numbers 0-9
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -Length 20 -SaveAs 'Basic Password'

            This Example will generate a 20 character password that contains Upper and Lower case letters ans numbers 0-9.
            Then it will save it as a password profile with the bane 'Basic Password' for future reuse.
        .EXAMPLE
            PS> New-KeePassPassword -PasswordProfileName 'Basic Password'

            This Example will generate a password using the password profile name Basic Password.
        .EXAMPLE
            PS> New-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -ExcludeCharacters '"' -Length 20

            This Example will generate a Password with the Specified Options and Exclude the Double Quote Character
        .PARAMETER UpperCase
            If Specified it will add UpperCase Letters to the character set used to generate the password.
        .PARAMETER LowerCase
            If Specified it will add LowerCase Letters to the character set used to generate the password.
        .PARAMETER Digits
            If Specified it will add Digits to the character set used to generate the password.
        .PARAMETER SpecialCharacters
            If Specified it will add Special Characters '!"#$%&''*+,./:;=?@\^`|~' to the character set used to generate the password.
        .PARAMETER Minus
            If Specified it will add the Minus Symbol '-' to the character set used to generate the password.
        .PARAMETER UnderScore
            If Specified it will add the UnderScore Symbol '_' to the character set used to generate the password.
        .PARAMETER Space
            If Specified it will add the Space Character ' ' to the character set used to generate the password.
        .PARAMETER Brackets
            If Specified it will add Bracket Characters '()<>[]{}' to the character set used to generate the password.
        .PARAMETER ExcludeLookAlike
            If Specified it will exclude Characters that Look Similar from the character set used to generate the password.
        .PARAMETER NoRepeatingCharacters
            If Specified it will only allow Characters exist once in the password that is returned.
        .PARAMETER ExcludeCharacters
            This will take a list of characters to Exclude, and remove them from the character set used to generate the password.
        .PARAMETER Length
            This will specify the length of the resulting password. If not used it will use KeePass's Default Password Profile
            Length Value which I believe is 20.
        .PARAMETER SaveAS
            Specify the name in which you wish to save the password configuration as.
            This will save all specified settings the KeePassConfiguration.xml file, which can then be specifed later when genreating a password to match the same settings.
        .PARAMETER PasswordProfileName
            *Specify this parameter to use a previously saved password profile to genreate a password.
            *Note:
                *This supports Tab completion as it will get all saved profiles.
        .INPUTS
            String
            Switch
        .OUTPUTS
            KeePassLib.Security.ProtectedString
    #>
    [CmdletBinding(DefaultParameterSetName = 'NoProfile')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "PasswordProfileName")]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Profile')]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName,

        [Parameter(Position = 0, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $UpperCase,

        [Parameter(Position = 1, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $LowerCase,

        [Parameter(Position = 2, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Digits,

        [Parameter(Position = 3, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $SpecialCharacters,

        [Parameter(Position = 4, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Minus,

        [Parameter(Position = 5, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $UnderScore,

        [Parameter(Position = 6, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Space,

        [Parameter(Position = 7, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $Brackets,

        [Parameter(Position = 8, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $ExcludeLookALike,

        [Parameter(Position = 9, ParameterSetName = 'NoProfile')]
        [ValidateNotNull()]
        [Switch] $NoRepeatingCharacters,

        [Parameter(Position = 10, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $ExcludeCharacters,

        [Parameter(Position = 11, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [Int] $Length,

        [Parameter(Position = 12, ParameterSetName = 'NoProfile')]
        [ValidateNotNullOrEmpty()]
        [String] $SaveAs
    )
    begin
    {
    }
    process
    {
        ## Create New Password Profile.
        $PassProfile = New-Object KeePassLib.Cryptography.PasswordGenerator.PwProfile

        if($PSCmdlet.ParameterSetName -eq 'NoProfile')
        {
            $NewProfileObject = '' | Select-Object ProfileName, CharacterSet, ExcludeLookAlike, NoRepeatingCharacters, ExcludeCharacters, Length
            if($PSBoundParameters.Count -gt 0)
            {
                $PassProfile.CharSet = New-Object KeePassLib.Cryptography.PasswordGenerator.PwCharSet

                if($UpperCase)
                {
                    $NewProfileObject.CharacterSet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                }

                if($LowerCase)
                {
                    $NewProfileObject.CharacterSet += 'abcdefghijklmnopqrstuvwxyz'
                }

                if($Digits)
                {
                    $NewProfileObject.CharacterSet += '0123456789'
                }

                if($SpecialCharacters)
                {
                    $NewProfileObject.CharacterSet += '!"#$%&''*+,./:;=?@\^`|~'
                }

                if($Minus)
                {
                    $NewProfileObject.CharacterSet += '-'
                }

                if($UnderScore)
                {
                    $NewProfileObject.CharacterSet += '_'
                }

                if($Space)
                {
                    $NewProfileObject.CharacterSet += ' '
                }

                if($Brackets)
                {
                    $NewProfileObject.CharacterSet += '[]{}()<>'
                }

                if($ExcludeLookALike)
                {
                    $NewProfileObject.ExcludeLookAlike = $true
                }
                else
                {
                    $NewProfileObject.ExcludeLookAlike = $false
                }

                if($NoRepeatingCharacters)
                {
                    $NewProfileObject.NoRepeatingCharacters = $true
                }
                else
                {
                    $NewProfileObject.NoRepeatingCharacters = $false
                }

                if($ExcludeCharacters)
                {
                    $NewProfileObject.ExcludeCharacters = $ExcludeCharacters
                }
                else
                {
                    $NewProfileObject.ExcludeCharacters = ''
                }

                if($Length)
                {
                    $NewProfileObject.Length = $Length
                }
                else
                {
                    $NewProfileObject.Length = '20'
                }

                $PassProfile.CharSet.Add($NewProfileObject.CharacterSet)
                $PassProfile.ExcludeLookAlike = $NewProfileObject.ExlcudeLookAlike
                $PassProfile.NoRepeatingCharacters = $NewProfileObject.NoRepeatingCharacters
                $PassProfile.ExcludeCharacters = $NewProfileObject.ExcludeCharacters
                $PassProfile.Length = $NewProfileObject.Length
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'Profile')
        {
            $PasswordProfileObject = Get-KPPasswordProfile -PasswordProfileName $PasswordProfileName

            if(-not $PasswordProfileObject)
            {
                Write-PSFMessage -Level Error -Message ('No KPPasswordProfile could be found with the specified Name: ' + $PasswordProfileName) -TargetObject $PasswordProfileName -Category ObjectNotFound -ErrorAction Stop
            }

            $PassProfile.CharSet.Add($PasswordProfileObject.CharacterSet)
            $PassProfile.ExcludeLookAlike = if($PasswordProfileObject.ExlcudeLookAlike -eq 'True'){$true}else{$false}
            $PassProfile.NoRepeatingCharacters = if($PasswordProfileObject.NoRepeatingCharacters -eq 'True'){$true}else{$false}
            $PassProfile.ExcludeCharacters = $PasswordProfileObject.ExcludeCharacters
            $PassProfile.Length = $PasswordProfileObject.Length
        }

        ## Create Pass Generator Profile Pool.
        $GenPassPool = New-Object KeePassLib.Cryptography.PasswordGenerator.CustomPwGeneratorPool
        ## Create Out Parameter aka [rel] param.
        [KeePassLib.Security.ProtectedString]$PSOut = New-Object KeePassLib.Security.ProtectedString
        ## Generate Password.
        $ResultMessage = [KeePassLib.Cryptography.PasswordGenerator.PwGenerator]::Generate([ref] $PSOut, $PassProfile, $null, $GenPassPool)
        ## Check if Password Generation was successful
        if($ResultMessage -ne 'Success')
        {
            Write-PSFMessage -Level Warning -Message '[PROCESS] Failure while attempting to generate a password with the specified settings or profile.'
            Write-PSFMessage -Level Warning -Message ('[PROCESS] Password Generation Failed with the Result Text: {0}.' -f $ResultMessage)
            if($ResultMessage -eq 'TooFewCharacters')
            {
                Write-PSFMessage -Level Warning -Message ('[PROCESS] Result Text {0}, typically means that you specified a length that is longer than the possible generated outcome.' -f $ResultMessage)
                $ExcludeCharacterCount = if($PassProfile.ExcludeCharacters){($PassProfile.ExcludeCharacters -split ',').Count}else{0}
                if($PassProfile.NoRepeatingCharacters -and $PassProfile.Length -gt ($PassProfile.CharSet.Size - $ExcludeCharacterCount))
                {
                    Write-PSFMessage -Level Warning -Message "[PROCESS] Checked for the invalid specification. `n`tSpecified Length: $($PassProfile.Length). `n`tCharacterSet Count: $($PassProfile.CharSet.Size). `n`tNo Repeating Characters is set to: $($PassProfile.NoRepeatingCharacters). `n`tExclude Character Count: $ExcludeCharacterCount."
                    Write-PSFMessage -Level Warning -Message '[PROCESS] Specify More characters, shorten the length, remove the no repeating characters option, or removed excluded characters.'
                }
            }

            Throw 'Unabled to generate a password with the specified options.'
        }
        else
        {
            if($SaveAs)
            {
                $NewProfileObject.ProfileName = $SaveAs
                New-KPPasswordProfile -KeePassPasswordObject $NewProfileObject
            }
        }

        try
        {
            $PSOut
        }
        catch
        {
            Write-PSFMessage -Level Warning -Message '[PROCESS] An exception occured while trying to convert the KeePassLib.Securtiy.ProtectedString to a SecureString.'
            Write-PSFMessage -Level Warning -Message ('[PROCESS] Exception Message: {0}' -f $_.Exception.Message)
            Throw $_
        }
    }
    end
    {
        if($PSOut){$PSOUT = $null}
    }
}
function Remove-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Configuration Profile.
        .DESCRIPTION
            This function allows a specified database configuration profile to be removed from the KeePassConfiguration.xml file.
        .PARAMETER DatabaseProfileName
            Specify the name of the profile to be deleted.
        .EXAMPLE
            PS> Remove-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal'

            This Example will remove the database configuration profile 'Personal' from the KeePassConfiguration.xml file.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name')]
        [string] $DatabaseProfileName
    )
    begin
    {
    }
    process
    {
        if($PSCmdlet.ShouldProcess($DatabaseProfileName))
        {
            try
            {
                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($SCRIPT:KeePassConfigurationFile)
                $XML.Settings.DatabaseProfiles.Profile | Where-Object { $_.Name -eq $DatabaseProfileName } | ForEach-Object { $xml.Settings.DatabaseProfiles.RemoveChild($_) } | Out-Null
                $XML.Save($SCRIPT:KeePassConfigurationFile)
            }
            catch
            {
                Write-PSFMessage -Level Warning -Message ('[PROCESS] An exception occured while attempting to remove a KeePass Database Configuration Profile ({0}).' -f $DatabaseProfileName)
                Write-PSFMessage -Level Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}
function Remove-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Entry.
        .DESCRIPTION
            This function removed a KeePass Database Entry.
        .PARAMETER KeePassEntry
            The KeePass Entry to be removed. Use the Get-KeePassEntry function to get this object.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER NoRecycle
            Specify this option to Permanently delete the entry and not recycle it.
        .PARAMETER Force
            Specify this option to forcefully delete the entry.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Remove-KeePassEntry -KeePassEntry $KeePassEntryObject

            This example removed the specified kee pass entry.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

        [Parameter(Position = 1)]
        [Switch] $NoRecycle,

        [Parameter(Position = 2)]
        [Switch] $Force,

        [Parameter(Position = 3, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        $MasterKey = $null

        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        if(-not $KPEntry)
        {
            Write-PSFMessage -Level Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }

        $EntryDisplayName = '{0}/{1}' -f $KPEntry.ParentGroup.GetFullPath('/', $true), $KPEntry.Strings.ReadSafe('Title')
        if($Force -or $PSCmdlet.ShouldProcess($EntryDisplayName))
        {
            [hashtable] $params = @{
                'KeePassConnection' = $KeePassConnectionObject;
                'KeePassEntry'      = $KPEntry;
                'Confirm'           = $false;
                'Force'             = $Force;
            }

            if($NoRecycle){ $params.NoRecycle = $NoRecycle }
            Remove-KPEntry @params
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
function Remove-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Database Group.
        .DESCRIPTION
            This function removed a KeePass Database Group.
        .PARAMETER KeePassGroup
            The KeePass Group to be removed. Use the Get-KeePassEntry function to get this object.
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER NoRecycle
            Specify this option to Permanently delete the Group and not recycle it.
        .PARAMETER Force
            Specify this option to forcefully delete the Group.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .EXAMPLE
            PS> Remove-KeePassGroup -KeePassGroup $KeePassGroupObject

            This example removed the specified keepass Group.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassGroup,

        [Parameter(Position = 1)]
        [Switch] $NoRecycle,

        [Parameter(Position = 2)]
        [Switch] $Force,

        [Parameter(Position = 3, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        $MasterKey = $null

        $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroup.FullPath -Stop | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime}

        if($KeePassGroupObject.Count -gt 1)
        {
            Write-PSFMessage -Level Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Removal.'
            Write-PSFMessage -Level Warning -Message ('[PROCESS] Found: ({0}) number of matching groups.' -f $KeePassGroupObject.Count)
            Throw 'Found more than one group with the same path, name and creation time. Stoping Removal.'
        }

        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroup.FullPath))
        {
            if(-not $NoRecycle)
            {
                Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -Confirm:$false -Force
            }
            else
            {
                if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Remove this Group permanetly: $KeePassGroup.FullPath?"))
                {
                    Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject -NoRecycle:$NoRecycle -Confirm:$false -Force
                }
            }
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
function Update-KeePassDatabaseConfiguration
{
    <#
        .SYNOPSIS
            Function to Update a KeePass Database Configuration Profile in the KeePassConfiguration.xml
        .DESCRIPTION
            The Profile Created will be accessible from the core functions Get,Update,New,Remove KeePassEntry and ect.
            The Profile stores database configuration for opening and authenticating to a keepass database.
            Using the configuration allows for speedier authentication and less complex commands.
        .PARAMETER DatabaseProfileName
            Specify the Name of the new Database Configuration Profile.
        .PARAMETER DatabasePath
            Specify the Path to the database (.kdbx) file.
        .PARAMETER KeyPath
            Specify the Path to the database (.key) key file if there is one.
        .PARAMETER UseNetworkAccount
            Specify this flag if the database uses NetworkAccount Authentication.
        .PARAMETER UseMasterKey
            Specify this flag if the database uses a Master Key Password for Authentication.
        .PARAMETER PassThru
            Specify to return the new database configuration profile object.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -KeyPath 'c:\users\username\documents\personal.key' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Key File and Uses NetworkAccount.
        .EXAMPLE
            PS> New-KeePassDatabaseConfiguration -DatabaseProfileName 'Personal' -DatabasePath 'c:\users\username\documents\personal.kdbx' -UseNetworkAccount

            This Example adds a Database Configuration Profile to the KeePassConfiguration.xml file with the Name Personal specifying the database file and authentication components; Uses NetworkAccount.
        .NOTES
            1. Currently all authentication combinations are supported except keyfile, masterkey password, and network authentication together.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(DefaultParameterSetName = '_none')]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String] $NewDatabaseProfileName = $DatabaseProfileName,

        [Parameter(Position = 2, ParameterSetName = 'Key')]
        [Parameter(Position = 2, ParameterSetName = 'Master')]
        [Parameter(Position = 2, ParameterSetName = 'Network')]
        [Parameter(Position = 2, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $DatabasePath,

        [Parameter(Position = 2, ParameterSetName = 'Key')]
        [Parameter(Position = 2, ParameterSetName = 'KeyAndMaster')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [String] $KeyPath,

        [Parameter(Position = 4, ParameterSetName = 'Key')]
        [Parameter(Position = 4, ParameterSetName = 'Master')]
        [Parameter(Position = 4, ParameterSetName = 'Network')]
        [Switch] $UseNetworkAccount,

        [Parameter(Position = 5, Mandatory, ParameterSetName = 'Master')]
        [Parameter(Position = 5, Mandatory, ParameterSetName = 'KeyAndMaster')]
        [Switch] $UseMasterKey,

        [Parameter(Position = 6)]
        [Switch] $Default,

        [Parameter(Position = 7)]
        [Switch] $PassThru
    )
    begin
    {
        if($PSCmdlet.ParameterSetName -eq 'Network' -and -not $UseNetworkAccount)
        {
            Write-PSFMessage -Level Warning -Message '[BEGIN] Please Specify a valid Credential Combination.'
            Write-PSFMessage -Level Warning -Message '[BEGIN] You can not have only a database file with no authentication options.'
            throw 'Please Specify a valid Credential Combination.'
        }
    }
    process
    {
        # throw 'Update-KeePassDatabaseConfiguration not yet implemented.'

        if (-not (Test-Path -Path $SCRIPT:KeePassConfigurationFile))
        {
            Write-PSFMessage -Level Verbose -Message '[PROCESS] A KeePass Configuration File does not exist. One will be generated now.'
            New-KPConfigurationFile
        }
        else
        {
            $CheckIfProfileExists = Get-KeePassDatabaseConfiguration -DatabaseProfileName $DatabaseProfileName
        }

        if(-not $CheckIfProfileExists)
        {
            Write-PSFMessage -Level Warning -Message ('[PROCESS] A KeePass Database Configuration Profile does not exists with the specified name: {0}.' -f $DatabaseProfileName)
            throw '[PROCESS] A KeePass Database Configuration Profile does not exists with the specified name: {0}.' -f $DatabaseProfileName
        }
        else
        {
            if($Default)
            {
                $defaultProfile = Get-KeePassDatabaseConfiguration -Default

                if($defaultProfile -and $defaultProfile.Name -ine $DatabaseProfileName)
                {
                    throw ('{0} profile is already set to the default, if you would like to overwrite it as the default please use the Update-KeePassDatabaseConfiguration function and remove the default flag.' -f $defaultProfile.Name)
                }
            }

            try
            {
                [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                $XML.Load($SCRIPT:KeePassConfigurationFile)

                $OldProfile = $XML.SelectNodes('/Settings/DatabaseProfiles/Profile') | Where-Object { $_.Name -eq $DatabaseProfileName }
                if(-not $DatabasePath){ $_DatabasePath = $OldProfile.DatabasePath }
                if(Test-Bound -ParameterName 'UseMasterKey' -Not){ $_UseMasterKey = [bool]::Parse($OldProfile.UseMasterKey) }
                if(-not $KeyPath){ $_KeyPath = $OldProfile.KeyPath}
                if(Test-Bound -ParameterName 'UseNetworkAccount' -Not){ $_UseNetworkAccount = [bool]::Parse($OldProfile.UseNetworkAccount) }

                if($PSCmdlet.ParameterSetName -eq '_none'){ $_AuthenticationType = $OldProfile.AuthenticationType }
                else{ $_AuthenticationType = $PSCmdlet.ParameterSetName}

                ## Create New Profile Element with Name of the new profile
                $DatabaseProfile = $XML.CreateElement('Profile')
                $DatabaseProfileAtribute = $XML.CreateAttribute('Name')
                $DatabaseProfileAtribute.Value = $NewDatabaseProfileName
                $DatabaseProfile.Attributes.Append($DatabaseProfileAtribute) | Out-Null

                ## Build and Add Element Nodes
                $DatabasePathNode = $XML.CreateNode('element', 'DatabasePath', '')
                $DatabasePathNode.InnerText = $_DatabasePath
                $DatabaseProfile.AppendChild($DatabasePathNode) | Out-Null

                $KeyPathNode = $XML.CreateNode('element', 'KeyPath', '')
                $KeyPathNode.InnerText = $_KeyPath
                $DatabaseProfile.AppendChild($KeyPathNode) | Out-Null

                $UseNetworkAccountNode = $XML.CreateNode('element', 'UseNetworkAccount', '')
                $UseNetworkAccountNode.InnerText = $_UseNetworkAccount
                $DatabaseProfile.AppendChild($UseNetworkAccountNode) | Out-Null

                $UseMasterKeyNode = $XML.CreateNode('element', 'UseMasterKey', '')
                $UseMasterKeyNode.InnerText = $_UseMasterKey
                $DatabaseProfile.AppendChild($UseMasterKeyNode) | Out-Null

                $AuthenticationTypeNode = $XML.CreateNode('element', 'AuthenticationType', '')
                $AuthenticationTypeNode.InnerText = $_AuthenticationType
                $DatabaseProfile.AppendChild($AuthenticationTypeNode) | Out-Null

                $DefaultNode = $XML.CreateNode('element', 'Default', '')
                $DefaultNode.InnerText = $Default
                $DatabaseProfile.AppendChild($DefaultNode) | Out-Null

                $XML.SelectSingleNode('/Settings/DatabaseProfiles').ReplaceChild($DatabaseProfile, $OldProfile) | Out-Null

                $XML.Save($SCRIPT:KeePassConfigurationFile)

                $Script:KeePassProfileNames = (Get-KeePassDatabaseConfiguration).Name

                if($PassThru)
                {
                    Get-KeePassDatabaseConfiguration -DatabaseProfileName $NewDatabaseProfileName
                }
            }
            catch
            {
                Write-PSFMessage -Level Warning -Message ('[PROCESS] An Exception Occured while trying to add a new KeePass database configuration ({0}) to the configuration file.' -f $NewDatabaseProfileName)
                Write-PSFMessage -Level Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                Throw $_
            }
        }
    }
}
function Update-KeePassEntry
{
    <#
        .SYNOPSIS
            Function to update a KeePass Database Entry.
        .DESCRIPTION
            This function updates a KeePass Database Entry with basic properites available for specification.
        .PARAMETER KeePassEntry
            The KeePass Entry to be updated. Use the Get-KeePassEntry function to get this object.
        .PARAMETER KeePassEntryGroupPath
            Specify this parameter if you wish to only return entries form a specific folder path.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER Title
            Specify the Title of the new KeePass Database Entry.
        .PARAMETER UserName
            Specify the UserName of the new KeePass Database Entry.
        .PARAMETER KeePassPassword
            *Specify the KeePassPassword of the new KeePass Database Entry.
            *Notes:
                *This Must be of the type SecureString or KeePassLib.Security.ProtectedString
        .PARAMETER Notes
            Specify the Notes of the new KeePass Database Entry.
        .PARAMETER URL
            Specify the URL of the new KeePass Database Entry.
        .PARAMETER PassThru
            Specify to return the modified object.
        .PARAMETER Force
            Specify to Update the specified entry without confirmation.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -upper -lower -digits -length 20)

            This example updates a keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword is used to generated a random password with the specified options.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -KeePassEntryGroupPath 'General/TestAccounts' -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(New-KeePassPassword -PasswordProfileName 'Default' )

            This example updates a keepass database entry in the General/TestAccounts database group, with the specified Title and UserName. Also the function New-KeePassPassword with a password profile specifed to create a new password genereated from options saved to a profile.
        .EXAMPLE
            PS> Update-KeePassEntry -KeePassEntry $KeePassEntryObject -DatabaseProfileName TEST -Title 'Test Title' -UserName 'Domain\svcAccount' -KeePassPassword $(ConvertTo-SecureString -String 'apassword' -AsPlainText -Force)

            This example updates a keepass database entry with the specified Title, UserName and manually specified password converted to a securestring.
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassEntry,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassEntryGroupPath,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [String] $UserName,

        [Parameter(Position = 4)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_.GetType().Name -eq 'ProtectedString' -or $_.GetType().Name -eq 'SecureString'})]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [String] $URL,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName,

        [Parameter(Position = 8)]
        [switch] $Expires,

        [Parameter(Position = 9)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 10, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 11)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 12)]
        [Switch] $PassThru,

        [Parameter(Position = 13)]
        [Switch] $Force
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        $MasterKey = $null

        $KPEntry = Get-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassUuid $KeePassEntry.Uuid
        if(-not $KPEntry)
        {
            Write-PSFMessage -Level Warning -Message '[PROCESS] The Specified KeePass Entry does not exist or cannot be found.'
            Throw 'The Specified KeePass Entry does not exist or cannot be found.'
        }

        if($Force -or $PSCmdlet.ShouldProcess("Title: $($KPEntry.Strings.ReadSafe('Title')), `n`tUserName: $($KPEntry.Strings.ReadSafe('UserName')), `n`tGroupPath: $($KPEntry.ParentGroup.GetFullPath('/', $true))."))
        {
            $KeePassGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassEntryGroupPath -Stop

            $setKPEntrySplat = @{
                URL               = $URL
                KeePassEntry      = $KPEntry
                UserName          = $UserName
                Notes             = $Notes
                KeePassPassword   = $KeePassPassword
                KeePassGroup      = $KeePassGroup
                PassThru          = $PassThru
                Force             = $true
                Title             = $Title
                KeePassConnection = $KeePassConnectionObject
            }

            if($IconName){ $setKPEntrySplat.IconName = $IconName }
            if(Test-Bound -ParameterName 'Expires'){ $setKPEntrySplat.Expires = $Expires }
            if($ExpiryTime){ $setKPEntrySplat.ExpiryTime = $ExpiryTime}

            Set-KPEntry @setKPEntrySplat | ConvertTo-KPPSObject -DatabaseProfileName $DatabaseProfileName
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
function Update-KeePassGroup
{
    <#
        .SYNOPSIS
            Function to update a KeePass Database Group.
        .DESCRIPTION
            This function updates a KeePass Database Group.
        .PARAMETER KeePassGroup
            The KeePass Group to be updated. Use the Get-KeePassGroup function to get this object.
        .PARAMETER KeePassParentGroupPath
            Specify this parameter if you wish move the specified group to a different parent group.
            Notes:
                * Path Separator is the foward slash character '/'
        .PARAMETER DatabaseProfileName
            *This Parameter is required in order to access your KeePass database.
        .PARAMETER GroupName
            Specify the GroupName to change the specified group to.
        .PARAMETER PassThru
            Specify to return the updated keepass group object.
        .PARAMETER Force
            Specify to Update the specified group without confirmation.
        .PARAMETER MasterKey
            Specify a SecureString MasterKey if necessary to authenticat a keepass databse.
            If not provided and the database requires one you will be prompted for it.
            This parameter was created with scripting in mind.
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .EXAMPLE
            PS> Update-KeePassGroup -DatabaseProfileName TEST -KeePassGroup $KeePassGroupObject -KeePassParentGroupPath 'General/TestAccounts'

            This Example moves the specified KeePassGroup to a New parent group path.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName 'TEST' -KeePassGroupPath 'General/DevAccounts/testgroup' | Update-KeePassGroup -DatabaseProfileName TEST -KeePassParentGroupPath 'General/TestAccounts'

            This Example moves group specified via the pipeline to a New parent group path.
        .EXAMPLE
            PS> Get-KeePassGroup -DatabaseProfileName 'TEST' -KeePassGroupPath 'General/DevAccounts/testgroup' | Update-KeePassGroup -DatabaseProfileName TEST -GroupName 'DevGroup'

            This Example renames the group specified via the pipeline to 'DevGroup'
        .INPUTS
            String
            SecureString
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $KeePassGroup,

        [Parameter(Position = 0, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('FullPath')]
        [String] $KeePassParentGroupPath,

        [Parameter(Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName,

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string] $IconName,

        [Parameter(Position = 5)]
        [ValidateNotNullOrEmpty()]
        [String] $Notes,

        [Parameter(Position = 3)]
        [switch] $Expires,

        [Parameter(Position = 4)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 5, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string] $DatabaseProfileName,

        [Parameter(Position = 6)]
        [ValidateNotNullOrEmpty()]
        [PSobject] $MasterKey,

        [Parameter(Position = 7)]
        [Switch] $PassThru,

        [Parameter(Position = 8)]
        [Switch] $Force
    )
    begin
    {
    }
    process
    {
        $KeePassConnectionObject = New-KPConnection -DatabaseProfileName $DatabaseProfileName -MasterKey $MasterKey
        $MasterKey = $null

        if($KeePassParentGroupPath -and $KeePassParentGroupPath -ne $KeePassGroup.FullPath)
        {
            $KeePassParentGroup = Get-KpGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassParentGroupPath -Stop
        }

        if($Force -or $PSCmdlet.ShouldProcess($KeePassGroup.FullPath))
        {
            $KeePassGroupObject = Get-KPGroup -KeePassConnection $KeePassConnectionObject -FullPath $KeePassGroup.FullPath | Where-Object { $_.CreationTime -eq $KeePassGroup.CreationTime }

            if($KeePassGroupObject.Count -gt 1)
            {
                Write-PSFMessage -Level Warning -Message '[PROCESS] Found more than one group with the same path, name and creation time. Stoping Update.'
                Write-PSFMessage -Level Warning -Message ('[PROCESS] Found: ({0}) number of matching groups' -f $KeePassGroupObject.Count)
                Throw 'Found more than one group with the same path, name and creation time.'
            }

            $setKPGroupSplat = @{
                KeePassConnection = $KeePassConnectionObject
                KeePassGroup      = $KeePassGroupObject
                PassThru          = $PassThru
                Force             = $true
                GroupName         = $GroupName
                Confirm           = $false
                Notes             = $Notes
            }

            if($IconName){ $setKPGroupSplat.IconName = $IconName }
            if($KeePassParentGroup){ $setKPGroupSplat.KeePassParentGroup = $KeePassParentGroup }
            if(Test-Bound -ParameterName 'Expires'){ $setKPGroupSplat.Expires = $Expires }
            if($ExpiryTime){ $setKPGroupSplat.ExpiryTime = $ExpiryTime }

            Set-KPGroup @setKPGroupSplat | ConvertTo-KpPsObject -DatabaseProfileName $DatabaseProfileName
        }
    }
    end
    {
        Remove-KPConnection -KeePassConnection $KeePassConnectionObject
    }
}
function Add-KPEntry
{
    <#
        .SYNOPSIS
            This Function will add a new entry to a KeePass Database Group.
        .DESCRIPTION
            This Function will add a new entry to a KeePass Database Group.

            Currently This function supportes the basic fields for creating a new KeePass Entry.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            This is the KeePass GroupObject to add the new Entry to.
        .PARAMETER Title
            This is the Title of the New KeePass Entry.
        .PARAMETER UserName
            This is the UserName of the New KeePass Entry.
        .PARAMETER KeePassPassword
            This is the Password of the New KeePass Entry.
        .PARAMETER Notes
            This is the Notes of the New KeePass Entry.
        .PARAMETER URL
            This is the URL of the New KeePass Entry.
        .PARAMETER PassThru
            Returns the New KeePass Entry after creation.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2)]
        [String] $Title,

        [Parameter(Position = 3)]
        [String] $UserName,

        [Parameter(Position = 4)]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [String] $Notes,

        [Parameter(Position = 6)]
        [String] $URL,

        [Parameter(Position = 7)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 8)]
        [bool] $Expires,

        [Parameter(Position = 9)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 10)]
        [Switch] $PassThru
    )
    begin
    {
        try
        {
            [KeePassLib.PwEntry] $KeePassEntry = New-Object KeePassLib.PwEntry($true, $true) -ea Stop
        }
        catch
        {
            Write-PSFMessage -Level Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwEntry Object.'
            Write-PSFMessage -Level Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if((Test-KPPasswordValue $KeePassPassword) -and (Test-KPConnection $KeePassConnection))
        {
            if($Title)
            {
                [KeePassLib.Security.ProtectedString] $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
                $KeePassEntry.Strings.Set('Title', $SecureTitle)
            }

            if($UserName)
            {
                [KeePassLib.Security.ProtectedString] $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
                $KeePassEntry.Strings.Set('UserName', $SecureUser)
            }

            if($KeePassPassword)
            {
                if($KeePassPassword.GetType().Name -eq 'SecureString')
                {
                    [KeePassLib.Security.ProtectedString] $KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString
                    $KeePassSecurePasswordString = $KeePassSecurePasswordString.Insert(0, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassPassword))).WithProtection($true)
                }
                elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
                {
                    $KeePassSecurePasswordString = $KeePassPassword
                }
                $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
            }
            else
            {
                ## get password based on default pattern
                $KeePassSecurePasswordString = New-KeePassPassword
                $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
            }

            if($Notes)
            {
                [KeePassLib.Security.ProtectedString] $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
                $KeePassEntry.Strings.Set('Notes', $SecureNotes)
            }

            if($URL)
            {
                [KeePassLib.Security.ProtectedString] $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
                $KeePassEntry.Strings.Set('URL', $SecureURL)
            }

            if($IconName -and $IconName -ne $KeePassEntry.IconId)
            {
                $KeePassEntry.IconId = $IconName
            }

            if(Test-Bound -ParameterName 'Expires')
            {
                $KeePassEntry.Expires = $Expires
            }

            if($ExpiryTime)
            {
                $KeePassEntry.ExpiryTime = $ExpiryTime.ToUniversalTime()
            }

            $KeePassGroup.AddEntry($KeePassEntry, $true)

            $KeePassConnection.Save($null)

            if($PassThru)
            {
                $KeePassEntry
            }
        }
    }
}
function Add-KPGroup
{
    <#
        .SYNOPSIS
            Creates a New KeePass Folder Group.
        .DESCRIPTION
            Creates a New KeePass Folder Group.
        .EXAMPLE
            PS> Add-KPGroup -KeePassConnection $Conn -GroupName 'NewGroupName' -KeePassParentGroup $KpGroup

            This Example Create a New Group with the specified name in the specified KeePassParentGroup.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER GroupName
            Specify the name of the new group(s).
        .PARAMETER KeePassParentGroup
            Sepcify the KeePassParentGroup(s) for the new Group(s).
        .PARAMETER IconName
            Specify the Name of the Icon for the Group to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER PassThru
            Specify to return the new keepass group object.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullorEmpty()]
        [String] $GroupName,

        [Parameter(Position = 2, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup,

        [Parameter(Position = 3)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 4)]
        [String] $Notes,

        [Parameter(Position = 5)]
        [bool] $Expires,

        [Parameter(Position = 6)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 7)]
        [Switch] $PassThru
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup] $KeePassGroup = New-Object KeePassLib.PwGroup -ea Stop
        }
        catch
        {
            Write-PSFMessage -Level Warning -Message '[BEGIN] An error occured while creating a new KeePassLib.PwGroup Object.'
            Write-PSFMessage -Level Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            $KeePassGroup.Name = $GroupName

            if($IconName -and $IconName -ne $KeePassGroup.IconId)
            {
                $KeePassGroup.IconId = $IconName
            }

            if($Notes)
            {
                $KeePassGroup.Notes = $Notes
            }

            if(Test-Bound -ParameterName 'Expires')
            {
                $KeePassGroup.Expires = $Expires
            }

            if($ExpiryTime)
            {
                $KeePassGroup.ExpiryTime = $ExpiryTime.ToUniversalTime()
            }

            $KeePassParentGroup.AddGroup($KeePassGroup, $true)
            $KeePassConnection.Save($null)

            if($PassThru)
            {
                $KeePassGroup
            }
        }
    }
}
function ConvertFrom-KPProtectedString
{
    <#
        .SYNOPSIS
            This Function will Convert a KeePass ProtectedString to Plain Text.
        .DESCRIPTION
            This Function will Convert a KeePassLib.Security.ProtectedString to Plain Text.

            This Would Primarily be used for Reading Title,UserName,Password,Notes, and URL ProtectedString Values.
        .EXAMPLE
            PS>Get-KeePassPassword -UpperCase -LowerCase -Digits -SpecialCharacters -Length 21 | ConvertFrom-KeePassProtectedString

            This Example will created a password using the specified options and convert the resulting password to a string.
        .PARAMETER KeePassProtectedString
            This is the KeePassLib.Security.ProtectedString to be converted to plain text
    #>
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()] [KeePassLib.Security.ProtectedString] $KeePassProtectedString
    )
    process
    {
        $KeePassProtectedString.ReadSafe()
    }
}
function Get-KPEntry
{
    <#
        .SYNOPSIS
            This function will lookup and Return KeePass one or more KeePass Entries.
        .DESCRIPTION
            This function will lookup Return KeePass Entry(ies). It supports basic lookup filtering.
        .EXAMPLE
            PS> Get-KPEntryBase -KeePassConnection $DB -UserName "MyUser"

            This Example will return all entries that have the UserName "MyUser"
        .EXAMPLE
            PS> Get-KPEntry -KeePassConnection $DB -KeePassGroup $KpGroup

            This Example will return all entries that are in the specified group.
        .EXAMPLE
            PS> Get-KPEntry -KeePassConnection $DB -UserName "AUserName"

            This Example will return all entries have the UserName "AUserName"
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            This is the KeePass Group Object in which to search for entries.
        .PARAMETER Title
            This is a Title of one or more KeePass Entries.
        .PARAMETER UserName
            This is the UserName of one or more KeePass Entries.
        .PARAMETER KeePassUuid
            Specify the KeePass Entry Uuid for reverse lookup.
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType('KeePassLib.PwEntry')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UUID')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Group')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Title')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'UserName')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Password')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Group')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup[]] $KeePassGroup,

        [Parameter(Position = 1, Mandatory, ParameterSetName = 'UUID', ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [Alias('Uuid')]
        [KeePassLib.PwUuid] $KeePassUuid,

        [Parameter(Position = 2, ParameterSetName = 'Group')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'Title')]
        [ValidateNotNullOrEmpty()]
        [String] $Title,

        [Parameter(Position = 3, ParameterSetName = 'Group')]
        [Parameter(Position = 2, ParameterSetName = 'Title')]
        [Parameter(Position = 1, Mandatory, ParameterSetName = 'UserName')]
        [ValidateNotNullOrEmpty()]
        [String] $UserName
    )
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            $KeePassItems = $KeePassConnection.RootGroup.GetEntries($true)

            if($PSCmdlet.ParameterSetName -eq 'UUID')
            {
                $KeePassItems | Where-Object { $KeePassUuid.CompareTo($_.Uuid) -eq 0 }
            }
            else
            {
                ## This a lame way of filtering.
                if($KeePassGroup)
                {
                    $KeePassItems = foreach($_keepassItem in $KeePassItems)
                    {
                        if($KeePassGroup.Contains($_keepassItem.ParentGroup))
                        {
                            $_keepassItem
                        }
                    }
                }

                if($Title)
                {
                    $KeePassItems = foreach($_keepassItem in $KeePassItems)
                    {
                        if($_keepassItem.Strings.ReadSafe('Title').ToLower().Equals($Title.ToLower()))
                        {
                            $_keepassItem
                        }
                    }
                }

                if($UserName)
                {
                    $KeePassItems = foreach($_keepassItem in $KeePassItems)
                    {
                        if($_keepassItem.Strings.ReadSafe('UserName').ToLower().Equals($UserName.ToLower()))
                        {
                            $_keepassItem
                        }
                    }
                }

                $KeePassItems
            }
        }
    }
}
function Get-KPGroup
{
    <#
        .SYNOPSIS
            Gets a KeePass Group Object.
        .DESCRIPTION
            Gets a KeePass Group Object. Type: KeePassLib.PwGroup
        .EXAMPLE
            PS> Get-KeePassGroup -KeePassConnection $Conn -FullPath 'full/KPDatabase/pathtoGroup'

            This Example will return a KeePassLib.PwGroup array Object with the full group path specified.
        .EXAMPLE
            PS> Get-KeePassGroup -KeePassConnection $Conn -GroupName 'Test Group'

            This Example will return a KeePassLib.PwGroup array Object with the groups that have the specified name.
        .PARAMETER KeePassConnection
            Specify the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER FullPath
            Specify the FullPath of a Group or Groups in a KPDB
        .PARAMETER GroupName
            Specify the GroupName of a Group or Groups in a KPDB.
        .PARAMETER KeePassUuid
            Specify the Uuid of the Group.
    #>
    [CmdletBinding(DefaultParameterSetName = 'None')]
    [OutputType('KeePassLib.PwGroup')]
    param
    (
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Full')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'Partial')]
        [Parameter(Position = 0, Mandatory, ParameterSetName = 'None')]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Full')]
        [ValidateNotNullOrEmpty()]
        [String] $FullPath,

        [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = 'Partial')]
        [ValidateNotNullOrEmpty()]
        [String] $GroupName,

        [Parameter(Position = 2)]
        [Switch] $Stop
    )
    begin
    {
        try
        {
            [KeePassLib.PwGroup[]] $KeePassOutGroups = $null
            [KeePassLib.PwGroup[]] $KeePassGroups = $KeePassConnection.RootGroup
            $KeePassGroups += $KeePassConnection.RootGroup.GetFlatGroupList()
        }
        catch
        {
            Write-PSFMessage -Level Warning -Message 'An error occured while getting a KeePassLib.PwGroup Object.'
            Write-PSFMessage -Level Error -ErrorRecord $_ -ea Stop
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            [int] $foundCount = 0

            if($PSCmdlet.ParameterSetName -eq 'Full')
            {
                foreach($_keepassGroup in $KeePassGroups)
                {
                    if($_keepassGroup.GetFullPath('/', $true).ToLower().Equals($FullPath.ToLower()))
                    {
                        $_keepassGroup
                        $foundCount += 1
                    }
                }
            }
            elseif($PSCmdlet.ParameterSetName -eq 'Partial')
            {
                foreach($_keepassGroup in $KeePassGroups)
                {
                    if($_keepassGroup.Name.ToLower().Equals($GroupName.ToLower()))
                    {
                        $_keepassGroup
                        $foundCount += 1
                    }
                }
            }
            elseif($PSCmdlet.ParameterSetName -eq 'None')
            {
                $KeePassGroups
                $foundCount = $KeePassGroups.Count
            }
        }

        if($Stop -and $foundCount -eq 0)
        {
            Write-PSFMessage -Level Warning -Message ('[PROCESS] The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassGroupParentPath)
            Throw 'The Specified KeePass Entry Group Path ({0}) does not exist.' -f $KeePassGroupParentPath
        }
    }
}
function Get-KPPasswordProfile
{
    <#
        .SYNOPSIS
            Function to Retreive All or a Specified Password Profile.
        .DESCRIPTION
            Function to Retreive All or a Specified Password Profile from the KeePassConfiguration.xml file.
        .PARAMETER PasswordProfileName
            Specify the Password Profile Name to Retreive.
        .EXAMPLE
            PS> Get-KPPasswordProfile

            Returns all Password Profile definitions if any.
        .NOTES
            Internal Funciton.
        .INPUTS
            String
        .OUTPUTS
            PSObject
    #>
    [CmdletBinding()]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "PasswordProfileName")]
    param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName
    )
    process
    {
        if(Test-Path -Path $SCRIPT:KeePassConfigurationFile)
        {
            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($SCRIPT:KeePassConfigurationFile)

            if($PasswordProfileName)
            {
                $XML.Settings.PasswordProfiles.Profile | Where-Object { $_.Name -ilike $PasswordProfileName }
            }
            else
            {
                $XML.Settings.PasswordProfiles.Profile
            }
        }
        else
        {
            Write-PSFMessage -Level Verbose 'No KeePass Configuration files exist, please create one to continue: New-KeePassDatabasConfiguration.'
        }
    }
}
function Import-KPLibrary
{
    [CmdletBinding()]
    param()
    process
    {
        Add-Type -Path $SCRIPT:KeePassLibraryPath
    }
}
function New-KPConfigurationFile
{
    <#
        .SYNOPSIS
            This Internal Function Creates the KeePassConfiguration.xml file.
        .DESCRIPTION
            This Internal Function Creates the KeePassConfiguration.xml file.
            This File is used to store database configuration for file locations, authentication settings and password profiles.
        .PARAMETER Force
            Specify this parameter to forcefully overwrite the existing config with a new fresh config.
        .EXAMPLE
            PS> New-KPConfigurationFile

            This Example will create a new KeePassConfiguration.xml file.
        .NOTES
            Internal Function.
        .INPUTS
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [Switch] $Force
    )
    process
    {
        if((Test-Path -Path $SCRIPT:KeePassConfigurationFile) -and -not $Force)
        {
            Write-PSFMessage -Level Warning -Message '[PROCESS] A KeePass Configuration File already exists. Please rerun with -force to overwrite the existing configuration.'
            Write-PSFMessage -Level Error -Message 'A KeePass Configuration File already exists.' -ea Stop
        }
        else
        {
            try
            {
                $Path = $SCRIPT:KeePassConfigurationFile

                $XML = New-Object System.Xml.XmlTextWriter($Path, $null)
                $XML.Formatting = 'Indented'
                $XML.Indentation = 1
                $XML.IndentChar = "`t"
                $XML.WriteStartDocument()
                $XML.WriteProcessingInstruction('xml-stylesheet', "type='text/xsl' href='style.xsl'")
                $XML.WriteStartElement('Settings')
                $XML.WriteStartElement('DatabaseProfiles')
                $XML.WriteEndElement()
                $XML.WriteStartElement("PasswordProfiles")
                $XML.WriteEndElement()
                $XML.WriteEndElement()
                $XML.WriteEndDocument()
                $xml.Flush()
                $xml.Close()
            }
            catch
            {
                Write-PSFMessage -Level Warning -Message 'An exception occured while trying to create a new keepass configuration file.'
                Write-PSFMessage -Level Error -ErrorRecord $_ -ea Stop
            }
        }
    }
}
function New-KPConnection
{
    <#
        .SYNOPSIS
            Creates an open connection to a Keepass database
        .DESCRIPTION
            Creates an open connection to a Keepass database using all available authentication methods
        .PARAMETER Database
            Path to the Keepass database (.kdbx file)
        .PARAMETER ProfileName
            Name of the profile entry
        .PARAMETER MasterKey
            Path to the keyfile (.key file) used to open the database
        .PARAMETER Keyfile
            Path to the keyfile (.key file) used to open the database
        .PARAMETER UseWindowsAccount
            Use the current windows account as an authentication method
    #>
    [CmdletBinding(DefaultParameterSetName = '__None')]
    param
    (
        [Parameter(Position = 0, ParameterSetName = 'Profile')]
        [AllowNull()]
        [String] $DatabaseProfileName,

        [Parameter(Position = 0, Mandatory, ParameterSetName = 'CompositeKey')]
        [ValidateNotNullOrEmpty()]
        [String] $Database,

        [Parameter(Position = 2, ParameterSetName = 'CompositeKey')]
        [Parameter(Position = 1, ParameterSetName = 'Profile')]
        [AllowNull()]
        [PSObject] $MasterKey,

        [Parameter(Position = 1, ParameterSetName = 'CompositeKey')]
        [ValidateNotNullOrEmpty()]
        [String] $KeyPath,

        [Parameter(Position = 3, ParameterSetName = 'CompositeKey')]
        [Switch] $UseWindowsAccount
    )
    process
    {
        try
        {
            $DatabaseObject = New-Object -TypeName KeepassLib.PWDatabase -ErrorAction Stop
        }
        catch
        {
            Write-PSFMessage -Level Error -Message 'Unable to Create KeepassLib.PWDatabase to open a connection.' -Exception $_.Exception -ea Stop
        }

        $CompositeKey = New-Object -TypeName KeepassLib.Keys.CompositeKey

        if(($MasterKey -isnot [PSCredential]) -and ($MasterKey -isnot [SecureString]) -and $MasterKey)
        {
            Write-PSFMessage -Level Error -Message ('[PROCESS] The MasterKey of type: ({0}). Is not Supported Please supply a MasterKey of Types (SecureString or PSCredential).' -f $($MasterKey.GetType().Name)) -Category InvalidType -TargetObject $MasterKey -RecommendedAction 'Provide a MasterKey of Type PSCredential or SecureString'
        }

        if($PSCmdlet.ParameterSetName -eq 'Profile' -or $PSCmdlet.ParameterSetName -eq '__None')
        {
            ## if not passing a profile name, attempt to get the default db
            $getKeePassDatabaseConfigurationSplat = @{ Stop = $true }
            if($DatabaseProfileName){ $getKeePassDatabaseConfigurationSplat.DatabaseProfileName = $DatabaseProfileName }
            else{ $getKeePassDatabaseConfigurationSplat.Default = $true }

            $KeepassConfigurationObject = Get-KeePassDatabaseConfiguration @getKeePassDatabaseConfigurationSplat

            $Database = $KeepassConfigurationObject.DatabasePath
            if(-not [string]::IsNullOrEmpty($KeepassConfigurationObject.KeyPath)){ $KeyPath = $KeepassConfigurationObject.KeyPath }
            [Switch] $UseWindowsAccount = $KeepassConfigurationObject.UseNetworkAccount
            [Switch] $UseMasterKey = $KeepassConfigurationObject.UseMasterKey

            if($UseMasterKey -and -not $MasterKey)
            {
                $MasterKey = Read-Host -Prompt 'KeePass Password' -AsSecureString
            }
        }
        elseif($PSCmdlet.ParameterSetName -eq 'CompositeKey')
        {
            $UseMasterKey = if($MasterKey){ $true }
        }

        if($MasterKey -is [PSCredential])
        {
            [SecureString] $MasterKey = $MasterKey.Password
        }

        $DatabaseItem = Get-Item -Path $Database -ErrorAction Stop

        ## Start Building CompositeKey
        ## Order in which the CompositeKey is created is important and must follow the order of : MasterKey, KeyFile, Windows Account
        if($UseMasterKey)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpPassword([System.Runtime.InteropServices.Marshal]::PtrToStringUni([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MasterKey)))))
        }

        if($KeyPath)
        {
            try
            {
                $KeyPathItem = Get-Item $KeyPath -ErrorAction Stop
                $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpKeyfile($KeyPathItem.FullName)))
            }
            catch
            {
                Write-PSFMessage -Level Warning ('Could not read the specfied Key file [{0}].' -f $KeyPathItem.FullName)
            }
        }

        if($UseWindowsAccount)
        {
            $CompositeKey.AddUserKey((New-Object KeepassLib.Keys.KcpUserAccount))
        }

        ## Build and Open Connection
        $IOInfo = New-Object KeepassLib.Serialization.IOConnectionInfo
        $IOInfo.Path = $DatabaseItem.FullName

        ## We currently are not using a status logger hence the null.
        $IStatusLogger = New-Object KeePassLib.Interfaces.NullStatusLogger

        $null = $DatabaseObject.Open($IOInfo, $CompositeKey, $IStatusLogger)
        $DatabaseObject

        if(-not $DatabaseObject.IsOpen)
        {
            Throw 'InvalidDatabaseConnectionException : The database is not open.'
        }
    }
}
function New-KPPasswordProfile
{
    <#
        .SYNOPSIS
            Function to save a password profile to the KeePassConfiguration.xml file.
        .DESCRIPTION
            This funciton will save a password profile to the config file.
            This is an internal function and is used in the -saveas option of the New-KeePassPassword function.
        .PARAMETER KeePassPasswordObject
            Specify the KeePass Password Profile Object to be saved to the config file.
        .EXAMPLE
            PS> New-KPPasswordProfile -KeePassPasswordObject $NewPasswordProfile

            This Example adds the $NewPasswordProfile object to the KeePassConfiguration.xml file.
        .NOTES
            Internal Funciton
        .INPUTS
            PSObject
        .OUTPUTS
            $null
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject] $KeePassPasswordObject
    )
    process
    {
        if(Test-Path -Path $SCRIPT:KeePassConfigurationFile)
        {
            $CheckIfExists = Get-KPPasswordProfile -PasswordProfileName $KeePassPasswordObject.ProfileName
            if($CheckIfExists)
            {
                Write-PSFMessage -Level Warning -Message ('[PROCESS] A Password Profile with the specified name ({0}) already exists.' -f $KeePassPasswordObject.ProfileName)
                Throw 'A Password Profile with the specified name ({0}) already exists.' -f $KeePassPasswordObject.ProfileName
            }

            [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
            $XML.Load($SCRIPT:KeePassConfigurationFile)
            ## Create New Profile Element with Name of the new profile
            $PasswordProfile = $XML.CreateElement('Profile')
            $PasswordProfileAtribute = $XML.CreateAttribute('Name')
            $PasswordProfileAtribute.Value = $KeePassPasswordObject.ProfileName
            $PasswordProfile.Attributes.Append($PasswordProfileAtribute) | Out-Null

            ## Build and Add Element Nodes
            $CharacterSetNode = $XML.CreateNode('element', 'CharacterSet', '')
            $CharacterSetNode.InnerText = $KeePassPasswordObject.CharacterSet
            $PasswordProfile.AppendChild($CharacterSetNode) | Out-Null

            $ExcludeLookAlikeNode = $XML.CreateNode('element', 'ExcludeLookAlike', '')
            $ExcludeLookAlikeNode.InnerText = $KeePassPasswordObject.ExcludeLookAlike
            $PasswordProfile.AppendChild($ExcludeLookAlikeNode) | Out-Null

            $NoRepeatingCharactersNode = $XML.CreateNode('element', 'NoRepeatingCharacters', '')
            $NoRepeatingCharactersNode.InnerText = $KeePassPasswordObject.NoRepeatingCharacters
            $PasswordProfile.AppendChild($NoRepeatingCharactersNode) | Out-Null

            $ExcludeCharactersNode = $XML.CreateNode('element', 'ExcludeCharacters', '')
            $ExcludeCharactersNode.InnerText = $KeePassPasswordObject.ExcludeCharacters
            $PasswordProfile.AppendChild($ExcludeCharactersNode) | Out-Null

            $LengthNode = $XML.CreateNode('element', 'Length', '')
            $LengthNode.InnerText = $KeePassPasswordObject.Length
            $PasswordProfile.AppendChild($LengthNode) | Out-Null

            $XML.SelectSingleNode('/Settings/PasswordProfiles').AppendChild($PasswordProfile) | Out-Null

            $XML.Save($SCRIPT:KeePassConfigurationFile)
        }
        else
        {
            Write-PSFMessage -Level Host 'No KeePass Database Configuration file exists. You can create one with the New-KeePassDatabaseConfiguration function.'
        }
    }
}
function Remove-KPConnection
{
    <#
        .SYNOPSIS
            This Function Removes a Connection to a KeePass Database.
        .DESCRIPTION
            This Function Removes a Connection to a KeePass Database.
        .EXAMPLE
            PS> Remove-KPConnection -KeePassConnection $DB

            This Example will Remove/Close a KeePass Database Connection using a pre-defined KeePass DB connection.
        .PARAMETER KeePassConnection
            This is the KeePass Connection to be Closed
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection
    )
    process
    {
        try
        {
            if($KeePassConnection.IsOpen)
            {
                $KeePassConnection.Close()
            }
            else
            {
                Write-PSFMessage -Level Warning -Message '[PROCESS] The KeePass Database Specified is already closed or does not exist.'
                Write-PSFMessage -Level Error -Message 'The KeePass Database Specified is already closed or does not exist.' -ea Stop
            }
        }
        catch [Exception]
        {
            Write-PSFMessage -Level Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
            Write-PSFMessage -Level Error -ErrorRecord $_ -ea Stop
        }
    }
}
function Remove-KPEntry
{
    <#
        .SYNOPSIS
            Remove a Specific KeePass Entry.
        .DESCRIPTION
            Remove a Specified KeePass Database Entry.
         .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KPConnection to Create the conneciton Object.
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to be deleted.
        .PARAMETER NoRecycle
            Specify this flag to Permanently delete an entry. (ei skip the recycle bin)
        .PARAMETER Force
            Specify this flag to forcefully delete an entry.
        .EXAMPLE
            PS> Remove-KPEntry -KeePassConnection $KeePassConnectionObject -KeePassEntry $KeePassEntryObject

            This Will remove a keepass database entry and prompt for confirmation.
        .INPUTS
            Strings
            KeePassLib.PwDatabase
            KeePassLib.PwEntry
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position = 2)]
        [Switch] $NoRecycle,

        [Parameter(Position = 3)]
        [Switch] $Force
    )
    begin
    {
        if($KeePassConnection.RecycleBinEnabled)
        {
            $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)

            if(-not $RecycleBin)
            {
                $RecycleBin = New-Object -TypeName KeePassLib.PwGroup($true, $true, 'RecycleBin', 43)
                $RecycleBin.EnableAutoType = $false
                $RecycleBin.EnableSearching = $false
                $KeePassConnection.RootGroup.AddGroup($RecycleBin, $true)
                $KeePassConnection.RecycleBinUuid = $RecycleBin.Uuid
                $KeePassConnection.Save($null)
                $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            }
        }

        $EntryDisplayName = "$($KeePassEntry.ParentGroup.GetFullPath('/', $true))/$($KeePassEntry.Strings.ReadSafe('Title'))"
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            if($Force -or $PSCmdlet.ShouldProcess($($EntryDisplayName)))
            {
                if($RecycleBin -and -not $NoRecycle)
                {
                    ## Make Copy of the group to be recycled.
                    $DeletedKeePassEntry = $KeePassEntry.CloneDeep()
                    ## Generate a new Uuid and update the copy fo the group
                    $DeletedKeePassEntry.Uuid = (New-Object KeePassLib.PwUuid($true))
                    ## Add the copy to the recycle bin, with take ownership set to true
                    $RecycleBin.AddEntry($DeletedKeePassEntry, $true)
                    ## Save for safety
                    $KeePassConnection.Save($null)
                    ## Delete Original Entry
                    $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry) > $null
                    ## Save again
                    $KeePassConnection.Save($null)
                    Write-PSFMessage -Level Verbose -Message "[PROCESS] Group has been Recycled."
                }
                else
                {
                    if($Force -or $PSCmdlet.ShouldContinue("Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.", "Do you want to continue to Permanently Delete this Entry: ($($EntryDisplayName))?"))
                    {
                        ## Deletes the specified group
                        $IsRemoved = $KeePassEntry.ParentGroup.Entries.Remove($KeePassEntry)

                        if(-not $IsRemoved)
                        {
                            Write-PSFMessage -Level Warning -Message "[PROCESS] Unknown Error has occured. Failed to Remove Entry ($($EntryDisplayName))"
                            Throw "Failed to Remove Entry $($EntryDisplayName)"
                        }
                        else
                        {
                            Write-PSFMessage -Level Verbose -Message "[PROCESS] Entry ($($EntryDisplayName)) has been Removed."
                            $KeePassConnection.Save($null)
                        }
                    }
                }
            }
        }
    }
}
function Remove-KPGroup
{
    <#
        .SYNOPSIS
            Function to remove a KeePass Group
        .DESCRIPTION
            Function to remove a specified KeePass Group.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassGroup
            Specify the Group to be removed.
        .PARAMETER NoRecycle
            Specify if you do not want the group to go to the Recycle Bin.
        .PARAMETER Force
            Specify to forcefully remove a group.
        .EXAMPLE
            PS> Remove-KPGroup -KeePassConnection $KeePassConnectionObject -KeePassGroup $KeePassGroupObject

            Removes the specified account. Prompts before deletion and will put to recyclebin if there is one.
        .INPUTS
            KeePassLib.PwDatabase
            KeePassLib.PwGroup
            Switch
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2)]
        [Switch] $NoRecycle,

        [Parameter(Position = 3)]
        [Switch] $Force
    )
    begin
    {
        if($KeePassConnection.RecycleBinEnabled)
        {
            $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            if(-not $RecycleBin)
            {
                $RecycleBin = New-Object -TypeName KeePassLib.PwGroup($true, $true, 'RecycleBin', 43)
                $RecycleBin.EnableAutoType = $false
                $RecycleBin.EnableSearching = $false
                $KeePassConnection.RootGroup.AddGroup($RecycleBin, $true)
                $KeePassConnection.RecycleBinUuid = $RecycleBin.Uuid
                $KeePassConnection.Save($null)
                $RecycleBin = $KeePassConnection.RootGroup.FindGroup($KeePassConnection.RecycleBinUuid, $true)
            }
        }
    }
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            if($Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/', $true))))
            {
                if($RecycleBin -and -not $NoRecycle)
                {
                    ## Make Copy of the group to be recycled.
                    $DeletedKeePassGroup = $KeePassGroup.CloneDeep()
                    ## Generate a new Uuid and update the copy fo the group
                    $DeletedKeePassGroup.Uuid = (New-Object KeePassLib.PwUuid($true))
                    ## Add the copy to the recycle bin, with take ownership set to true
                    $RecycleBin.AddGroup($DeletedKeePassGroup, $true, $true)
                    $KeePassConnection.Save($null)
                    $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup) > $null
                    $KeePassConnection.Save($null)
                    Write-PSFMessage -Level Verbose -Message '[PROCESS] Group has been Recycled.'
                }
                else
                {
                    if($Force -or $PSCmdlet.ShouldContinue('Recycle Bin Does Not Exist or the -NoRecycle Option Has been Specified.', "Do you want to continue to Permanently Delete this Group: ($($KeePassGroup.GetFullPath('/', $true)))?"))
                    {
                        ## Deletes the specified group
                        $IsRemoved = $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup)
                        if(-not $IsRemoved)
                        {
                            Write-PSFMessage -Level Warning -Message ('[PROCESS] Unknown Error has occured. Failed to Remove Group ({0})' -f $KeePassGroup.GetFullPath('/', $true))
                            Throw 'Failed to Remove Group ({0})' -f $KeePassGroup.GetFullPath('/', $true)
                        }
                        else
                        {
                            Write-PSFMessage -Level Verbose -Message ('[PROCESS] Group ({0}) has been Removed.' -f $KeePassGroup.GetFullPath('/', $true))
                            $KeePassConnection.Save($null)
                        }
                    }
                }
            }
        }
    }
}
function Remove-KPPasswordProfile
{
    <#
        .SYNOPSIS
            Function to remove a specifed Password Profile.
        .DESCRIPTION
            Removes a specified password profile from the KeePassConfiguration.xml file.
        .PARAMETER PasswordProfileName
            Specify the Password Profile to be delete from the config file.
        .EXAMPLE
            PS> Remove-KPPasswordProfile -PasswordProfileName 'Personal'

            This example remove the password profile with the name 'Personal'
        .NOTES
            Internal Funciton.
        .INPUTS
            Strings
        .OUTPUTS
            $null
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingPlainTextForPassword", "PasswordProfileName")]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [String] $PasswordProfileName
    )
    begin
    {
    }
    process
    {
        if(-not (Test-Path -Path $SCRIPT:KeePassConfigurationFile))
        {
            Write-PSFMessage -Level Verbose -Message '[PROCESS] A KeePass Configuration File does not exist.'
        }
        else
        {
            if($PSCmdlet.ShouldProcess($PasswordProfileName))
            {
                try
                {
                    [Xml] $XML = New-Object -TypeName System.Xml.XmlDocument
                    $XML.Load($SCRIPT:KeePassConfigurationFile)
                    $XML.Settings.PasswordProfiles.Profile  | Where-Object { $_.Name -eq $PasswordProfileName } | ForEach-Object { $xml.Settings.PasswordProfiles.RemoveChild($_) } | Out-Null
                    $XML.Save($SCRIPT:KeePassConfigurationFile)
                }
                catch [exception]
                {
                    Write-PSFMessage -Level Warning -Message ('[PROCESS] An exception occured while attempting to remove a KeePass Password Profile ({0}).' -f $PasswordProfileName)
                    Write-PSFMessage -Level Warning -Message ('[PROCESS] {0}' -f $_.Exception.Message)
                    Throw $_
                }
            }
        }
    }
}
function Restore-KPConfigurationFile
{
    <#
        .SYNOPSIS
            Restore Config file from previous version
        .DESCRIPTION
            Restore Config file from previous version
        .PARAMETER
        .EXAMPLE
        .NOTES
        .INPUTS
        .OUTPUTS
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0)]
        [String] $BreakingChangesVersion
    )
    process
    {
        $ReturnStatus = $false
        $Path = Resolve-Path -Path ('{0}\..' -f $PSScriptRoot)

        Write-PSFMessage -Level Verbose -Message ('[PROCESS] Checking if there is a previous KeePassConfiguration.xml file to be loaded from: {0}.' -f $Path.Path )
        $PreviousVersion = ((Get-ChildItem $Path.Path).Name | Sort-Object -Descending | Select-Object -First 2)[1]

        Write-PSFMessage -Level Verbose -Message ('PreviousVersion: {0}.' -f $PreviousVersion)
        $PreviousVersionConfigurationFile = Resolve-Path -Path ('{0}\..\{1}\KeePassConfiguration.xml' -f $PSScriptRoot, $PreviousVersion) -ErrorAction SilentlyContinue -ErrorVariable GetPreviousConfigurationFileError

        if(-not $GetPreviousConfigurationFileError -and $PreviousVersion)
        {
            Write-PSFMessage -Level Verbose -Message ('[PROCESS] Copying last Configuration file from the previous version ({0}).' -f $PreviousVersion)
            Copy-Item -Path $PreviousVersionConfigurationFile -Destination "$PSScriptRoot" -ErrorAction SilentlyContinue -ErrorVariable RestorePreviousConfigurationFileError

            if($RestorePreviousConfigurationFileError)
            {
                Write-PSFMessage -Level Warning -Message '[PROCESS] Unable to restore previous KeePassConfiguration.xml file. You will need to copy your previous file from your previous module version folder or create a new one.'
            }
            else
            {
                $ReturnStatus = $true
            }
        }

        return $ReturnStatus
    }
}
function Set-KPEntry
{
    <#
        .SYNOPSIS
            This Function will update a entry.
        .DESCRIPTION
            This Function will update a entry.

            Currently This function supportes the basic fields for a KeePass Entry.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER KeePassEntry
            This is the KeePass Entry Object to update/set atrributes.
        .PARAMETER KeePassGroup
            Specifiy this if you want Move the KeePassEntry to another Group
        .PARAMETER Title
            This is the Title to update/set.
        .PARAMETER UserName
            This is the UserName to update/set.
        .PARAMETER KeePassPassword
            This is the Password to update/set.
        .PARAMETER Notes
            This is the Notes to update/set.
        .PARAMETER URL
            This is the URL to update/set.
        .PARAMETER PassThru
            Returns the updated KeePass Entry after updating.
        .PARAMETER Force
            Specify to force updating the KeePass Entry.
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet will autosave on exit
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwEntry] $KeePassEntry,

        [Parameter(Position = 2)]
        [String] $Title,

        [Parameter(Position = 3)]
        [String] $UserName,

        [Parameter(Position = 4)]
        [PSObject] $KeePassPassword,

        [Parameter(Position = 5)]
        [String] $Notes,

        [Parameter(Position = 6)]
        [String] $URL,

        [Parameter(Position = 7)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 8)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 9)]
        [bool] $Expires,

        [Parameter(Position = 10)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 11)]
        [Switch] $PassThru,

        [Parameter(Position = 12)]
        [Switch] $Force
    )
    process
    {
        if((Test-KPPasswordValue $KeePassPassword) -and (Test-KPConnection $KeePassConnection))
        {

            if($Force -or $PSCmdlet.ShouldProcess("Title: $($KeePassEntry.Strings.ReadSafe('Title')). `n`tUserName: $($KeePassEntry.Strings.ReadSafe('UserName')). `n`tGroup Path $($KeePassEntry.ParentGroup.GetFullPath('/', $true))"))
            {
                [KeePassLib.PwEntry] $OldEntry = $KeePassEntry.CloneDeep()

                if($Title)
                {
                    $SecureTitle = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectTitle, $Title)
                    $KeePassEntry.Strings.Set('Title', $SecureTitle)
                }

                if($UserName)
                {
                    $SecureUser = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUserName, $UserName)
                    $KeePassEntry.Strings.Set('UserName', $SecureUser)
                }

                if($KeePassPassword)
                {
                    if($KeePassPassword.GetType().Name -eq 'SecureString')
                    {
                        $KeePassSecurePasswordString = New-Object KeePassLib.Security.ProtectedString
                        $KeePassSecurePasswordString = $KeePassSecurePasswordString.Insert(0, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeePassPassword))).WithProtection($true)
                    }
                    elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
                    {
                        $KeePassSecurePasswordString = $KeePassPassword
                    }
                    $KeePassEntry.Strings.Set('Password', $KeePassSecurePasswordString)
                }

                if($Notes)
                {
                    $SecureNotes = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectNotes, $Notes)
                    $KeePassEntry.Strings.Set('Notes', $SecureNotes)
                }

                if($URL)
                {
                    $SecureURL = New-Object KeePassLib.Security.ProtectedString($KeePassConnection.MemoryProtection.ProtectUrl, $URL)
                    $KeePassEntry.Strings.Set('URL', $SecureURL)
                }

                if($IconName -and $IconName -ne $KeePassEntry.IconId)
                {
                    $KeePassEntry.IconId = $IconName
                }

                if(Test-Bound -ParameterName 'Expires')
                {
                    $KeePassEntry.Expires = $Expires
                }

                if($ExpiryTime)
                {
                    $KeePassEntry.ExpiryTime = $ExpiryTime.ToUniversalTime()
                }

                $OldEntry.History.clear()
                $KeePassEntry.History.Add($OldEntry)

                if($KeePassGroup)
                {
                    $OldKeePassGroup = $KeePassEntry.ParentGroup
                    ## Add to group and move
                    $KeePassGroup.AddEntry($KeePassEntry, $true, $true)
                    ## delete old entry
                    $null = $OldKeePassGroup.Entries.Remove($KeePassEntry)
                }

                ## Add History Entry
                $KeePassEntry.LastModificationTime = [DateTime]::UtcNow
                $KeePassEntry.LastAccessTime = [DateTime]::UtcNow

                ## Save for safety
                $KeePassConnection.Save($null)

                if($PassThru)
                {
                    $KeePassEntry
                }
            }
        }
    }
}
function Set-KPGroup
{
    <#
        .SYNOPSIS
            Creates a New KeePass Folder Group.
        .DESCRIPTION
            Creates a New KeePass Folder Group.
        .EXAMPLE
            PS> Add-KPGroup -KeePassConnection $Conn -GroupName 'NewGroupName' -KeePassParentGroup $KpGroup

            This Example Create a New Group with the specified name in the specified KeePassParentGroup.
        .PARAMETER KeePassConnection
            This is the Open KeePass Database Connection

            See Get-KeePassConnection to Create the conneciton Object.
        .PARAMETER GroupName
            Specify the name of the new group(s).
        .PARAMETER KeePassParentGroup
            Sepcify the KeePassParentGroup(s) for the new Group(s).
        .PARAMETER IconName
            Specify the Name of the Icon for the Entry to display in the KeePass UI.
        .PARAMETER Notes
            Specify group notes
        .PARAMETER PassThru
            Specify to return the updated group object.
        .PARAMETER Force
            Specify to force updating the group.
        .PARAMETER Expires
            Specify if you want the KeePass Object to Expire, default is to not expire.
        .PARAMETER ExpiryTime
            Datetime expiration Time value.
        .NOTES
            This Cmdlet Does AutoSave on exit.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param
    (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNull()]
        [KeePassLib.PwDatabase] $KeePassConnection,

        [Parameter(Position = 1, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassGroup,

        [Parameter(Position = 2)]
        [String] $GroupName,

        [Parameter(Position = 3)]
        [ValidateNotNullOrEmpty()]
        [KeePassLib.PwGroup] $KeePassParentGroup,

        [Parameter(Position = 4)]
        [KeePassLib.PwIcon] $IconName,

        [Parameter(Position = 5)]
        [String] $Notes,

        [Parameter(Position = 6)]
        [bool] $Expires,

        [Parameter(Position = 7)]
        [DateTime] $ExpiryTime,

        [Parameter(Position = 8)]
        [Switch] $PassThru,

        [Parameter(Position = 9)]
        [Switch] $Force
    )
    process
    {
        if(Test-KPConnection $KeePassConnection)
        {
            if($Force -or $PSCmdlet.ShouldProcess($($KeePassGroup.GetFullPath('/', $true))))
            {
                if($GroupName)
                {
                    $KeePassGroup.Name = $GroupName
                }

                if($IconName -and $IconName -ne $KeePassGroup.IconId)
                {
                    $KeePassGroup.IconId = $IconName
                }

                if($Notes)
                {
                    $KeePassGroup.Notes = $Notes
                }

                if(Test-Bound -ParameterName 'Expires')
                {
                    $KeePassGroup.Expires = $Expires
                }

                if($ExpiryTime)
                {
                    $KeePassGroup.ExpiryTime = $ExpiryTime.ToUniversalTime()
                }

                if($KeePassParentGroup)
                {
                    if($KeePassGroup.ParentGroup.Uuid.CompareTo($KeePassParentGroup.Uuid) -ne 0 )
                    {
                        $UpdatedKeePassGroup = $KeePassGroup.CloneDeep()
                        $UpdatedKeePassGroup.Uuid = New-Object KeePassLib.PwUuid($true)
                        $KeePassParentGroup.AddGroup($UpdatedKeePassGroup, $true, $true)
                        $KeePassConnection.Save($null)
                        $KeePassGroup.ParentGroup.Groups.Remove($KeePassGroup) > $null
                        $KeePassConnection.Save($null)
                        $KeePassGroup = $UpdatedKeePassGroup
                    }
                }

                $KeePassConnection.Save($null)

                if($PassThru)
                {
                    $KeePassGroup
                }
            }
        }
    }
}
## Taken and Modified from DBATools
function Test-Bound
{
    <#
        .SYNOPSIS
            Helperfunction that tests, whether a parameter was bound.

        .DESCRIPTION
            Helperfunction that tests, whether a parameter was bound.

        .PARAMETER ParameterName
            The name(s) of the parameter that is tested for being bound.
            By default, the check is true when AT LEAST one was bound.

        .PARAMETER Not
            Reverses the result. Returns true if NOT bound and false if bound.

        .PARAMETER And
            All specified parameters must be present, rather than at least one of them.

        .PARAMETER BoundParameters
            The hashtable of bound parameters. Is automatically inherited from the calling function via default value. Needs not be bound explicitly.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Position = 0, Mandatory)]
        [string[]] $ParameterName,

        [Alias('Reverse')]
        [switch] $Not,

        [switch] $And,

        [object] $BoundParameters = (Get-PSCallStack)[0].InvocationInfo.BoundParameters
    )
    process
    {
        if($And)
        {
            $test = $true
        }
        else
        {
            $test = $false
        }

        foreach($name in $ParameterName)
        {
            if($And)
            {
                if(-not $BoundParameters.ContainsKey($name))
                {
                    $test = $false
                }
            }
            else
            {
                if($BoundParameters.ContainsKey($name))
                {
                    $test = $true
                }
            }
        }

        return ((-not $Not) -eq $test)
    }
}
function Test-KPConnection
{
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [PSObject] $KeePassConnection
    )

    if($KeePassConnection.IsOpen)
    {
        $true
    }
    else
    {
        $false
        Write-PSFMessage -Level Warning -Message 'The KeePass Connection Sepcified is not open or does not exist.'
        Write-PSFMessage -Level Error -Message 'The KeePass Connection Sepcified is not open or does not exist.' -ea Stop
    }
}
function Test-KPPasswordValue
{
    [cmdletbinding()]
    param
    (
        [Parameter(Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [PSObject] $KeePassPassword
    )

    if(-not $KeePassPassword)
    {
        $true
    }
    elseif($KeePassPassword.GetType().Name -eq 'SecureString')
    {
        $true
    }
    elseif($KeePassPassword.GetType().Name -eq 'ProtectedString')
    {
        $true
    }
    else
    {
        $false
        Write-PSFMessage -Level Warning -Message '[PROCESS] Please provide a KeePassPassword of Type SecureString or KeePassLib.Security.ProtectedString.'
        Write-PSFMessage -Level Warning -Message ('[PROCESS] The Value supplied ({0}) is of Type {1}.' -f $KeePassPassword, $KeePassPassword.GetType().Name)
        Write-PSFMessage -Level Error -Message 'Please provide a KeePassPassword of Type SecureString or KeePassLib.Security.ProtectedString.' -ea Stop
    }
}

function Set-KeePassConfigFilePath {
    <#
    .SYNOPSIS
    Sets the path to the keepass configuration file used for state operations
    #>
    param (
        [String]$Path
    )
    $SCRIPT:KeePassConfigurationFile = $Path
    Get-KeePassConfigFile
}


# $KeePassRoot = "$($ENV:LOCALAPPDATA)/KeePass"
# if (-not (Test-Path $KeePassRoot)) {New-Item -ItemType Directory -Path $KeePassRoot}
# [String] $SCRIPT:KeePassConfigurationFile = "$KeePassRoot/KeePassConfiguration.xml"
[String] $SCRIPT:KeePassLibraryPath = '{0}\bin\*.dll' -f $PSScriptRoot

## Source KpLib
Import-KPLibrary

## Check for config and init
function Get-KeePassConfigFile {
    if (-not(Test-Path -Path $SCRIPT:KeePassConfigurationFile))
    {
        Write-PSFMessage -Level Warning -Message '**IMPORTANT NOTE:** Please always keep an up-to-date backup of your keepass database files and key files if used.'
    
        $Versions = ((Get-ChildItem "$PSScriptRoot\..").Name | Sort-Object -Descending)
    
        if(-not $(Restore-KPConfigurationFile))
        {
            New-KPConfigurationFile
    
            $previousVersion = [int]($Versions[1] -replace '\.')
            $CurrentVersion = $Versions[0]
            if($previousVersion -lt 2124)
            {
                Write-PSFMessage -Level Warning -Message ('**BREAKING CHANGES:** This new version of the module {0} contains BREAKING CHANGES, please review the changelog or readme for details!' -f $CurrentVersion)
            }
    
            Write-PSFMessage -Level Warning -Message 'This message will not show again on next import.'
        }
    }
    else
    {
        New-Variable -Name 'KeePassProfileNames' -Value @((Get-KeePassDatabaseConfiguration).Name) -Scope 'Script' #-Option Constant
    }
}

Export-ModuleMember *

# if(Get-Command Register-ArgumentCompleter -ea 0)
# {
#     Register-ArgumentCompleter -ParameterName 'DatabaseProfileName' -ScriptBlock {
#         param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

#         Get-KeePassDatabaseConfiguration | Where-Object { $_.Name -ilike "${wordToComplete}*" } | ForEach-Object {
#             New-Object System.Management.Automation.CompletionResult ( $_.Name, $_.Name, 'ParameterValue', $_.Name)
#         }
#     }

#     Register-ArgumentCompleter -ParameterName 'IconName' -ScriptBlock {
#         param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

#         [KeePassLib.PwIcon].GetEnumValues() | Where-Object { $_ -ilike "${wordToComplete}*" } | ForEach-Object {
#             New-Object System.Management.Automation.CompletionResult ( $_, $_, 'ParameterValue', $_)
#         }
#     }

#     Register-ArgumentCompleter -ParameterName 'PasswordProfileName' -ScriptBlock {
#         param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameter)

#         (Get-KPPasswordProfile).Name | Where-Object { $_ -ilike "${wordToComplete}*" } | ForEach-Object {
#             New-Object System.Management.Automation.CompletionResult ( $_, $_, 'ParameterValue', $_)
#         }
#     }
# }

