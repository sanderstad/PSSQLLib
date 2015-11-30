################################################################################
#  Written by Sander Stad, SQLStad.nl
# 
#  (c) 2015, SQLStad.nl. All rights reserved.
# 
#  For more scripts and sample code, check out http://www.SQLStad.nl
# 
#  You may alter this code for your own *non-commercial* purposes (e.g. in a
#  for-sale commercial tool). Use in your own environment is encouraged.
#  You may republish altered code as long as you include this copyright and
#  give due credit, but you must obtain prior permission before blogging
#  this code.
# 
#  THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF
#  ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
#  TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
#  PARTICULAR PURPOSE.
#
#  Changelog:
#  v1.0: Initial version
#  v1.1: Added several functions for hosts
#  v1.2: Added functionality to get the host system information
#        Cleaned up code, make it more readable
#        Changed parameters to be consistent throughout functions
#
################################################################################

function Get-SQLConfiguration
{
    <# 
    .SYNOPSIS
        Get the contents of the configuration of the instance
    .DESCRIPTION
        The script will connect to the instance and execute a query to get the 
        configuration settings. It wil return a table with the configurations.
    .PARAMETER instance
        This is the instance that needs to be connected
    .EXAMPLE
        Get-SQLConfiguration "SQL01"
    .EXAMPLE
        Get-SQLConfiguration "SQL01\INST01"
	.EXAMPLE
        Get-SQLInstance -inst "SQL01\INST01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>

    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$inst = $null
    )
    
    # Check if assembly is loaded
    Load-Assembly -name 'Microsoft.SqlServer.Smo'

    # Define the array
    $result = @()

    # Check if the instance object is already initiated
    if($server -eq $null)
    {
        try{
            $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $inst
        }
        catch [Exception]
        {
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
    }

    # Get the configurations
    $configuration = $server.Configuration

    # Get all the properties
    $result = $configuration.Properties 

    # Return the result
    return $result

}

Export-ModuleMember -Function Get-SQLConfiguration


function Get-SQLInstanceSettings
{
    <# 
    .SYNOPSIS
        Get the SQL Server instance settings
    .DESCRIPTION
        This function gets the settings of the instance and return
        the data in the form of a table.
    .PARAMETER instance
        This is the instance that needs to be connected
    .EXAMPLE
        Get-SQLInstance "SQL01"
    .EXAMPLE
        Get-SQLInstance "SQL01\INST01"
    .EXAMPLE
        Get-SQLInstance -inst "SQL01\INST01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$inst = $null
    )
    
    # Check if assembly is loaded
    Load-Assembly -name 'Microsoft.SqlServer.SMO'

    # Define the array
    $result = @()

    # Check if the instance object is already initiated
    if($server -eq $null)
    {
        try{
            $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $inst
        }
        catch [Exception]
        {
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
    }

    # Get the instance settings
    $result = $server | Select `
		AuditLevel,BackupDirectory,BrowserServiceAccount,BrowserStartMode,BuildClrVersionString,`
		BuildNumber,ClusterName,ClusterQuorumState,ClusterQuorumType,Collation,CollationID,`
		ComparisonStyle,ComputerNamePhysicalNetBIOS,DefaultFile,DefaultLog,Edition,ErrorLogPath,`
		FilestreamLevel,FilestreamShareName,HadrManagerStatus,InstallDataDirectory,InstallSharedDirectory,`
		InstanceName,IsCaseSensitive,IsClustered,IsFullTextInstalled,IsHadrEnabled,IsSingleUser,IsXTPSupported,`
		Language,LoginMode,MailProfile,MasterDBLogPath,MasterDBPath,MaxPrecision,NamedPipesEnabled,NetName,`
		NumberOfLogFiles,OSVersion,PerfMonMode,PhysicalMemory,PhysicalMemoryUsageInKB,Platform,Processors,`
		ProcessorUsage,Product,ProductLevel,ResourceLastUpdateDateTime,ResourceVersionString,RootDirectory,`
		ServerType,ServiceAccount,ServiceInstanceId,ServiceName,ServiceStartMode,SqlCharSet,SqlCharSetName,`
		SqlDomainGroup,SqlSortOrder,SqlSortOrderName,Status,TapeLoadWaitTime,TcpEnabled,VersionMajor,VersionMinor,`
		VersionString,Name,Version,EngineEdition,ResourceVersion,BuildClrVersion,DefaultTextMode 

    # Return the result
    return $result
}

Export-ModuleMember -Function Get-SQLInstanceSettings


function Get-SQLDatabases
{
    <# 
    .SYNOPSIS
        Get the SQL Server database settings
    .DESCRIPTION
        This function gets the settings of the prent databases and returns
        the data in the form of a table.
    .PARAMETER instance
        This is the instance that needs to be connected
    .EXAMPLE
        Get-Get-SQLDatabases "SQL01"
    .EXAMPLE
        Get-Get-SQLDatabases "SQL01\INST01"
    .EXAMPLE
        Get-Get-SQLDatabases -inst "SQL01\INST01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$inst = $null
    )

    # Check if assembly is loaded
    Load-Assembly -name 'Microsoft.SqlServer.SMO'

    # Define the array
    $result = @()

    # Check if the instance object is already initiated
    if($server -eq $null)
    {
        try{
            $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $inst
        }
        catch [Exception]
        {
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
    }

    # Get all the databases
    $databases = $server.Databases

    # Get the properties of each database
    $result = $databases | Select `
		ID,Name,AutoClose,AutoCreateIncrementalStatisticsEnabled,`
		AutoCreateStatisticsEnabled,AutoShrink,AutoUpdateStatisticsAsync,AutoUpdateStatisticsEnabled,`
		AvailabilityGroupName,CloseCursorsOnCommitEnabled,Collation,`
		CompatibilityLevel,CreateDate,DataSpaceUsage,`
		DelayedDurability,EncryptionEnabled,HasDatabaseEncryptionKey,HasFileInCloud,HasFullBackup,`
		IndexSpaceUsage,IsDbSecurityAdmin,IsFullTextEnabled,IsManagementDataWarehouse,IsMirroringEnabled,`
		LastBackupDate,LastDifferentialBackupDate,LastLogBackupDate,`
		Owner,PageVerify,PolicyHealthState,PrimaryFilePath,ReadOnly,`
		RecoveryModel,RecursiveTriggersEnabled,Size,SnapshotIsolationState,SpaceAvailable,`
		Status,TargetRecoveryTime,Trustworthy,UserAccess,UserName,Version 

    # Return the result
    return $result
}

Export-ModuleMember -Function Get-SQLDatabases

function Get-SQLDatabaseFiles
{
    <# 
    .SYNOPSIS
        Get the database files for each database 
    .DESCRIPTION
        The function return all the database files from all databases
    .PARAMETER instance
        This is the instance that needs to be connected
    .PARAMETER dbfilter
        This is used to return only show details on certain databases
    .EXAMPLE
        Get-Get-SQLDatabaseFiles "SQL01"
    .EXAMPLE
        Get-Get-SQLDatabaseFiles "SQL01\INST01"
    .EXAMPLE
        Get-Get-SQLDatabaseFiles -inst "SQL01\INST01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$inst = $null
    )

    # Check if assembly is loaded
    Load-Assembly -name 'Microsoft.SqlServer.SMO'

    # Define the array
    $dataFiles = @()
    $logFiles = @()
    $result = @()

    # Check if the instance object is already initiated
    if($server -eq $null)
    {
        try{
            $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $inst
        }
        catch [Exception]
        {
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
    }

    # Get all the databases
    $databases = $server.Databases

    # Loop through all the databases
    foreach($database in $databases)
    {
        
        # Get the filegroups for the database
        $filegroups = $database.FileGroups

        # Loop through all the filegroups
        foreach($filegroup in $filegroups)
        {
            # Get all the data files from the filegroup
            $files = $filegroup.Files

            # Loop through all the data files
            foreach($file in $files)
            {
                $result += $file | Select `
					@{Name="DatabaseName"; Expression={$database.Name}}, Name, `
					@{Name="FileType";Expression={"ROWS"}}, `
					@{Name="Directory"; Expression={$file.FileName | Split-Path -Parent}}, `
					@{Name="FileName"; Expression={$file.FileName | Split-Path -Leaf}}, `
					Growth, GrowthType, Size, UsedSpace
            }
        }

        # Get all the data files from the filegroup
        $files = $database.LogFiles

        # Loop through all the log files
        foreach($file in $files)
        {
            $result += $file | Select `
				@{Name="DatabaseName"; Expression={$database.Name}}, Name, `
				@{Name="FileType";Expression={"LOG"}}, `
				@{Name="Directory"; Expression={$file.FileName | Split-Path -Parent}}, `
				@{Name="FileName"; Expression={$file.FileName | Split-Path -Leaf}}, `
				Growth, GrowthType, Size, UsedSpace
        }

    }

    return $result
}

Export-ModuleMember -Function Get-SQLDatabaseFiles

function Get-SQLDatabaseUsers
{
    <# 
    .SYNOPSIS
        Get the database users 
    .DESCRIPTION
        The function returns all the database users present
    .PARAMETER instance
        This is the instance that needs to be connected
    .PARAMETER dbfilter
        This is used to return only show details on certain databases
    .EXAMPLE
        Get-SQLDatabaseUsers "SQL01"
    .EXAMPLE
        Get-SQLDatabaseUsers "SQL01\INST01"
    .EXAMPLE
        Get-SQLDatabaseUsers -inst "SQL01\INST01"
    .EXAMPLE
        Get-SQLDatabaseUsers -inst "SQL01\INST01" -dbfilter "tempdb,msdb"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param
    (
		[Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$inst = $null
		, [Parameter(Mandatory = $false, Position=2)]
        [ValidateNotNullOrEmpty()]
        [string]$dbfilter = $null
    )
    
    # Check if assembly is loaded
    Load-Assembly -name 'Microsoft.SqlServer.SMO'

    # Check if the instance object is already initiated
    if($server -eq $null)
    {
        try{
            $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $inst
        }
        catch [Exception]
        {
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
    }

    # Create the result array
    $result = @()

    # Get all the databases
    $databases = $server.Databases

    # Loop through the databases
    foreach($database in $databases)
    {
        # Get the database users
        $databaseUsers = $database.Users 

        # Get the result
        $result += $databaseUsers | Select `
			Parent,Name,AsymmetricKey,AuthenticationType,Certificate,`
			CreateDate,DateLastModified,DefaultLanguageLcid,DefaultLanguageName,`
			DefaultSchema,HasDBAccess,ID,IsSystemObject,Login,LoginType,`
			PolicyHealthState,Sid,UserType 
    }
    
    # Return the results
    return $result 
}

Export-ModuleMember -Function Get-SQLDatabaseUsers

function Get-SQLDatabasePrivileges
{
    <# 
    .SYNOPSIS
        Gets the users in the database and looks up the roles
    .DESCRIPTION
        The function return all the database users with their roles in the database
    .PARAMETER instance
        This is the instance that needs to be connected
    .EXAMPLE
        Get-SQLDatabasePrivileges "SQL01"
    .EXAMPLE
        Get-SQLDatabasePrivileges "SQL01\INST01"
    .EXAMPLE
        Get-SQLDatabasePrivileges -inst "SQL01\INST01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$inst = $null
    )
    
    # Check if assembly is loaded
    Load-Assembly -name 'Microsoft.SqlServer.SMO'

    # Check if the instance object is already initiated
    if($server -eq $null)
    {
        try{
            $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $inst
        }
        catch [Exception]
        {
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
    }

    # Create the result array
    $result = @()

    # Create the memberRoles array
    $userRoles = @()

    # Get all the databases
    $databases = $server.Databases
    
    # Loop through the databases
    foreach($database in $databases)
    {
        # Get all the logins
        $users = $database.Users
        
        # Get all the roles
        $roles = $database.Roles
        
        # Loop through the logins
        foreach($user in $users)
        {
            # Check if user is not a system user
            if(
				($user.Name -ne "dbo") `
				-and ($user.Name -notlike "##*") `
				-and ($user.Name -ne "INFORMATION_SCHEMA") `
				-and ($user.Name -ne "sys") `
				-and ($user.Name -ne "guest"))
            {

                # Loop through the roles
                foreach($role in $roles)
                {
                    # Get all the members of the role
                    $roleMembers = $role.EnumMembers()

                    # Check if the login is in the list
                    if($roleMembers -contains $user.Name)
                    {
                        $userRoles += $role.Name
                    }
                }

                # Combine the results
                $result += $database | Select `
					@{N="DatabaseName";E={$database.Name}},`
					@{N="UserName";E={$user.Name}},`
					@{N="UserType"; E={$user.LoginType}},`
					@{N="DatabaseRoles";E={([string]::Join(",", $userRoles))}}
            }

            # Clear the array
            $userRoles = @()
        }
    }

    return $result
}

Export-ModuleMember -Function Get-SQLDatabasePrivileges


function Get-SQLServerPrivileges
{
    <# 
    .SYNOPSIS
        Returns each server login with their server roles
    .DESCRIPTION
        This function will return all the logins on the database server
        and check whether they are member of a server role.
    .PARAMETER  instance
        This is the instance that needs to be connected
    .EXAMPLE
        Get-SQLServerPrivileges "SQL01"
    .EXAMPLE
        Get-SQLServerPrivileges "SQL01\INST01"
    .EXAMPLE
        Get-SQLServerPrivileges -inst "SQL01\INST01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$inst = $null
    )
    
    # Check if assembly is loaded
    Load-Assembly -name 'Microsoft.SqlServer.SMO'

    # Check if the instance object is already initiated
    if($server -eq $null)
    {
        try{
            $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $inst
        }
        catch [Exception]
        {
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
    }

    # Create the result array
    $result = @()

    # Create the array for the server roles
    $serverRoles = @()

    # Get all the logins
    $logins = $server.Logins

    # Loop through the logins
    foreach($login in $logins)
    {
        
        if(($login.Name -notlike "##*"))
        {
            # Get all the server
            $serverRoles = ($login.ListMembers()) -join ","

            # Make the result
            if($serverRoles.Count -gt 1)
            {
                $result += $login | Select `
					Name,LoginType,CreateDate,DateLastModified,IsDisabled,`
					@{N="ServerRoles";E=([string]::Join(",", $serverRoles))} | Sort-Object Name 
            }
            else
            {
                $result += $login | Select `
					Name,LoginType,CreateDate,DateLastModified,IsDisabled,`
					@{N="ServerRoles";E={$serverRoles}} | Sort-Object Name 
            }

            # Clear the array
            $serverRoles = @()
        }
    }

    return $result

}

Export-ModuleMember -Function Get-SQLServerPrivileges


function Get-SQLAgentJobs
{
    
    <# 
    .SYNOPSIS
        Returns the SQL Server jobs 
    .DESCRIPTION
        The function return all the jobs present in the SQL Server with information
        like the jobtype, enabled or not, date created, last run date etc.
    .PARAMETER instance
        This is the instance that needs to be connected
    .EXAMPLE
        Get-SQLServerJobs "SQL01"
    .EXAMPLE
        Get-SQLServerJobs "SQL01\INST01"
    .EXAMPLE
        Get-SQLServerJobs -inst "SQL01\INST01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$inst = $null
    )

    # Check if assembly is loaded
    Load-Assembly -name 'Microsoft.SqlServer.SMO'

    # Check if the instance object is already initiated
    if($server -eq $null)
    {
        try{
            $server = New-Object ('Microsoft.SqlServer.Management.Smo.Server') $inst
        }
        catch [Exception]
        {
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
    }

    # Get the jobs
    $server.JobServer.Jobs

    # Create the result array
    $result = @()

    # Get the results
    $result = $jobs | Select `
		Name,JobType,IsEnabled,DateCreated,DateLastModified,LastRunDate,`
		LastRunOutcome,NextRunDate,OwnerLoginName,Category | Sort-Object Name 

    # Return the result
    return $result
}

Export-ModuleMember -Function Get-SQLAgentJobs

function Get-HostHarddisk
{
    <# 
    .SYNOPSIS
        Checks the host's harddisks
    .DESCRIPTION
        The function return the data of all the drives with size, available space, percentage used etc
    .PARAMETER hst
        This is the host that needs to be connected
    .EXAMPLE
        Get-HostHarddisk "SQL01"
    .EXAMPLE
        Get-HostHarddisk -hst "SQL01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$hst = $null
    )

    # Get the data
	$drives= Get-WmiObject -Class Win32_LogicalDisk -Computername $hst -Errorvariable errorvar | Where {$_.drivetype -eq 3}
    
    # Create the result array
    $result = @()

    # Get the results
    $result = $drives | Select -property `
		@{N="Disk";E={$_.DeviceID}},VolumeName, `
		@{N="FreeSpaceMB";E={"{0:N2}" -f ($_.Freespace/1Mb)}}, `
		@{N="SizeMB";E={"{0:N2}" -f ($_.Size/1Mb)}}, `
		@{N="PercentageUsed";E={"{0:N2}" -f (($_.Size - $_.FreeSpace) / $_.Size * 100)}}

    return $result
}

Export-ModuleMember -Function Get-HostHarddisk


function Get-HostHardware
{
    <# 
    .SYNOPSIS
        Checks the host's hardware
    .DESCRIPTION
        The function return the data of hardware in de host like number of processors
        manufacturer, current timezone etc
    .PARAMETER hst
        This is the host that needs to be connected
    .EXAMPLE
        Get-HostHardware "SQL01"
    .EXAMPLE
        Get-HostHardware -hst "SQL01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$hst = $null
    )

    # Get the data
	$computer = Get-Wmiobject -Class win32_computersystem -Computername $hst -Errorvariable errorvar
    
    $result = @()

    # Get the result
    $result = $computer | Select Description,NumberOfLogicalProcessors,NumberOfProcessors, `
		@{N="TotalPhysicalMemoryGB";E={"{0:N2}" -f ($_.TotalPhysicalMemory/1Gb)}}, `
		Model,Manufacturer,PartOfDomain,CurrentTimeZone,DaylightInEffect

    # Return the result
    return $result
}

Export-ModuleMember -Function Get-HostHardware

function Get-HostOperatingSystem
{
    <# 
    .SYNOPSIS
        Checks the host's OS
    .DESCRIPTION
        The function return the data of OS in de host like the architecture,
        the OS language, the version etc
    .PARAMETER hst
        This is the host that needs to be connected
    .EXAMPLE
        Get-HostOperatingSystems "SQL01"
    .EXAMPLE
        Get-HostOperatingSystems -hst "SQL01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$hst = $null
    )

    # Get the data
    $os = Get-WmiObject -Class win32_operatingsystem -Computername $hst -Errorvariable errorvar

    $result = @()

    # Get the results
    $result = $os | Select `
		OSArchitecture,OSLanguage,OSProductSuite,OSType,BuildNumbe,`
		BuildType,Version,WindowsDirectory,PlusVersionNumber,`
		@{N="FreePhysicalMemoryMB";E={"{0:N2}" -f ($_.FreePhysicalMemory / 1Mb)}},`
		@{N="FreeSpaceInPagingFilesMB";E={"{0:N2}" -f ($_.FreeSpaceInPagingFiles)}},`
		@{N="FreeVirtualMemoryMB";E={"{0:N2}" -f ($_.FreeVirtualMemory)}},`
		PAEEnabled,ServicePackMajorVersion,ServicePackMinorVersion

    #return the result
    return $result

}

Export-ModuleMember -Function Get-HostOperatingSystem

function Get-HostSQLServerServices
{
    <# 
    .SYNOPSIS
        Get the SQL Server services
    .DESCRIPTION
        The function return all the services present on the server regarding SQL Server
    .PARAMETER hst
        This is the host that needs to be connected
    .EXAMPLE
        Get-HostSQLServerServices "SQL01"
    .EXAMPLE
        Get-HostSQLServerService -hst "SQL01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param
    (
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$hst = $null
    )

    return Get-WmiObject win32_Service -Computer $hst | where {$_.DisplayName -match "SQL Server"} | `
		select SystemName, DisplayName, Name, State, Status, StartMode, StartName 
}

Export-ModuleMember -Function Get-HostSQLServerServices

function Get-HostSystemInformation()
{
	<# 
    .SYNOPSIS
        Get the system information of the host
    .DESCRIPTION
        Select information from the system like the domain, manufacturer, model etc.
    .PARAMETER hst
        This is the host that needs to be connected
    .EXAMPLE
        Get-HostSystemInformation "SQL01"
    .EXAMPLE
        Get-HostSystemInformation -hst "SQL01"
    .INPUTS
    .OUTPUTS
        System.Array
    .NOTES
    .LINK
    #>
    param(
        [Parameter(Mandatory = $true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$hst = $null
    )

    $result = @()

    $data = Get-WmiObject -class "Win32_ComputerSystem" -Namespace "root\CIMV2" -ComputerName $hst

    $result = $data | Select `
        Name,Domain,Manufacturer,Model, `
        NumberOfLogicalProcessors,NumberOfProcessors,LastLoadInfo, `
        @{Name='TotalPhysicalMemoryMB';Expression={[math]::round(($_.TotalPhysicalMemory / 1024 / 1024))}}


    return $result

}

Export-ModuleMember -Function Get-HostSystemInformation

function Load-Assembly
{
    <# 
    .SYNOPSIS
        Check if a assembly is loaded and load it if neccesary
    .DESCRIPTION
        The script will check if an assembly is already loaded.
        If it isn't already loaded it will try to load the assembly
    .PARAMETER  name
        Full name of the assembly to be loaded
    .EXAMPLE
        Load-Assembly -name 'Microsoft.SqlServer.SMO'
    .INPUTS
    .OUTPUTS
    .NOTES
    .LINK
    #>
     [CmdletBinding()]
     param(
          [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()]
          [String] $name
     )
     
     if(([System.AppDomain]::Currentdomain.GetAssemblies() | where {$_ -match $name}) -eq $null)
     {
        try{
            [System.Reflection.Assembly]::LoadWithPartialName($name) | Out-Null
        } 
        catch [System.Exception]
        {
            Write-Host "Failed to load assembly!" -ForegroundColor Red
            Write-Host "$_.Exception.GetType().FullName, $_.Exception.Message" -ForegroundColor Red
        }
     }
}
