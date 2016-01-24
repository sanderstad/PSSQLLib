# PSSQLLib
Powershell SQL Server Library 

## Features

The library has the following features:

* Get the host harddisk information
* Get the host hardware
* Get the host operating system information
* Get the host uptime
* Get the SQL Server instance settings
* Get the SQL Server instance configuration settings
* Get the SQL Server instance uptime
* Get the SQL Server login server privileges
* Get the SQL Server databases
* Get the SQL Server database files
* Get the SQL Server database users
* Get the SQL Server database user privileges
* Get the SQL Server Agent jobs
* Get the SQL Server disk latencies

## Installation
Unzip the file.

Make a directory (if not already present) named "PSSQLLib" in one of the following standard Powershell Module directories:
* $Home\Documents\WindowsPowerShell\Modules (%UserProfile%\Documents\WindowsPowerShell\Modules)
* $Env:ProgramFiles\WindowsPowerShell\Modules (%ProgramFiles%\ WindowsPowerShell\Modules)
* $Systemroot\System32\WindowsPowerShell\v1.0\Modules (%systemroot%\System32\ WindowsPowerShell\v1.0\Modules)

Place both the psd1 and psm1 files in the module directory created earlier.

Execute the following command in a PowerShell command screen:
  Import-Module PSSQLLib

To check if the module is imported correctly execute the following command:
  Get-Command -Module PSSQLLib
  or
  Get-Module -Name PSSQLLib

You should be able to see a list of functions
