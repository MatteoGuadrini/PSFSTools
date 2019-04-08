New-Alias -Name "mkprj" -Value New-ProjectFolder -Option ReadOnly
New-Alias -Name "rdold" -Value Remove-OlderThan -Option ReadOnly
New-Alias -Name "bckar" -Value Backup-ArchiveFiles -Option ReadOnly

function New-ProjectFolder () {
    <# 
    .SYNOPSIS 
        New project folder
    .DESCRIPTION 
        Create a project folder and assign ACL with three Active Directory groups:
        Owner
        Writer
        Reader
    .EXAMPLE
        New-ProjectFolder -Name Test -LitheralPath C:\Project -Permission Owner,Writer,Reader -OU "OU=Test,DC=Test,DC=local"
    .EXAMPLE
        New-ProjectFolder -Name "Test 2" -LitheralPath C:\Project -Permission Writer,Reader -OU "OU=Test,DC=Test,DC=local" -DomainController srv1.dc.local
    #>
    [CmdletBinding()]
    param (
        [parameter(mandatory=$true)][ValidateNotNull()][string]$Name,
        [parameter(mandatory=$true)][ValidateNotNull()][string]$LitheralPath,
        [parameter(mandatory=$true)][ValidateSet("Reader","Writer","Owner")][array]$Permission,
        [parameter(mandatory=$true)][ValidateNotNull()][string]$OU,
        [parameter(mandatory=$false)][string]$DomainController,
        [parameter(mandatory=$false)][switch]$Log
    )
    Set-Variable -Name $OU -Option AllScope
    if ($DomainController) {
        Set-Variable -Name $DomainController -Option AllScope
    }
    # Verify if Log file exists
    if ($Log.IsPresent) {
        if (!([System.Diagnostics.EventLog]::SourceExists("ProjectFolder"))) {
            New-EventLog -LogName "Application" -Source "ProjectFolder"
        }
    }

    function Get-Error () {
        if ($Error) {
            return $false
        } else {
            return $true
        }
    }
    
    function Get-DomainClass ($OrganizationalUnit) {
        $Domain = ($OrganizationalUnit -split "," | Select-String "DC=" | ForEach-Object { $_ -replace "DC=",""}) -join "."
        return $Domain
    }
    
    function Connect-DomainController () {
        if ($DomainController) {
            $IPAddress = ([System.Net.Dns]::GetHostAddresses($DomainController)).IPAddressToString
            if (Test-Connection -ComputerName $IPAddress -Quiet -Count 1) {
                $ActiveDirectorySession = New-PSSession -ConfigurationName "Microsoft.PowerShell" -ComputerName $DomainController -Authentication Kerberos
                Import-PSSession $ActiveDirectorySession -AllowClobber -DisableNameChecking -Module ActiveDirectory | Out-Null
            }
            Write-Verbose -Message "Connected to domain controller: $DomainController"
        } else {
            $DomainClass = Get-DomainClass -OrganizationalUnit $OU
            $IPAddress = ([System.Net.Dns]::GetHostAddresses($DomainClass)).IPAddressToString -split " "
            foreach ($IP in $IPAddress) {
                $DomainController = ([System.Net.Dns]::GetHostbyAddress($IP)).HostName
                if (Test-Connection -ComputerName $DomainController -Quiet -Count 1) {
                    $ActiveDirectorySession = New-PSSession -ConfigurationName "Microsoft.PowerShell" -ComputerName $DomainController -Authentication Kerberos
                    Import-PSSession $ActiveDirectorySession -AllowClobber -DisableNameChecking -Module ActiveDirectory | Out-Null
                    Write-Verbose -Message "Connected to domain controller: $DomainController"
                    break
                }
            }
        }
        Get-Error
        $Global:ActiveDirectorySession = $ActiveDirectorySession
    }
    
    $Error.clear()
    
    $FullPath = "$LitheralPath\$Name"
    # Check if folder already exists
    Write-Verbose -Message "Check if folder project $FullPath exists"
    if (Test-Path $FullPath) {
        $ErrorActionPreference = "Stop"
        Write-Error -Message "Project already exists."
    }
    
    # Connect to domain controller
    if (-not(Connect-DomainController)) {
        $ErrorActionPreference = "Stop"
        Write-Error -Message "Not connect to domain controller."
    }
    
    # Create folder
    Write-Verbose -Message "Create folder $FullPath"
    New-Item -Path $FullPath -ItemType Directory | Out-Null
    
    # Remove inheritance and add Administrators group to folder
    Write-Verbose -Message "Remove inheritance and add Administrators group to folder $FullPath"
    $Domain = Get-DomainClass -OrganizationalUnit $OU
    $ACL = Get-Acl -Path $FullPath
    $ACL.SetAccessRuleProtection($True, $False)
    $InheritanceFlag = @()
    $InheritanceFlag += [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
    $InheritanceFlag += [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $objType = [System.Security.AccessControl.AccessControlType]::Allow
    $colRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
    $objGroup = New-Object System.Security.Principal.NTAccount("BUILTIN", "Administrators")
    $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule($objGroup, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
    $ACL.AddAccessRule($objACE)
    $ACL.SetOwner($objGroup)
    Set-ACL -Path $FullPath -AclObject $ACL
    $ACL = Get-Acl -Path $FullPath
    
    # Create a permission groups and set permission to folder
    Write-Verbose -Message "Create a permission groups and set permission to folder $FullPath"
    if ($Permission -contains "Owner") {
        # Create Active Directory group
        $OwnerGroupName = (("$Name" + "_Owners").Replace(" ","_")).Trim()
        Write-Verbose -Message "Create a permission for Owner group: $OwnerGroupName"
        ## Name max 64 char
        $OwnerGroupName = if ($OwnerGroupName.Length -gt 64) {$OwnerGroupName.Substring(0,64)} else {$OwnerGroupName}
        $OwnerGroupSAM = ((("$Name" + ".owners").Replace(" ","_")).Trim()).ToLower()
        ## Samaccountname max 256
        $OwnerGroupSAM = if ($OwnerGroupSAM.Length -gt 256) {$OwnerGroupSAM.Substring(0,256)} else {$OwnerGroupSAM}
        New-ADGroup -Name $OwnerGroupName -SamAccountName $OwnerGroupSAM -GroupCategory Security -GroupScope Global -DisplayName "$Name Owners" -Path $OU -Description "Owners of project folder $FullPath on $($env:computername)"
        do {
            Start-Sleep -Seconds 2
        } until (Get-ADGroup -Identity $OwnerGroupSAM -ErrorAction SilentlyContinue)
        Invoke-Command -Session $ActiveDirectorySession -ScriptBlock {repadmin /syncall /AdeP} | Out-Null
        # Assign permission to folder with Active Directory group
        $colRights = [System.Security.AccessControl.FileSystemRights]"FullControl"
        $objGroup = New-Object System.Security.Principal.NTAccount($Domain, $OwnerGroupSAM)
        $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule($objGroup, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
        $ACL.AddAccessRule($objACE)
        Write-Verbose -Message "Assign permission FullControl to $OwnerGroupName on $FullPath"
        Set-ACL -Path $FullPath -AclObject $ACL
    }
    if ($Permission -contains "Writer") {
        # Create Active Directory group
        $WriterGroupName = (("$Name" + "_Writers").Replace(" ","_")).Trim()
        Write-Verbose -Message "Create a permission for Owner group: $WriterGroupName"
        ## Name max 64 char
        $WriterGroupName = if ($WriterGroupName.Length -gt 64) {$WriterGroupName.Substring(0,64)} else {$WriterGroupName}
        $WriterGroupSAM = ((("$Name" + ".writers").Replace(" ","_")).Trim()).ToLower()
        ## Samaccountname max 256
        $WriterGroupSAM = if ($WriterGroupSAM.Length -gt 256) {$WriterGroupSAM.Substring(0,256)} else {$WriterGroupSAM}
        New-ADGroup -Name $WriterGroupName -SamAccountName $WriterGroupSAM -GroupCategory Security -GroupScope Global -DisplayName "$Name Writers" -Path $OU -Description "Writers of project folder $FullPath on $($env:computername)"
        do {
            Start-Sleep -Seconds 2
        } until (Get-ADGroup -Identity $WriterGroupSAM -ErrorAction SilentlyContinue)
        Invoke-Command -Session $ActiveDirectorySession -ScriptBlock {repadmin /syncall /AdeP} | Out-Null
        # Assign permission to folder with Active Directory group
        $colRights = [System.Security.AccessControl.FileSystemRights]"Read,Write,Modify"
        $objGroup = New-Object System.Security.Principal.NTAccount($Domain, $WriterGroupSAM)
        $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule($objGroup, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
        $ACL.AddAccessRule($objACE)
        Write-Verbose -Message "Assign permissions Read,Write,Modify to $WriterGroupName on $FullPath"
        Set-ACL -Path $FullPath -AclObject $ACL
    }
    if ($Permission -contains "Reader") {
        # Create Active Directory group
        $ReaderGroupName = (("$Name" + "_Readers").Replace(" ","_")).Trim()
        Write-Verbose -Message "Create a permission for Owner group: $ReaderGroupName"
        ## Name max 64 char
        $ReaderGroupName = if ($ReaderGroupName.Length -gt 64) {$ReaderGroupName.Substring(0,64)} else {$ReaderGroupName}
        $ReaderGroupSAM = ((("$Name" + ".readers").Replace(" ","_")).Trim()).ToLower()
        ## Samaccountname max 256
        $ReaderGroupSAM = if ($ReaderGroupSAM.Length -gt 256) {$ReaderGroupSAM.Substring(0,256)} else {$ReaderGroupSAM}
        New-ADGroup -Name $ReaderGroupName -SamAccountName $ReaderGroupSAM -GroupCategory Security -GroupScope Global -DisplayName "$Name Readers" -Path $OU -Description "Readers of project folder $FullPath on $($env:computername)"
        do {
            Start-Sleep -Seconds 2
        } until (Get-ADGroup -Identity $ReaderGroupSAM -ErrorAction SilentlyContinue)
        Invoke-Command -Session $ActiveDirectorySession -ScriptBlock {repadmin /syncall /AdeP} | Out-Null
        # Assign permission to folder with Active Directory group
        $colRights = [System.Security.AccessControl.FileSystemRights]"Read,ReadAndExecute,ListDirectory"
        $objGroup = New-Object System.Security.Principal.NTAccount($Domain, $ReaderGroupSAM)
        $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule($objGroup, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
        $ACL.AddAccessRule($objACE)
        Write-Verbose -Message "Assign permissions Read,ReadAndExecute,ListDirectory to $ReaderGroupName on $FullPath"
        Set-ACL -Path $FullPath -AclObject $ACL
    }
    # Log the event
    if ($Log.IsPresent) {
        if ($?) {
            Write-EventLog -LogName "Application" -Source "ProjectFolder" -EntryType "Information" -EventID 1 -Category 0 -Message "Project folder $FullPath has been created with permissions "@Permission
        } else {
            Write-EventLog -LogName "Application" -Source "ProjectFolder" -EntryType "Error" -EventID 1 -Category 0 -Message "Check the project folder $FullPath; an error are occurred"
        }
    }
    
    # Remove all session
    Get-PSSession | Remove-PSSession
    
    Write-Host "Created project folder $FullPath with permission: "@Permission
}

function Remove-OlderThan () {
    <# 
    .SYNOPSIS 
        Remove files and folders older than days
    .DESCRIPTION 
        Remove files and folders older than days
    .EXAMPLE
        Remove-OlderThan -Path C:\Temp -Days 15 -Recurse
    #>
    [CmdletBinding()]
    param (
        [parameter(mandatory=$true)][ValidateNotNull()][string]$Path,
        $Days = 7,
        [parameter(mandatory=$false)][switch]$Recurse
    )

    $Days = (Get-Date).AddDays(-$Days)
    
    if ($Recurse.IsPresent) {
        Write-Verbose -Message "Delete files older than $Days, recursively in all the folders"
        # Delete files older than the $Days.
        Get-ChildItem -Path $Path -Recurse -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $Days } | Remove-Item -Force -Recurse -Confirm:$false
    } else {
        # Delete files older than the $Days.
        Write-Verbose -Message "Delete files older than $Days"
        Get-ChildItem -Path $Path -Force | Where-Object { !$_.PSIsContainer -and $_.CreationTime -lt $Days } | Remove-Item -Force -Confirm:$false
    }
    # Delete any empty directories left behind after deleting the old files.
    Write-Verbose -Message "Delete any empty directories left behind after deleting the old files recursively in all the folders"
    Get-ChildItem -Path $Path -Recurse -Force | Where-Object { $_.PSIsContainer -and (Get-ChildItem -Path $_.FullName -Recurse -Force | Where-Object { !$_.PSIsContainer }).Length -eq 0 } | Remove-Item -Force -Recurse -Confirm:$false
}

function Backup-ArchiveFiles () {
    <#
    .SYNOPSIS
        Archive files
    .DESCRIPTION
        Archive files older than a number of years
    .EXAMPLE
        Backup-ArchivedFiles -Path C:\Temp -Years 2 -ArchivePath D:\Temp
    .EXAMPLE
        Backup-ArchivedFiles -Path C:\Temp -Years 2 -ArchivePath D:\Temp -Exclude path1,"folder with space" -AllFiles
    #>
    [CmdletBinding()]
    param (
        [parameter(mandatory=$true)][ValidateNotNull()][string]$Path,
        $Years = 1,
        [parameter(mandatory=$true)][ValidateNotNull()][string]$ArchivePath,
        [parameter(mandatory=$false)][array]$Exclude,
        [parameter(mandatory=$false)][switch]$AllFiles,
        [parameter(mandatory=$false)][switch]$DeleteEmptyFolders,
        [parameter(mandatory=$false)][switch]$Log
    )
    # Verify if Log file exists
    if ($Log.IsPresent) {
        if (!([System.Diagnostics.EventLog]::SourceExists("Archive"))) {
            New-EventLog -LogName "Application" -Source "Archive"
        }
    }
    # Calculate time span
    $OlderThan = (Get-Date).AddYears(-$Years)
    $Year = $OlderThan.Year
    Write-Verbose -Message "Calculate time span: $OlderThan"
    # Prepare exclusion patterns
    if ($Exclude) {
        foreach ($Exclusion in $Exclude) {
            $Pattern += "|" + $Exclusion -replace "\\","\\" -replace ":","\:" -replace "\.","\."
        }
        $Pattern = $Pattern.TrimStart("|")
    } else {
        $Pattern = [void]
    }
    Write-Verbose -Message "Prepare exclusion patterns: $Pattern"
    # Consider all files or not
    if ($AllFiles.IsPresent) {
        # Loop the path: only folders
        foreach ($folder in (Get-ChildItem -Path $Path -Directory -Recurse | Where-Object { $_.FullName -notmatch $Pattern } )) {
            $Destination = ("$ArchivePath\$Year\" + ($folder.FullName -replace "(^[A-Za-z]\:\\)","")) -replace "\\$",""
            Write-Verbose -Message "Set destination: $Destination"
            # Check if all files in a folder are older than $Year
            $all = Get-ChildItem -Path $folder.FullName -File | Where-Object { $_.FullName -notmatch $Pattern } | Measure-Object
            $older = Get-ChildItem -Path $folder.FullName -File | Where-Object { $_.FullName -notmatch $Pattern -and $_.LastAccessTime -lt $OlderThan } | Measure-Object
            Write-Verbose -Message "Check if all files in folder $($folder.FullName) are older than $OlderThan; all is $($all.Count) - older is $($older.Count)"
            if ($all.Count -eq $older.Count) {
                Write-Verbose -Message "Move files into $($folder.FullName) in $Destination"
                if (-not (Test-Path -Path $Destination)) { New-Item -Path $Destination -ItemType Directory | Out-Null }
                Get-ChildItem -Path $folder.FullName -File | Where-Object { $_.FullName -notmatch $Pattern } | Move-Item -Destination "$Destination\" -Force -Confirm:$false
                if ($Log.IsPresent) {
                    if (Test-Path $Destination) {
                        Write-EventLog -LogName "Application" -Source "Archive" -EntryType "Information" -EventID 1 -Category 0 -Message "Archived file $($folder.FullName) to $Destination successfully"
                    } else {
                        Write-EventLog -LogName "Application" -Source "Archive" -EntryType "Error" -EventID 1 -Category 0 -Message "Archived file $($folder.FullName) failed to $Destination"
                    }
                }
            }
        }
    } else {
        # Loop the path: only files
        foreach ($file in (Get-ChildItem -Path $Path -File -Recurse | Where-Object { $_.FullName -notmatch $Pattern } )) {
            $Destination = ("$ArchivePath\$Year\" + ($file.FullName -replace "(^[A-Za-z]\:\\)","")) -replace "\\$",""
            Write-Verbose -Message "Move file $($file.FullName) in $Destination"
            if (-not (Test-Path -Path $(Split-Path -Path $Destination))) { New-Item -Path $(Split-Path -Path $Destination) -ItemType Directory | Out-Null }
            Move-Item -Path $file.FullName -Destination $Destination -Force -Confirm:$false
            if ($Log.IsPresent) {
                if (Test-Path $Destination) {
                    Write-EventLog -LogName "Application" -Source "Archive" -EntryType "Information" -EventID 1 -Category 0 -Message "Archived file $($file.FullName) to $Destination"
                } else {
                    Write-EventLog -LogName "Application" -Source "Archive" -EntryType "Error" -EventID 1 -Category 0 -Message "Archived file $($file.FullName) failed to $Destination"
                }
            }
        }
    }
    # Delete empty folders...or not
    if ($DeleteEmptyFolders.IsPresent) {
        Write-Verbose -Message "Delete any empty directories left behind after deleting the old files."
        Get-ChildItem -Path $Path -Recurse -Force | Where-Object { $_.PSIsContainer -and (Get-ChildItem -Path $_.FullName -Recurse -Force | Where-Object { !$_.PSIsContainer }).Length -eq 0 } | Remove-Item -Force -Recurse -Confirm:$false
    }
}