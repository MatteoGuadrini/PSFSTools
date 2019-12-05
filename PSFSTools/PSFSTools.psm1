New-Alias -Name "mkprj" -Value New-ProjectFolder -Option ReadOnly
New-Alias -Name "rdold" -Value Remove-OlderThan -Option ReadOnly
New-Alias -Name "bckar" -Value Backup-ArchiveFiles -Option ReadOnly
New-Alias -Name "ntemp" -Value New-TemplateFileServer -Option ReadOnly
New-Alias -Name "wfs" -Value Write-FileServerFromTemplate -Option ReadOnly

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
        [parameter(mandatory = $true)][ValidateNotNull()][string]$Name,
        [parameter(mandatory = $true)][ValidateNotNull()][string]$LitheralPath,
        [parameter(mandatory = $true)][ValidateSet("Reader", "Writer", "Owner")][array]$Permission,
        [parameter(mandatory = $true)][ValidateNotNull()][string]$OU,
        [parameter(mandatory = $false)][string]$DomainController,
        [parameter(mandatory = $false)][switch]$Log
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
        $Domain = ($OrganizationalUnit -split "," | Select-String "DC=" | ForEach-Object { $_ -replace "DC=", "" }) -join "."
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
        $OwnerGroupName = (("$Name" + "_Owners").Replace(" ", "_")).Trim()
        Write-Verbose -Message "Create a permission for Owner group: $OwnerGroupName"
        ## Name max 64 char
        $OwnerGroupName = if ($OwnerGroupName.Length -gt 64) { $OwnerGroupName.Substring(0, 64) } else { $OwnerGroupName }
        $OwnerGroupSAM = ((("$Name" + ".owners").Replace(" ", "_")).Trim()).ToLower()
        ## Samaccountname max 256
        $OwnerGroupSAM = if ($OwnerGroupSAM.Length -gt 256) { $OwnerGroupSAM.Substring(0, 256) } else { $OwnerGroupSAM }
        New-ADGroup -Name $OwnerGroupName -SamAccountName $OwnerGroupSAM -GroupCategory Security -GroupScope Global -DisplayName "$Name Owners" -Path $OU -Description "Owners of project folder $FullPath on $($env:computername)"
        do {
            Start-Sleep -Seconds 2
        } until (Get-ADGroup -Identity $OwnerGroupSAM -ErrorAction SilentlyContinue)
        Invoke-Command -Session $ActiveDirectorySession -ScriptBlock { repadmin /syncall /AdeP } | Out-Null
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
        $WriterGroupName = (("$Name" + "_Writers").Replace(" ", "_")).Trim()
        Write-Verbose -Message "Create a permission for Owner group: $WriterGroupName"
        ## Name max 64 char
        $WriterGroupName = if ($WriterGroupName.Length -gt 64) { $WriterGroupName.Substring(0, 64) } else { $WriterGroupName }
        $WriterGroupSAM = ((("$Name" + ".writers").Replace(" ", "_")).Trim()).ToLower()
        ## Samaccountname max 256
        $WriterGroupSAM = if ($WriterGroupSAM.Length -gt 256) { $WriterGroupSAM.Substring(0, 256) } else { $WriterGroupSAM }
        New-ADGroup -Name $WriterGroupName -SamAccountName $WriterGroupSAM -GroupCategory Security -GroupScope Global -DisplayName "$Name Writers" -Path $OU -Description "Writers of project folder $FullPath on $($env:computername)"
        do {
            Start-Sleep -Seconds 2
        } until (Get-ADGroup -Identity $WriterGroupSAM -ErrorAction SilentlyContinue)
        Invoke-Command -Session $ActiveDirectorySession -ScriptBlock { repadmin /syncall /AdeP } | Out-Null
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
        $ReaderGroupName = (("$Name" + "_Readers").Replace(" ", "_")).Trim()
        Write-Verbose -Message "Create a permission for Owner group: $ReaderGroupName"
        ## Name max 64 char
        $ReaderGroupName = if ($ReaderGroupName.Length -gt 64) { $ReaderGroupName.Substring(0, 64) } else { $ReaderGroupName }
        $ReaderGroupSAM = ((("$Name" + ".readers").Replace(" ", "_")).Trim()).ToLower()
        ## Samaccountname max 256
        $ReaderGroupSAM = if ($ReaderGroupSAM.Length -gt 256) { $ReaderGroupSAM.Substring(0, 256) } else { $ReaderGroupSAM }
        New-ADGroup -Name $ReaderGroupName -SamAccountName $ReaderGroupSAM -GroupCategory Security -GroupScope Global -DisplayName "$Name Readers" -Path $OU -Description "Readers of project folder $FullPath on $($env:computername)"
        do {
            Start-Sleep -Seconds 2
        } until (Get-ADGroup -Identity $ReaderGroupSAM -ErrorAction SilentlyContinue)
        Invoke-Command -Session $ActiveDirectorySession -ScriptBlock { repadmin /syncall /AdeP } | Out-Null
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
        [parameter(mandatory = $true)][ValidateNotNull()][string]$Path,
        $Days = 7,
        [parameter(mandatory = $false)][switch]$Recurse
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
        [parameter(mandatory = $true)][ValidateNotNull()][string]$Path,
        $Years = 1,
        [parameter(mandatory = $true)][ValidateNotNull()][string]$ArchivePath,
        [parameter(mandatory = $false)][array]$Exclude,
        [parameter(mandatory = $false)][switch]$AllFiles,
        [parameter(mandatory = $false)][switch]$DeleteEmptyFolders,
        [parameter(mandatory = $false)][switch]$Log
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
            $Pattern += "|" + $Exclusion -replace "\\", "\\" -replace ":", "\:" -replace "\.", "\."
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
            $Destination = ("$ArchivePath\$Year\" + ($folder.FullName -replace "(^[A-Za-z]\:\\)", "")) -replace "\\$", ""
            Write-Verbose -Message "Set destination: $Destination"
            # Check if all files in a folder are older than $Year
            $all = Get-ChildItem -Path $folder.FullName -File | Where-Object { $_.FullName -notmatch $Pattern } | Measure-Object
            $older = Get-ChildItem -Path $folder.FullName -File | Where-Object { $_.FullName -notmatch $Pattern -and $_.LastAccessTime -lt $OlderThan } | Measure-Object
            Write-Verbose -Message "Check if all files in folder $($folder.FullName) are older than $OlderThan; all is $($all.Count) - older is $($older.Count)"
            if (($all.Count -eq $older.Count) -and ($all.Count -ne 0)) {
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
        foreach ($file in (Get-ChildItem -Path $Path -File -Recurse | Where-Object { $_.FullName -notmatch $Pattern -and $_.LastAccessTime -lt $OlderThan } )) {
            $Destination = ("$ArchivePath\$Year\" + ($file.FullName -replace "(^[A-Za-z]\:\\)", "")) -replace "\\$", ""
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

function New-TemplateFileServer () {
    <#
    .SYNOPSIS
        Create file server structure template.
    .DESCRIPTION
        Create a xml default template for a file server structure.
    .EXAMPLE
        New-TemplateFileServer -Path C:\Temp\fs1.xml
    #>
    [CmdletBinding()]
    param (
        [parameter(mandatory = $true)][string] $Path
    )
    $template = @"
<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<!-- Root folder -->
<folder name="root">
    <!-- Permission local group g1 -->
    <permission inheritance="true|false" type="allow|deny" full="true|false" write="true|false" read="true|false">WORKGROUP\g1</permission>
    <!-- d1 folder -->
    <folder name="d1">
        <!-- Permission local group g1 -->
        <permission inheritance="true|false" type="allow|deny" full="true|false" write="true|false" read="true|false">WORKGROUP\g1</permission>
        <!-- Permission ldap group g2 -->
        <permission inheritance="true|false" type="allow|deny" full="true|false" write="true|false" read="true|false">DOMAIN\g2</permission>
        <!-- s2 subfolder -->
        <folder name="s1">
            <!-- Permission ldap group g2 -->
            <permission inheritance="true|false" type="allow|deny" full="true|false" write="true|false" read="true|false">DOMAIN\g2</permission>
        </folder>
    </folder>
    <!-- d2 folder -->
    <folder name="d2">
        <!-- Permission local group g1 -->
        <permission inheritance="true|false" type="allow|deny" full="true|false" write="true|false" read="true|false">WORKGROUP\g1</permission>
        <!-- Permission ldap group g3 -->
        <permission inheritance="true|false" type="allow|deny" full="true|false" write="true|false" read="true|false">DOMAIN\g3</permission>
    </folder>
</folder>
"@
    Out-File -FilePath $Path -Encoding utf8 -InputObject $template
    if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
        Write-Host "New template $Path"
    } else {
        Write-Error -Message "Unable to write a template $Path"
    }
}

function Write-FileServerFromTemplate () {
    <#
    .SYNOPSIS
        Create or modify structure of file server based on template file.
    .DESCRIPTION
        Create or modify structure of file server based on template file.
        The file is a xml file create with New-TemplateFileServer.
    .EXAMPLE
        Write-FileServerFromTemplate -Template C:\Temp\fs1.xml
    .EXAMPLE
        Write-FileServerFromTemplate -Template C:\Temp\fs1.xml -RootPath D:\FS
        .EXAMPLE
        Write-FileServerFromTemplate -Template C:\Temp\fs1.xml -RootPath D:\FS -DeleteDiff
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [parameter(mandatory = $true)][string] $Template,
        [string] $RootPath = $($PWD.Path),
        [switch] $DeleteDiff,
        [switch] $ForceDiff,
        [switch] $ForceACL
    )
    # Read Template
    try {
        [xml] $Template = Get-Content -Path $Template
    } catch [System.Management.Automation.ArgumentTransformationMetadataException] {
        throw "$Template is not a xml format."
    }
    # Set root
    $root = Join-Path -Path $RootPath -ChildPath $Template.folder.name
    Write-Verbose "root $root"
    # Create a function than walk to xml child
    function createFSTree ($xml, $root) {
        $fc = 0
        foreach ($e in $xml) {
            # Create folder structure
            if ($e.ParentNode.folder -as [array]) {
                $parent = Join-Path -Path $root -ChildPath $e.ParentNode.folder[$fc].name
                $tempDirs = $e.ParentNode.folder.name
            } else {
                $parent = Join-Path -Path $root -ChildPath $e.ParentNode.folder.name
                $tempDirs = @($e.ParentNode.folder.name)
            }
            # Create folder if not exists
            if (-not(Test-Path -Path $parent -ErrorAction SilentlyContinue)) {
                New-Item -Path $parent -ItemType Directory | Out-Null
                Write-Host "$parent folder created" -ForegroundColor Green
            } else {
                Write-Host "$parent folder exists" -ForegroundColor Yellow
            }
            # Check DeleteOld
            if ($DeleteDiff.IsPresent -and $e.ParentNode.folder) {
                $folders = Get-ChildItem -Path (Get-Item -Path $parent).parent.FullName -Directory
                foreach ($folder in $folders) {
                    if ($tempdirs -and $tempDirs -notcontains $folder.Name) {
                        if ($ForceDiff -or $PSCmdlet.ShouldContinue("Are you sure delete folder $($folder.FullName) ?", "Delete folder $($folder.FullName).")) {
                            Remove-Item -Path $folder.FullName -Recurse -Force
                            Write-Host "Deleted folder $($folder.FullName)" -ForegroundColor Red
                        }
                    }
                }
            }
            # Apply permissions
            $ACL = Get-Acl -Path $RootPath
            [bool]$changed = $false
            foreach ($p in $e.permission) {
                $acl_map = [pscustomobject]@{
                    full        = "FullControl"
                    write       = "Read,Write,Modify"
                    read        = "Read,ReadAndExecute,ListDirectory"
                    type        = $p.type
                    inheritance = "InheritOnly"
                    group       = $p."#text"
                }
                Write-Verbose "Group: $($acl_map.group)"
                $ACL.SetAccessRuleProtection($true, $true)
                $InheritanceFlag = @()
                $InheritanceFlag += [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
                $InheritanceFlag += [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
                $PropagationFlag = $(
                    if ($p.inheritance -eq "true") { $acl_map.inheritance }
                    else { "None" }
                )
                $objType = $(
                    if ($acl_map.type -eq "allow") {
                        0
                    } else {
                        1
                    }
                )
                $colRights = $(
                    if ($p.full -eq "true") { $acl_map.full }
                    elseif ($p.write -eq "true") { $acl_map.write }
                    elseif ($p.read -eq "true") { $acl_map.read }
                )
                $objGroup = New-Object System.Security.Principal.NTAccount($acl_map.group -split '\', -1, 'SimpleMatch')
                $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule($objGroup, $colRights, $InheritanceFlag, $PropagationFlag, $objType)
                $currentAcl = Get-Acl -Path $parent
                $ACL.SetAccessRule($objACE)
                # Check if changed permission
                foreach ($permission in $objACE) {
                    if ($currentAcl.Access.IdentityReference -notcontains $permission.IdentityReference) {
                        [bool]$changed = $true
                    } else {
                        foreach ($c in $currentAcl.Access) {
                            # Check IdentityReference
                            if ($c.IdentityReference -eq $permission.IdentityReference) {
                                # Check AccessControlType
                                if ($c.AccessControlType -ne $permission.AccessControlType) {
                                    [bool]$changed = $true
                                    continue
                                }
                                # Check FileSystemRights
                                if ($c.FileSystemRights -ne $permission.FileSystemRights) {
                                    [bool]$changed = $true
                                    continue
                                }
                            }
                        }
                    }
                }
            }
            # Check if removed permission
            foreach ($permission in $currentAcl.Access) {
                if ($ACL.Access.IdentityReference -notcontains $permission.IdentityReference) {
                    [bool]$changed = $true
                }
            }
            if ($changed) { 
                (Get-Item -Path $parent).SetAccessControl($ACL)
                Write-Host -ForegroundColor DarkGreen $ACL.AccessToString
            } elseif ($ForceACL.IsPresent) { 
                (Get-Item -Path $parent).SetAccessControl($ACL)
                Write-Host -ForegroundColor DarkGreen $ACL.AccessToString
            }
            # Check if child has a folder
            if ($e.folder.folder) {
                createFSTree -xml $e.folder -root $parent
            }
            $fc++
        }
    }
    # Walk to xml
    createFSTree -xml $Template.folder -root $root
}
