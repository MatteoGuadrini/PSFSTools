<img src="https://i.ibb.co/xq6c0Xj/psfstools.png" alt="PSFSTools">

# PSFSTools is:
Simple file server tools for complex task.
## A powershell module
**PSFSTools** is a powershell module. Download and copying it under `%Windir%\System32\WindowsPowerShell\v1.0\Modules` for all users or under `%UserProfile%\Documents\WindowsPowerShell\Modules` for the current user or install through [PowershellGallery](https://www.powershellgallery.com/packages/PSFSTools).
> ATTENTION: This module is not signed. Before import or execute cmdlet on this module, see [about_signing](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing) session. Verify execution of scripts is allowed with `Get-ExecutionPolicy` (should be RemoteSigned or Unrestricted). If scripts are not enabled, run PowerShell as Administrator and call ```Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm```.

You can also install it via git:
```
git clone https://github.com/MatteoGuadrini/PSFSTools.git
cd PSFSTools
copy /Y PSFSTools %Windir%\System32\WindowsPowerShell\v1.0\Modules
```
## A collection of tool
Various task on a file server, require execution complexity; how and when to archive, create folders assigned to certain groups or delete files older than one month or delete folders that are no longer used.

This module, with  
## Tools:
* New-ProjectFolder
* Remove-OlderThan
* Backup-ArchiveFiles
* New-TemplateFileServer
* Write-FileServerFromTemplate
* Get-DedupFiles

For more module info, run:
```powershell
Get-Help about_psfstools
```

### New-ProjectFolder
Creates a project folder and assign ACL with three Active Directory groups: Owner, Writer, Reader. For example:
```powershell
New-ProjectFolder -Name Test -LitheralPath C:\Project -Permission Owner,Writer,Reader -OU "OU=Test,DC=Test,DC=local"
```
The name of directory is *Test* and your path is *C:\Project\Test*. This cmdlet, creates a three Active Directory security group:
* Test_Readers (Read, Execute)
* Test_Writers (Read, Execute, Write, Modify)
* Test_Owners (Full Control)

And apply these on path with permission in brackets.
For more info, run:
```powershell
Get-Help New-ProjectFolder -Full
```
### Remove-OlderThan
 Removes files and folders older than days. In addition, also deletes empty folders. For example:
```powershell
Remove-OlderThan -Path C:\Temp -Days 15 -Recurse
```
Delete file and empty folder in *C:\Temp*, if creation date is older than 15 days.
For more info, run:
```powershell
Get-Help Remove-OlderThan -Full
```
### Backup-ArchiveFiles
Archive files older than a number of years. For example:
```powershell
Backup-ArchivedFiles -Path C:\Temp -Years 2 -ArchivePath D:\Temp -Exclude C:\Temp\Docs,"C:\Temp\Docs two" -AllFiles
```
Looking for file with Access Date older than two years into path *C:\Temp*; the destination path is *D:\Temp*. With *Exclude* option you can skip file in specified paths. Flag *AllFiles* means than all files in a folder must be older than two years. This cmdlet performing a move.
For more info, run:
```powershell
Get-Help Backup-ArchiveFiles -Full
```
## File server topology configuration
To create and maintain a file server topology, use the following commands.
### New-TemplateFileServer
With this command you can create an example topology file of a file server.
```powershell
New-TemplateFileServer -Path C:\Temp\fs1.xml
```
Change the topology according to your needs.
### Write-FileServerFromTemplate
Applying topology means creating folders and assigning them permissions, specified in the topology template file.
To apply it, run this command:
```powershell
Write-FileServerFromTemplate -Template C:\Temp\fs1.xml -RootPath D:\FS
```
Applying the command a second time, the new folders in the topology will be created, while the existing ones will be ignored. All permissions will be overwritten, if `-Force` parameter is specified.

For more info, run:
```powershell
Get-Help New-TemplateFileServer -Full
Get-Help Write-FileServerFromTemplate -Full
```

## Report cmdlet
These cmdlets are used to run reports
### Get-DedupFiles
To recover files that are duplicated in a certain path
```powershell
Get-DedupFiles -Path C:\Temp
```
Or to traverse the path, just specify the _-Recurse_ parameter: 
```powershell
Get-DedupFiles -Path C:\Temp -Recurse
```

For more info, run:
```powershell
Get-Help Get-DedupFiles -Full
```

### Show-LatestCreatedFile
Show the latest created files based on a date or size.
The size of the files can be specified in bytes 1, 1MB, 1GB, 1TB, 1PB.
```powershell
Show-LatestCreatedFile -Path C:\Temp -Recurse -Size 50MB -CreationTime '05/29/2016'
```

For more info, run:
```powershell
Get-Help Show-LatestCreatedFile -Full
```

### Show-LatestWritedFile
Show the latest modified files based on a date or size.
The size of the files can be specified in bytes 1, 1MB, 1GB, 1TB, 1PB.
```powershell
Show-LatestWritedFile -Path C:\Temp -Recurse -Size 50MB -CreationTime '05/29/2016'
```

For more info, run:
```powershell
Get-Help Show-LatestWritedFile -Full
```

### Show-LatestAccessedFile
Show the latest accessed files based on a date or size.
The size of the files can be specified in bytes 1, 1MB, 1GB, 1TB, 1PB.
```powershell
Show-LatestAccessedFile -Path C:\Temp -Recurse -Size 50MB -CreationTime '05/29/2016'
```

For more info, run:
```powershell
Get-Help Show-LatestAccessedFile -Full
```

### Show-FolderLength
Show to estimate file space usage.
Track the directories which are consuming excessive amount of space on a drive.
```powershell
Show-FolderLength -Path C:\Temp
```

For more info, run:
```powershell
Get-Help Show-FolderLength -Full
```

**A great thanks**.

For donations, press this

For me

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.me/guos)

For [Telethon](http://www.telethon.it/)

The Telethon Foundation is a non-profit organization recognized by the Ministry of University and Scientific and Technological Research.
They were born in 1990 to respond to the appeal of patients suffering from rare diseases.
Come today, we are organized to dare to listen to them and answers, every day of the year.

<a href="https://www.telethon.it/sostienici/dona-ora"> <img src="https://www.telethon.it/dev/_nuxt/img/c6d474e.svg" alt="Telethon" title="Telethon" width="200" height="104" /> </a>

[Adopt the future](https://www.ioadottoilfuturo.it/)