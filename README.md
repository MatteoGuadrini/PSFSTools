# PSFSTools is:
Simple file server tools for complex task.
## A powershell module
**PSFSTools** is a powershell module. Download and copying it under `%Windir%\System32\WindowsPowerShell\v1.0\Modules` for all users or under `%UserProfile%\Documents\WindowsPowerShell\Modules` for the current user or install through [PowershellGallery](https://www.powershellgallery.com/packages/PSFSTools).
> ATTENTION: This module is not signed. Before import or execute cmdlet on this module, see [about_signing](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_signing) session. To skip this part and continue, run ```Set-ExecutionPolicy -ExecutionPolicy Unrestricted```
## A collection of tool
Various task on a file server, require execution complexity; how and when to archive, create folders assigned to certain groups or delete files older than one month or delete folders that are no longer used.

This module, with  
## Tools:
* New-ProjectFolder
* Remove-OlderThan
* Backup-ArchiveFiles

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

**A great thanks**.

For donations, press this

For me

[![paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.me/guos)

For [Telethon](http://www.telethon.it/)
The Telethon Foundation is a non-profit organization recognized by the Ministry of University and Scientific and Technological Research.
They were born in 1990 to respond to the appeal of patients suffering from rare diseases.
Come today, we are organized to dare to listen to them and answers, every day of the year.

<a href="https://dona.telethon.it/it/dona-ora"> <img src="http://www.telethon.it/sites/all/themes/telethon/images/svg/logo.svg" alt="Telethon" title="Telethon" width="200" height="104" /> </a>
