# Windows Commands - General

[TOC]



## System

```cmd
# Get system info about computer and OS
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
systeminfo /s test-server
systeminfo /s test-server /u testdomain\<username>
hostname 


#OS Check Patches and disk information
wmic logicaldisk
wmic qfe
wmic product get name, version,  vendor
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%

# Display environment variables
set
echo %Path%

# List windows services
net start
sc queryex type=service 'lists all services'
wmic service list brief
tasklist /SVC

# Display list of currently running processes
tasklist 
tasklist /s <server>
tasklist /s <server> /u testdomain\<username> /p <password>

# Kill a process 
taskkill /PID 1234 /F

# See what drives are mounted to your file system
wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
wmic logicaldisk get deviceid, volumename, description
wmic logicaldisk get name
mountvol

# Check for current drivers
driverquery

# Find filepath to executable (Like which on linux)
where cmd 

```



## Network

```cmd
# Show network information
ipconfig
ipconfig /all
arp -a 
netstat -an
netstat -r
netstat -rn
router print

# Retrieve local DNS information
ipconfig /displaydns 
nslookup 

# List network shares
net share

# List ports and connections with the system
netstat -nabo
netstat -aton

# Find information about a specific service
netstat -nabo | findstr /I <service|process|port>

# Find all listening ports on port 80
netstat -na | findstr :80

# Finf all listening ports and their associated PIDs
netstat -nao | findstr /I listening

# Display a target PCs listening services
nbtstat -A <targetIP>

# Display information about all connections to the computer (have to be an admin shell)
net session

# Display host name from IP
nvtstat -a <IP>

 
```



## Firewall/AV/Service Enumeration

```cmd
# Show firewall running or stopped
netsh firewall show state

# Show firewall configuration
netsh firewall show conf
netsh firewall show state

# Disable Firewall
netsh firewall set opmode disable
netsh firewall set opmode=disable profile=all
netsh advfirewall set all profiles state off 

# Query Windows Defender
sc query windefend

# Antivirus
netsh advfirewall firewall dump
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all

# enable RDP
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
```



## Domain

```bash
# Get domain controllers
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName

# Retrieve information about Domain and Domain controller
wmic ntdomain list
echo %logonserver% 

# Check if you are part of domain
net localgroup /domain

# List detailed information about the current domain user account 
net user %USERNAME% /domain 

# Prints members of the domain admins
net group <groupname> /domain

# Print password policy for the domain
net accounts /domain 
netaccounts /domain:DOMAINNAME
```



## Users

```cmd
# Current User information
whoami
echo %USERNAME% || whoami
whoami /priv
whoami /groups
net user %USERNAME%

# Lost local users
net user

# Other users information
net user <username> 'Checks groups associated with user'
net localgroup 'Lists all local groups availible'
net localgroup <groupname>  'Lists members of given group'

# Print password policy for the local system
net accounts

# List other logged in users
qwinsta 

# Add user to non-admin
net user /add username
net user /add <username> <password>

# Add user to admin group
net localgroup administrators /add <username>


```



## File System

```cmd
# Show current dirrectory 
cd

# Displays a list of a directories files and subdirs
dir 

# Show hidden files
dir /A

# Finding files
dir /a /s file.txt
```



## Working with Files and Folders

```cmd
# Windows version of cat - print out file contents
type file.txt
more file.txt # Displays one screen of output at a time

# grep files
findstr file.txt <pattern>
findstr /si password *.txt
# rename files
ren <scrfile> <destinationfile>

# Create files
fsutil filename

# File permissions
icacles file.txt
C:\Program Files : icacls <program_name>

# Grant permission to access files
icacls file.txt /grant <username>

# Check stored usernames and passwords
cmdkey /list
```



## Password Hunting

```cmd

```



## Access Control

```cmd
# Permissions on a folder recursively
cacls *.* /t /e /g domainname\administrator:f

```

## Exploit

```cmd
# Run exploit on cmd.exe
powershell -executionpolicy bypass -command <command>
powershell -ExecutionPolicy ByPass -command ./test.ps1
powershell -ExecutionPolicy ByPass -command C:\Users\<username>\Desktop\test.ps1
```
