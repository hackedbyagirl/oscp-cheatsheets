# Important Files

## Windows
```bash
# General
%SYSTEMDRIVE%\boot.ini
%WINDIR%\win.ini
C:\Windows\System32\license.rtf
C:\Windows/system32\eula.txt
C:\sysprep.inf
C:\sysprep\sysprep.inf
C:\sysprep\sysprep.xml

# Stored Users Passwords in either LM or NTLM Hash
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM

# SYSTEM Registry Hive (Needed to extract user account password hashes)
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

# Windows System Registry Hive 
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security

# Script that executes at Startup/Boot
%SYSTEMDRIVE%\autoexec.bat

# Used by OS when there isnt enough RAM
%SYSTEMDRIVE%\pagefile.sys

# Web Server
%SystemDrive%\inetpub\logs\LogFiles
C:\inetpub\wwwroot\Web.config
C:\Windows\system32\inetsrv\config\applicationHost.config
C:\Windows\system32\inetsrv\config\schema\ASPNET_schema.xml

# Internet Explorer Web Browser History
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat

# User Level Registry Settings
%USERPROFILE%\ntuser.dat

# System Host Files
%WINDIR%\System32\drivers\etc\hosts
C:\Windows\System32\drivers\etc\networks

# Domain Joined Computer Issue Logs
%WINDIR%\debug\NetSetup.log

# IIS Logs
%WINDIR%\iis[version].log where [version] = 6, 7, or 8

# System Center Configuration Manager Logs
%WINDIR%\system32\CCM\logs\*.log

# Windows Event Logs
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt

# Backup Windows Registry Files
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav

# Web Logs
%WINDIR%\system32\logfiles\httperr\httperr1.log
%WINDIR%\system32\logfiles\w3svc1\exYYMMDD.log where YYMMDD = year month day

# Automated Deployment of Windows Images, can sometimes contain User Accounts
unattend.txt, unattend.xml, unattended.xml, sysprep.inf
```

## Linux
```
# DNS Servers
/etc/resolv.conf

# Bash History 
/home/[USERNAME]/.bash_history
~/.bash_history
$USER/.bash_history
/root/.bash_history

# Passwords
/etc/passwd
/etc/group
/etc/shadow
ls -alh /var/mail/

# private key search
~/.ssh/authorized_keys
~/.ssh/identity.pub
~/.ssh/identity
~/.ssh/id_rsa.pub
~/.ssh/id_rsa
~/.ssh/id_dsa.pub
~/.ssh/id_dsa
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_rsa_key.pub
/etc/ssh/ssh_host_rsa_key
/etc/ssh/ssh_host_key.pub
/etc/ssh/ssh_host_key
```

