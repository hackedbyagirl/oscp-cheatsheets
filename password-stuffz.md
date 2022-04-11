# Password Stuff

## Default Cred Search

### Pass Station
```bash
pass-station search Weblogi
pass-station search WEBLOGIC --field username --sensitive
pass-station search 'admin[0-9]+' --field all
pass-station search Edimax --output csv
```
### ChangeME
A default credential scanner.
supports the http/https, mssql, mysql, postgres, ssh, ssh w/key, snmp, mongodb and ftp protocols.


```bash
# Scan
./changeme.py 192.168.59.100
./changeme.py 192.168.59.0/24
./changeme.py nmap-xml-file.xml
./changeme.py <protocol>://<host>

# Web specific
./changeme.py -n "Apache Tomcat" --timeout 5 192.168.59.0/24

# SSH Specific
./changeme.py --protocols ssh,ssh_key 192.168.59.0/24

# SMNP Specific
./changeme.py snmp://192.168.1.20

```
### DeafultCredDB
```bash
# Deafult Cred Search DB
# cd defaultcredsearch
python3 creds search tomcat  
```
