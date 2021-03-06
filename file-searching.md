# Finding Files and Strings

```bash
# Find all the files whose name is test.txt in the current working directory		
find . -name test.txt

# Find all the files whose name is test.txt under /home directory
find /home -name test.txt

# Find all the files whose name is test.txt with ignoring the case under /home directory	
find /home -iname test.txt

# Find directories whose name is Test in / directory	
find / -type d -name Test

# Find all php files in current working directory	
find . -type f -name â*.phpâ

# Find Files With 777 Permissions	
find . type f -perm 777 

# Find Files Without 777 Permissions	
find . type f ! -perm 777

# Find all empty files under /tmp	
find /tmp -type f -empty

# File all Hidden Files under /tmp	
find /tmp -type f -name â.*â

# Find all test.txt files under / owned by root	
find / -name test.txt -user root

# Find last 50 days modified files	
find / -mtime 50

# Find Last 50 Days Accessed Files	
find / -atime 50

# Find Last 50-100 Days Modified Files	
find / -mtime +50 -mtime -100

# Find Changed Files in Last 1 Hour	
find / -cmin -60

# Find Modified Files in Last 1 Hour	
find / -mmin -60

# Find 50MB Files	
find / -size 50M
```
