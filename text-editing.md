# Text Editing Commands

[TOC]

---

## Awk

```bash
# Print the lines which contains the given pattern.	
awk '/test/ {print}' test.txt
awk '/test/ {print}' test.txt > newfile

# Print the fields 1 and 4 with delimeter whitespace
awk '{print $1,$4}' test.txt 
awk '{print $1,$4}' test.txt > newfile

# Display a block of test starts with the word start and ends with the word end	
awk '/start/,/stop/' file.txt
```

## Cut

```bash
# displays 2nd character from each line of a file	
cut -c2 test.txt

# display first 3 characters of from each line of a file	
cut -c1-3 test.txt

# display characters starting from 3rd character to the end of each line of a file	
cut -c3- test.txt

# display first 8 character of from each line of a file	
cut -c-8 test.txt

# display 1st field when : is used as a delimeter	
cut -d':' -f1 test.txt

# display 1st and 6th fields when : is used as a delimeter	
cut -d':' -f1,6 test.txt

# display all fileds except 7th field when : is used as a delimeter	
cut -d':' –complement -s -f7 test.txt
```

## Grep

```bash
# Search all lines with specified string in a file	
grep "string" test.txt

# Search all lines with specified string in a file pattern (test_1.txt, test_2.txt, test_3.txt ...)	
grep "string" test_*.txt

# Case insensitive search all lines with specified string in a file
grep -i "string" test.txt

# match regex in files (*)	
grep "REGEX" test.txt

# Match lines with the pattern starts with "first" and ends with "last" with anything in-between	
grep "start.*end" test.txt

# search for full words, not for sub-strings	
grep -iw "is" test.txt

# display line matches the pattern and N lines after match	
grep -A 3 "string" test.txt

# display line matches the pattern and N lines before match	
grep -B 2 "string" test.txt

# display line matches the pattern and N lines before match and N lines after match	
grep -C 2 "string" test.txt

# search all files recursively	
grep -r "string" *

# display all lines that doesn’t match the given pattern	
grep -v "string" test.txt

# display lines that doesn’t match all the given pattern (if there are more than one pattern)	
grep -v -e "string1" -v -e "string2" test.txt

# count the number of lines that matches the pattern	
grep -c "string" test.txt

# count the number of lines that don’t match the pattern	
grep -v -c "string" test.txt

# display only the filenames containing the given pattern (test_1.txt, test_2.txt, test_3.txt ...)	
grep -l "string" test_*.txt

# Show only the matched string, not the whole line	
grep -o "start.*end" test.txt

# show line number while displaying the output	
grep -n "string" test.txt


(*) Regex:
? The preceding item is optional and matched at most once.
* The preceding item will be matched zero or more times.
+ The preceding item will be matched one or more times.
{n} The preceding item is matched exactly n times.
{n,} The preceding item is matched n or more times.
{,m} The preceding item is matched at most m times.
{n,m} The preceding item is matched at least n times, but not more than m times.
```



## Sed

```bash
# return lines 5 through 10 from test.txt	
sed -n '5,10p' test.txt

# print the entire file except  lines 20 through 35 from test.txt	
sed -n '20,35d' test.txt

# display lines 5-7 and 10-13 from test.txt	
sed -n -e '5,7p' -e '10,13p' test.txt

# Replace every instance of the word 'test' with 'real' in test.txt
sed 's/test/real/g' test.txt

# Replace every instance of the word 'test' with 'real' in test.txt with ignoring character case	
sed 's/test/real/gi' test.txt

# Replace multiple spaces with single space	
sed 's/ */ /g' test.txt

# Replace every instance of the word 'test' with 'real' within line 30-40 in test.txt	
sed '30,40 s/test/real/g' test.txt

# Delete lines that start with # or empty lines (**)	
sed '/^#\|^$\| *#/d' test.txt

# Replace words zip and Zip with rar in file test.txt	
sed 's/[Zz]ip/rar/g' test.txt

# insert one blank line between each lines	
sed G test.txt

# Remove the hidden new lines (DOS new line chars) at the end of each line (and do the changes in-file)	
sed -i 's/\r//' test.txt

Note: (**)
Regex can be explained as below:
^# menas line start with #
\| means or
^$ means blank line
And  *# means lines start with some space and then # 
# Remove certain ips from file
sed -i '/10\.0\.15./d' sed-test
```


