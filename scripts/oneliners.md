## Bash One-Liners

Smile.

#### Take the second field out output

```bash
cat file.txt | awk '{print $2}'
```

#### Tee output to file and stout

```bash
enum4linux | tee file.txt
```

#### Decrypt VNC Password

```bash
echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv
```

#### Grep

Recursively Grep for word, case insensitive, show 3 lines before and after match

```bash
grep -ri "word" location -A3 -B3
```

Show lines that don't have words.

```bash
cat file.txt | grep -v "word1\|word2\|word3"
```

Find filename, case insensitive, with size.

```bash
ll $(find /opt/SecLists) | grep -i "wordpress"
```

Keeps lines that have a capital letter, a special character, and a number.

```bash
cat input.txt | grep -P '[A-Z]' | grep -P '[^a-zA-Z0-9]' | grep -P '[0-9]'
```

#### Manipulating Txt Files

Capitalize the first letter of every word.

```bash
awk '{ for(i=1; i<=NF; i++) $i = toupper(substr($i,1,1)) substr($i,2) } 1' users.txt
```

Make txt file of words lowercase and remove duplicates without ordering the words.

```bash
awk '!a[tolower($0)]++ {print tolower($0)}' input.txt > output.txt
awk '!a[toupper($0)]++ {print toupper($0)}' users.txt
```

Remove any words from txt file that are less than 6 chars.

```bash
awk 'length($0) >= 6' passwords.txt > temp.txt && mv temp.txt passwords.txt
```

Prepend the special chars '^$' at the beginning of each word in a text file from lines 106 to 122.

```bash
sed -i '89,105s|^|^$|' bdg.rule
```

Every combination of words from file1 and file2, separated by a colon, with outer loop being users, then removing any words in file2 that aren't 7 letters and have a capital letter and a special char, without ordering.

```bash
awk 'length($0) >= 7' passwords.txt > tmp_passwords.txt && awk 'NR==FNR {a[$1]; next} {for (i in a) print $1 ":" i}' tmp_passwords.txt users.txt | grep -P '[A-Z]' | grep -P '[^a-zA-Z0-9]' > combined.txt && rm tmp_passwords.txt
```

Combining two files' lines with a ':'.

```bash
awk 'NR==FNR {a[$1]; next} {for (i in a) print i ":" i}' users.txt users.txt
```

Make a txt file of all port numbers.

```bash
seq 1 65535 > ports.txt
```

Combine all files named passwords.txt.

```bash
find /home/kali/practice -name "passwords.txt" -exec cat {} \; > megapasswords.txt
```

Prepends file1 to the beginning of file2.

```bash
cat file1 file2 > file3
```
