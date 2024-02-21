## Generic Notes

### Learning and Problem-Solving Strategies

1. **Feynman Technique for Learning**:
   - Learn a Module.
   - Explain it to a beginner.
   - Identify gaps in understanding.
   - Return to study to fill those gaps.

2. **SQ2R Method for Study**:
   - Survey, Question, Read, Recite, Review.

3. **Cool Quote by Henry Ford**:
   - "Whether you think you can or think you can’t—you’re right."

---

### Technical Procedures and Commands

1. **Accessing Module Exercise VMs via SSH**:
   ```bash
   ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" learner@191.168.50.52
   ```

2. **Updating and Locating Files in Linux**:
   - Update the database with `sudo updatedb`.
   - Locate specific files using `locate`.
     Example:
     ```bash
     sudo updatedb
     locate file.ovpn
     ```

3. **Connecting to a VPN**:
   - Use `sudo openvpn` to connect.
   - Keep the command prompt open.
     Example:
     ```bash
     sudo openvpn file.ovpn
     ```

4. **Addressing File Execution Permission Issues**:
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
Aux argument will provide all processes, and piping to grep filters.

---

#### Adding Resositories

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

When fuzzing APIs, try to fuzz in special characters ("/opt/SecLists/Fuzzing/special-characters.txt") and monitor for different responses. You can do this recursively. Find out if you can close out a command so you can inject new code.
