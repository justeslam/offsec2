## SMB Checklist

```bash
enum4linux -a $ip
enum4linux -a -u "CRAFT2\\thecybergeek" -p "winniethepooh" $ip
enum4linux -a -M -l -d $ip 2>&1
enum4linux -a -u "" -p "" $ip && enum4linux -a -u "guest" -p "" $ip
enum4linux-ng $ip
nmap $ip -p 139,445 –script smb*
smbclient -L //$ip
smbclient -N -L //$ip
smbclient -L //$ip -N
smbclient -N //$ip/backup
smbclient -L //$ip/myshare -U anonymous
smbclient //$ip/transfer -N
smbclient -U '%' -N \\\\<smb $ip>\\<share name>
smbclient -U 'guest' \\\\<smb $ip>\\<share name>
smbclient -U null -N \\\\<smb $ip>\\<share name>
smbclient -U '%' -N \\\\$ip\\<share name> -m SMB2
smbclient -U '%' -N \\\\$ip\\<share name> -m SMB3
smbclient -L \\$ip -U "" -N -p 12445
smbclient '//$ip/Sarge' -p 12445
proxychains -q smbclient //172.16.173.21/monitoring -U "relia.com\andrea"

smbclient.py $dom
smbclient -W WORKGROUP -U % -t 5 -L //$dom -g
smbclient -W WORKGROUP -U % -s /tmp/tmpm24idfat -t 5 -L //192.168.154.117 -g
smbclient.py active.htb/SVC_TGS:GPPstillStandingStrong2k18@$ip
> shares
> use Users

nxc smb $ip -u 'a' -p '' --shares # Guest logon
nxc smb $ip  -u 'user' -p 'pass' -M spider_plus
nxc SMB $ip -u USER -p PASSWORD --spider C\$ --pattern txt
nxc smb $ip -u "V.Ventz" -p "HotelCalifornia194\!" -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=1000000000

rpcclient -N -U "" \\$ip
rpcclient -U “” $ip ///when asked enter empty password
rpcclient -U “” $ip -N
rpcclient $>srvinfo
rpcclient $>enumdomusers
rpcclient $>querydominfo
rpcclient $>getdompwinfo   //password policy
rpcclient $>netshareenum
nmblookup -A 192.168.1.1
nbtscan IP
```

#### Look up the SMB versions

Miss this everytime.

#### To recursively download

```bash
> prompt off
> recurse on
> mget *

> prompt off
> recurse on
> dir *

// smbmap
// crackmapexec
```


You can try putting payloads in SMBs as soon as you can, that way you don't have to worry about that method of client-side attacks.

If you can navigate to the web root, maybe wwwroot, you can upload a shell and try to access it through your browser.

#### Notes

Using nxc smb will find you the domain name quickly.

Resource: https://www.netexec.wiki/smb-protocol/enumeration/enumerate-null-sessions
