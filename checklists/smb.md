# SMB Checklist

enum4linux -a $IP
enum4linux -a -u "CRAFT2\\thecybergeek" -p "winniethepooh" $ip
enum4linux -a -M -l -d $IP 2>&1
enum4linux -a -u "" -p "" $ip && enum4linux -a -u "guest" -p "" $ip
nmap $ip -p 139,445 –script smb*
smbclient -L //$IP
smbclient -N -L //IP
smbclient -L //IP -N
smbclient -N //$ip/backup
smbclient -L //192.168.1.2/myshare -U anonymous
smbclient //192.168.235.248/transfer -N
smbclient -U '%' -N \\\\<smb $IP>\\<share name>
smbclient -U 'guest' \\\\<smb $IP>\\<share name>
smbclient -U null -N \\\\<smb $IP>\\<share name>
smbclient -U '%' -N \\\\$IP\\<share name> -m SMB2
smbclient -U '%' -N \\\\$IP\\<share name> -m SMB3
smbclient -L \\$ip -U "" -N -p 12445
smbclient '//$ip/Sarge' -p 12445
proxychains -q smbclient //172.16.173.21/monitoring -U "relia.com\andrea"

nxc smb 10.10.10.178 -u 'a' -p '' --shares # Guest logon
nxc smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus
nxc SMB $ip -u USER -p PASSWORD --spider C\$ --pattern txt
nxc smb $ip -u "V.Ventz" -p "HotelCalifornia194\!" -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=1000000000

rpcclient -N -U "" \\10.10.10.161
rpcclient -U “” $IP ///when asked enter empty password
rpcclient $>srvinfo
rpcclient $>enumdomusers
rpcclient $>querydominfo
rpcclient $>getdompwinfo   //password policy
rpcclient $>netshareenum
nmblookup -A 192.168.1.1
nbtscan IP


#### To recursively download

> prompt off
> recurse on
> mget *

// smbmap
// crackmapexec

You can try putting payloads in SMBs as soon as you can, that way you don't have to worry about that method of client-side attacks.

If you can navigate to the web root, maybe wwwroot, you can upload a shell and try to access it through your browser.

Resource: https://www.netexec.wiki/smb-protocol/enumeration/enumerate-null-sessions
