# SMB Checklist

enum4linux -a $IP
smbclient -L //$IP
smbclient -N -L //IP
smbclient -L //192.168.1.2/myshare -U anonymous
smbclient //192.168.235.248/transfer -N
proxychains -q smbclient //172.16.173.21/monitoring -U "relia.com\andrea"
nxc smb 10.10.10.10 -u 'user' -p 'pass' -M spider_plus
nxc SMB <IP> -u USER -p PASSWORD --spider C\$ --pattern txt
rpcclient -U “” $IP ///when asked enter empty password
rpcclient $>srvinfo
rpcclient $>enumdomusers
rpcclient $>querydominfo
rpcclient $>getdompwinfo   //password policy
rpcclient $>netshareenum
nmblookup -A 192.168.1.1
nbtscan IP
nmap IP -p 139,445 –script smb*


> prompt off
> recurse on
> mget *

// smbmap
// crackmapexec

You can try putting payloads in SMBs as soon as you can, that way you don't have to worry about that method of client-side attacks.

If you can navigate to the web root, maybe wwwroot, you can upload a shell and try to access it through your browser.

Resource: https://www.netexec.wiki/smb-protocol/enumeration/enumerate-null-sessions
