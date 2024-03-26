# SMB Checklist

enum4linux -a IP
smbclient -L //IP
smbclient -N -L //IP
smbclient -L //192.168.1.2/myshare -U anonymous
rpcclient -U “” 192.168.1.2    ///when asked enter empty password
rpcclient $>srvinfo
rpcclient $>enumdomusers
rpcclient $>querydominfo
rpcclient $>getdompwinfo   //password policy
rpcclient $>netshareenum
nmblookup -A 192.168.1.1
nbtscan IP
nmap IP -p 139,445 –script smb*
