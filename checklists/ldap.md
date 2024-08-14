# LDAP - Ports 389,636,3268,3269

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
````