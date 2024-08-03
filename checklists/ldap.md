# LDAP - Ports 389,636,3268,3269

````
ldapsearch -x -H ldap://192.168.214.122

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
ldapsearch -x -H ldap://192.168.214.122 -s base namingcontexts

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
ldapsearch -x -H ldap://192.168.214.122 -b "DC=exampleH,DC=example"
````