# Active Directory

Active Directory Domain Services, often referred to as Active Directory (AD), is a service that allows system administrators to update and manage operating systems, applications, users, and data access on a large scale. Active Directory is installed with a standard configuration, however, system administrators often customize it to fit the needs of the organization.

While Active Directory itself is a service, it also acts as a management layer. AD contains critical information about the environment, storing information about users, groups, and computers, each referred to as objects. Permissions set on each object dictate the privileges that object has within the domain

An AD environment has a critical dependency on the Domain Name System (DNS) service. As such, a typical domain controller will also host a DNS server that is authoritative for a given domain.

To ease the management of various objects and assist with management, system administrators often organize these objects into Organizational Units (OUs).1

OUs are comparable to file system folders in that they are containers used to store objects within the domain. Computer objects represent actual servers and workstations that are domain-joined (part of the domain), and user objects represent accounts that can be used to log in to the domain-joined computers. In addition, all AD objects contain attributes, which will vary depending on the type of object. For example, a user object may include attributes such as first name, last name, username, phone number, etc.

AD relies on several components and communication services. For example, when a user attempts to log in to the domain, a request is sent to a Domain Controller (DC), which checks whether or not the user is allowed to log in to the domain. One or more DCs act as the hub and core of the domain, storing all OUs, objects, and their attributes. Since the DC is such a central domain component, we'll pay close attention to it as we enumerate AD.

Objects can be assigned to AD groups so that administrators can manage those object as a single unit. For example, users in a group could be given access to a file server share or given administrative access to various clients in the domain. Attackers often target high-privileged groups.

Members of Domain Admins3 are among the most privileged objects in the domain. If an attacker compromises a member of this group (often referred to as domain administrators), they essentially gain complete control over the domain.

This attack vector could extend beyond a single domain since an AD instance can host more than one domain in a domain tree or multiple domain trees in a domain forest. While there is a Domain Admins group for each domain in the forest, members of the Enterprise Admins group are granted full control over all the domains in the forest and have Administrator privilege on all DCs. This is obviously a high-value target for an attacker.

```bash
net user /domain # Print users in the domain
net user jeffadmin /domain # Check out potential admin account
net group /domain # Print groups in the domain
net group "Sales Department" /domain # Pay attention to non-default groups
```

### Using PS and .NET Classes

AD enumeration relies on LDAP. When a domain machine searches for an object, like a printer, or when we query user or group objects, LDAP is used as the communication channel for the query. In other words, LDAP is the protocol used to communicate with Active Directory.

LDAP communication with AD is not always straight-forward, but we'll leverage an Active Directory Services Interface (ADSI) (a set of interfaces built on COM) as an LDAP provider. According to Microsoft's documentation, we need a specific LDAP ADsPath in order to communicate with the AD service. The LDAP path's prototype looks like this:

```bash
LDAP://HostName[:PortNumber][/DistinguishedName]
```

The Hostname can be a computer name, IP address or a domain name. In our case, we are working with the corp.com domain, so we could simply add that to our LDAP path and likely obtain information. Note that a domain may have multiple DCs, so setting the domain name could potentially resolve to the IP address of any DC in the domain.

While this would likely still return valid information, it might not be the most optimal enumeration approach. In fact, to make our enumeration as accurate as possible, we should look for the DC that holds the most updated information. This is known as the Primary Domain Controller (PDC). There can be only one PDC in a domain. To find the PDC, we need to find the DC holding the PdcRoleOwner property. We'll eventually use PowerShell and a specific .NET class to find this.

The PortNumber for the LDAP connection is optional as per Microsoft's documentation. In our case we will not add the port number since it will automatically choose the port based on whether or not we are using an SSL connection. However, it is worth noting that if we come across a domain in the future using non-default ports, we may need to manually add this to the script.

Lastly, a DistinguishedName (DN) is a part of the LDAP path. A DN is a name that uniquely identifies an object in AD, including the domain itself. If we aren't familiar with LDAP, this may be somewhat confusing so let's go into a bit more detail.

In order for LDAP to function, objects in AD (or other directory services) must be formatted according to a specific naming standard.8 To show an example of a DN, we can use our stephanie domain user. We know that stephanie is a user object within the corp.com domain. With this, the DN may (although we cannot be sure yet) look something like this:

```bash
CN=Stephanie,CN=Users,DC=corp,DC=com
```

The Listing above shows a few new references we haven't seen earlier in this Module, such as CN and DC. The CN is known as the Common Name, which specifies the identifier of an object in the domain. While we normally refer to "DC" as the Domain Controller in AD terms, "DC" means Domain Component when we are referring to a Distinguished Name. The Domain Component represents the top of an LDAP tree and in this case we refer to it as the Distinguished Name of the domain itself.

When reading a DN, we start with the Domain Component objects on the right side and move to the left. In the example above, we have four components, starting with two components named DC=corp,DC=com. The Domain Component objects as mentioned above represent the top of an LDAP tree following the required naming standard.

Continuing through the DN, CN=Users represents the Common Name for the container where the user object is stored (also known as the parent container). Finally, all the way to the left, CN=Stephanie represents the Common Name for the user object itself, which is also lowest in the hierarchy.

In our case for the LDAP path, we are interested in the Domain Component object, which is DC=corp,DC=com. If we added CN=Users to our LDAP path, we would restrict ourselves by only being able to search objects within that given container.

In the Microsoft .NET classes related to AD, we find the System.DirectoryServices.ActiveDirectory namespace. While there are a few classes to choose from here, we'll focus on the Domain Class. It specifically contains a reference to the PdcRoleOwner in the properties, which is exactly what we need. By checking the methods, we find a method called GetCurrentDomain(), which will return the domain object for the current user, in this case stephanie.

To invoke the Domain Class and the GetCurrentDomain method, we'll run the following command in PowerShell:

```bash
PS C:\Users\stephanie> [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

Forest                  : corp.com
DomainControllers       : {DC1.corp.com}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner        : DC1.corp.com
RidRoleOwner            : DC1.corp.com
InfrastructureRoleOwner : DC1.corp.com
Name                  	: corp.com
```

The output reveals the PdcRoleOwner property, which in this case is DC1.corp.com. While we can certainly add this hostname directly into our script as part of the LDAP path, we want to automate the process so we can also use this script in future engagements.

Let's do this one step at a time. First, we'll create a variable that will store the domain object, then we will print the variable so we can verify that it still works within our script. The first part of our script is listed below:

```bash
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Print the variable
$domainObj
```

```bash
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

# Print the $PDC variable
$PDC
```

While we can also get the DN for the domain via the domain object, it does not follow the naming standard required by LDAP. In our example, we know that the base domain is corp.com and the DN would in fact be DC=corp,DC=com. In this instance, we could grab corp.com from the Name property in the domain object and tell PowerShell to break it up and add the required DC= parameter. However, there is an easier way of doing it, which will also make sure we are obtaining the correct DN.

We can use ADSI directly in PowerShell to retrieve the DN. We'll use two single quotes to indicate that the search starts at the top of the AD hierarchy.

```bash
PS C:\Users\stephanie> ([adsi]'').distinguishedName
DC=corp,DC=com
```

This returns the DN in the proper format for the LDAP path.

Now we can add a new variable in our script that will store the DN for the domain. To make sure the script still works, we'll add a print statement and print the contents of our new variable:

```bash
# Store the domain object in the $domainObj variable
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()

# Store the PdcRoleOwner name to the $PDC variable
$PDC = $domainObj.PdcRoleOwner.Name

# Store the Distinguished Name variable into the $DN variable
$DN = ([adsi]'').distinguishedName

# Print the $DN variable
$DN
```

At this point, we are dynamically obtaining the Hostname and the DN with our script. Now we must assemble the pieces to build the full LDAP path. To do this, we'll add a new $LDAP variable to our script that will contain the $PDC and $DN variables, prefixed with "LDAP://".

The final script generates the LDAP shown below. Note that in order to clean it up, we have removed the comments. Since we only needed the PdcRoleOwner property's name value from the domain object, we add that directly in our $PDC variable on the first line, limiting the amount of code required:

```bash
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"
$LDAP
```

```bash
PS C:\Users\stephanie> .\enumeration.ps1
LDAP://DC1.corp.com/DC=corp,DC=com
```

The DirectoryEntry class encapsulates an object in the AD service hierarchy. In our case, we want to search from the very top of the AD hierarchy, so we will provide the obtained LDAP path to the DirectoryEntry class.

One thing to note with DirectoryEntry is that we can pass it credentials to authenticate to the domain. However, since we are already logged in, there is no need to do that here.

The DirectorySearcher class performs queries against AD using LDAP. When creating an instance of DirectorySearcher, we must specify the AD service we want to query in the form of the SearchRoot property. According to Microsoft's documentation, this property indicates where the search begins in the AD hierarchy. Since the DirectoryEntry class encapsulates the LDAP path that points to the top of the hierarchy, we will pass that as a variable to DirectorySearcher. The DirectorySearcher documentation lists FindAll(), which returns a collection of all the entries found in AD.

```bash
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.FindAll()
```

```bash
PS C:\Users\stephanie> .\enumeration.ps1

Path
----
LDAP://DC1.corp.com/DC=corp,DC=com
LDAP://DC1.corp.com/CN=Users,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Computers,DC=corp,DC=com
LDAP://DC1.corp.com/OU=Domain Controllers,DC=corp,DC=com
LDAP://DC1.corp.com/CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=LostAndFound,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Infrastructure,DC=corp,DC=com
LDAP://DC1.corp.com/CN=ForeignSecurityPrincipals,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Program Data,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Microsoft,CN=Program Data,DC=corp,DC=com
LDAP://DC1.corp.com/CN=NTDS Quotas,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Managed Service Accounts,DC=corp,DC=com
LDAP://DC1.corp.com/CN=Keys,DC=corp,DC=com
LDAP://DC1.corp.com/CN=WinsockServices,CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=RpcServices,CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=FileLinks,CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=VolumeTable,CN=FileLinks,CN=System,DC=corp,DC=com
LDAP://DC1.corp.com/CN=ObjectMoveTable,CN=FileLinks,CN=System,DC=corp,DC=com
...
```

Filtering the output is rather simple, and there are several ways to do so. One way is to set up a filter that will sift through the samAccountType attribute, which is an attribute applied to all user, computer, and group objects.

The official documentation reveals different values of the samAccountType attribute, but we'll start with 0x30000000 (decimal 805306368), which will enumerate all users in the domain. To implement the filter in our script, we can simply add the filter to the $dirsearcher.filter as shown below:

```bash
$PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$dirsearcher.FindAll()
```

```bash
PS C:\Users\stephanie> .\enumeration.ps1

Path                                                         Properties
----                                                         ----------
LDAP://DC1.corp.com/CN=Administrator,CN=Users,DC=corp,DC=com {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=Guest,CN=Users,DC=corp,DC=com         {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=krbtgt,CN=Users,DC=corp,DC=com        {logoncount, codepage, objectcategory, description...}
LDAP://DC1.corp.com/CN=dave,CN=Users,DC=corp,DC=com          {logoncount, codepage, objectcategory, usnchanged...}
LDAP://DC1.corp.com/CN=stephanie,CN=Users,DC=corp,DC=com     {logoncount, codepage, objectcategory, dscorepropagatio...
```

This is great information to have, but we need to develop it a little further. When enumerating AD, we are very interested in the attributes of each object, which are stored in the Properties field.

Knowing this, we can store the results we receive from our search in a new variable. We'll iterate through each object and print each property on its own line via a nested loop as shown below.

```bash
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = $domainObj.PdcRoleOwner.Name
$DN = ([adsi]'').distinguishedName 
$LDAP = "LDAP://$PDC/$DN"

$direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)

$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="samAccountType=805306368"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop
    }

    Write-Host "-------------------------------"
}

```

This complete script will search through AD and filter the results based on the samAccountType of our choosing, then place the results into the new $result variable. It will then further filter the results based on two foreach loops. The first loop will extract the objects stored in $result and place them into the $obj variable. The second loop will extract all the properties for each object and store the information in the $prop variable. The script will then print $prop and present the output in the terminal.

```bash
PS C:\Users\stephanie> .\enumeration.ps1
...
logoncount                     {173}
codepage                       {0}
objectcategory                 {CN=Person,CN=Schema,CN=Configuration,DC=corp,DC=com}
dscorepropagationdata          {9/3/2022 6:25:58 AM, 9/2/2022 11:26:49 PM, 1/1/1601 12:00:00 AM}
usnchanged                     {52775}
instancetype                   {4}
name                           {jeffadmin}
badpasswordtime                {133086594569025897}
pwdlastset                     {133066348088894042}
objectclass                    {top, person, organizationalPerson, user}
badpwdcount                    {0}
samaccounttype                 {805306368}
lastlogontimestamp             {133080434621989766}
usncreated                     {12821}
objectguid                     {14 171 173 158 0 247 44 76 161 53 112 209 139 172 33 163}
memberof                       {CN=Domain Admins,CN=Users,DC=corp,DC=com, CN=Administrators,CN=Builtin,DC=corp,DC=com}
whencreated                    {9/2/2022 11:26:48 PM}
adspath                        {LDAP://DC1.corp.com/CN=jeffadmin,CN=Users,DC=corp,DC=com}
useraccountcontrol             {66048}
cn                             {jeffadmin}
countrycode                    {0}
primarygroupid                 {513}
whenchanged                    {9/19/2022 6:44:22 AM}
lockouttime                    {0}
lastlogon                      {133088312288347545}
distinguishedname              {CN=jeffadmin,CN=Users,DC=corp,DC=com}
admincount                     {1}
samaccountname                 {jeffadmin}
objectsid                      {1 5 0 0 0 0 0 5 21 0 0 0 30 221 116 118 49 27 70 39 209 101 53 106 82 4 0 0}
lastlogoff                     {0}
accountexpires                 {9223372036854775807}
...
```

We can filter based on any property of any object type. In the example below, we have made two changes. First, we have changed the filter to use the name property to only show information for jeffadmin. Additionally, we have added .memberof to the $prop variable to only display the groups jeffadmin is a member of:

```bash
$dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry)
$dirsearcher.filter="name=jeffadmin"
$result = $dirsearcher.FindAll()

Foreach($obj in $result)
{
    Foreach($prop in $obj.Properties)
    {
        $prop.memberof
    }

    Write-Host "-------------------------------"
}
```

```bash
PS C:\Users\stephanie> .\enumeration.ps1
CN=Domain Admins,CN=Users,DC=corp,DC=com
CN=Administrators,CN=Builtin,DC=corp,DC=com
```

We can use this script to enumerate any object available to us in AD. However, in the current state, this would require us to make further edits to the script itself based on what we wish to enumerate.

Instead, we can make the script more flexible, allowing us to add the required parameters via the command line. For example, we could have the script accept the samAccountType we wish to enumerate as a command line argument.

There are many ways we can accomplish this. One way is to simply encapsulate the current functionality of the script into an actual function. An example of this is shown below.

```bash
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName

    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")

    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)

    return $DirectorySearcher.FindAll()

}
```

To use the function, let's import it to memory:

```bash
PS C:\Users\stephanie> Import-Module .\function.ps1
```

Within PowerShell, we can now use the LDAPSearch command (our declared function name) to obtain information from AD. To repeat parts of the user enumeration we did earlier, we can again filter on the specific samAccountType:

```bash
PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(samAccountType=805306368)"
...
```

We can also search directly for an Object Class, which is a component of AD that defines the object type. Let's use objectClass=group in this case to list all the groups in the domain:

```bash
PS C:\Users\stephanie> LDAPSearch -LDAPQuery "(objectclass=group)"
```

To enumerate every group available in the domain and also display the user members, we can pipe the output into a new variable and use a foreach loop that will print each property for a group. This allows us to select specific attributes we are interested in. For example, let's focus on the CN and member attributes:

```bash
PS C:\Users\stephanie\Desktop> foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) { $group.properties | select {$_.cn}, {$_.member} }
```

Even though this environment is somewhat small, we still received a lot of output. Let's focus on the three groups we noticed earlier in our enumeration with net.exe:
```bash
...
Sales Department              {CN=Development Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=stephanie,CN=Users,DC=corp,DC=com}
Management Department         CN=jen,CN=Users,DC=corp,DC=com
Development Department        {CN=Management Department,DC=corp,DC=com, CN=pete,CN=Users,DC=corp,DC=com, CN=dave,CN=Users,DC=corp,DC=com}
...
```

Since the output can be somewhat difficult to read, let's once again search for the groups, but this time specify the Sales Department in the query and pipe it into a variable in our PowerShell command line:

```bash
PS C:\Users\stephanie\Desktop> $sales.properties.member
CN=Development Department,DC=corp,DC=com
CN=pete,CN=Users,DC=corp,DC=com
CN=stephanie,CN=Users,DC=corp,DC=com
PS C:\Users\stephanie\Desktop>
```

Now that we know the Development Department is a member of the Sales Department, let's enumerate it:

```bash
PS C:\Users\stephanie> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"

PS C:\Users\stephanie> $group.properties.member
CN=Management Department,DC=corp,DC=com
CN=pete,CN=Users,DC=corp,DC=com
CN=dave,CN=Users,DC=corp,DC=com
```

Based on the output above, we have another case of a nested group since Management Department is a member of Development Department. Let's check this group as well:

```bash
PS C:\Users\stephanie\Desktop> $group = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Management Department*))"

PS C:\Users\stephanie\Desktop> $group.properties.member
CN=jen,CN=Users,DC=corp,DC=com
```

### Enumerating Object Permissions

AD includes a wealth of permission types that can be used to configure an ACE.3 However, from an attacker's standpoint, we are mainly interested in a few key permission types. Here's a list of the most interesting ones along with a description of the permissions they provide:

	GenericAll: Full permissions on object
	GenericWrite: Edit certain attributes on the object
	WriteOwner: Change ownership of the object
	WriteDACL: Edit ACE's applied to object
	AllExtendedRights: Change password, reset password, etc.
	ForceChangePassword: Password change for object
	Self (Self-Membership): Add ourselves to for example a group
