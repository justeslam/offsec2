# Active Information Gathering

"Living off the Land" aka LOLBAS - leveraging the tools available on the workstation. Applications that can provide unintended code execution are normally listed under the LOLBAS project


## DNS Record Types

	**NS**: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
	**A**: Also known as a host record, the "a record" contains the IPv4 address of a hostname (such as www.megacorpone.com).
	**AAAA**: Also known as a quad A host record, the "aaaa record" contains the IPv6 address of a hostname (such as www.megacorpone.com).
	**MX**: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
	**PTR**: Pointer Records are used in reverse lookup zones and can find the records associated with an IP address.
	**CNAME**: Canonical Name Records are used to create aliases for other host records.
	**TXT**: Text records can contain any arbitrary data and be used for various purposes, such as domain ownership verification.


Search for A record.
```bash
kali@kali:~$ host www.megacorpone.com
www.megacorpone.com has address 149.56.244.87
```

Search by DNS record type.
```bash
kali@kali:~$ host -t mx megacorpone.com
megacorpone.com mail is handled by 10 fb.mail.gandi.net.
megacorpone.com mail is handled by 20 spool.mail.gandi.net.
megacorpone.com mail is handled by 50 mail.megacorpone.com.
megacorpone.com mail is handled by 60 mail2.megacorpone.com.
```

If doesn't exist.
```bash
kali@kali:~$ host idontexist.megacorpone.com
Host idontexist.megacorpone.com not found: 3(NXDOMAIN)
```

## DNS Lookups

```bash
kali@kali:~$ cat list.txt
www
ftp
mail
owa
proxy
router

kali@kali:~$ for ip in $(cat list.txt); do host $ip.megacorpone.com; done
www.megacorpone.com has address 149.56.244.87
Host ftp.megacorpone.com not found: 3(NXDOMAIN)
mail.megacorpone.com has address 51.222.169.212
Host owa.megacorpone.com not found: 3(NXDOMAIN)
Host proxy.megacorpone.com not found: 3(NXDOMAIN)
router.megacorpone.com has address 51.222.169.214

kali@kali:~$ for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
...
208.169.222.51.in-addr.arpa domain name pointer admin.megacorpone.com.
209.169.222.51.in-addr.arpa domain name pointer beta.megacorpone.com.
210.169.222.51.in-addr.arpa domain name pointer fs1.megacorpone.com.
211.169.222.51.in-addr.arpa domain name pointer intranet.megacorpone.com.
...
```
If we were performing an assessment, we could further extrapolate these results, and might scan for "mail2", "router", etc., and reverse-lookup positive results.

## DNSrecon

An advanced DNS enumeration script written
in Python

Standard domain scan.
```bash
kali@kali:~$ dnsrecon -d megacorpone.com -t std
[*] std: Performing General Enumeration against: megacorpone.com...
[-] DNSSEC is not configured for megacorpone.com
[*] 	 SOA ns1.megacorpone.com 51.79.37.18
[*] 	 NS ns1.megacorpone.com 51.79.37.18
[*] 	 NS ns3.megacorpone.com 66.70.207.180
[*] 	 NS ns2.megacorpone.com 51.222.39.63
[*] 	 MX mail.megacorpone.com 51.222.169.212
[*] 	 MX spool.mail.gandi.net 217.70.178.1
[*] 	 MX fb.mail.gandi.net 217.70.178.217
[*] 	 MX fb.mail.gandi.net 217.70.178.216
[*] 	 MX fb.mail.gandi.net 217.70.178.215
[*] 	 MX mail2.megacorpone.com 51.222.169.213
[*] 	 TXT megacorpone.com Try Harder
[*] 	 TXT megacorpone.com google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA
[*] Enumerating SRV Records
[+] 0 Records Found
```

Brute force scan.
```bash
kali@kali:~$ dnsrecon -d megacorpone.com -D ~/list.txt -t brt
[*] Using the dictionary file: /home/kali/list.txt (provided by user)
[*] brt: Performing host and subdomain brute force against megacorpone.com...
[+] 	 A www.megacorpone.com 149.56.244.87
[+] 	 A mail.megacorpone.com 51.222.169.212
[+] 	 A router.megacorpone.com 51.222.169.214
[+] 3 Records Found
```

## DNSEnum

```bash
kali@kali:~$ dnsenum megacorpone.com
...
dnsenum VERSION:1.2.6

-----   megacorpone.com   -----

...

Brute forcing with /usr/share/dnsenum/dns.txt:
_______________________________________________

admin.megacorpone.com.                   5        IN    A        51.222.169.208
beta.megacorpone.com.                    5        IN    A        51.222.169.209
fs1.megacorpone.com.                     5        IN    A        51.222.169.210
intranet.megacorpone.com.                5        IN    A        51.222.169.211
mail.megacorpone.com.                    5        IN    A        51.222.169.212
mail2.megacorpone.com.                   5        IN    A        51.222.169.213
ns1.megacorpone.com.                     5        IN    A        51.79.37.18
ns2.megacorpone.com.                     5        IN    A        51.222.39.63
ns3.megacorpone.com.                     5        IN    A        66.70.207.180
router.megacorpone.com.                  5        IN    A        51.222.169.214
siem.megacorpone.com.                    5        IN    A        51.222.169.215
snmp.megacorpone.com.                    5        IN    A        51.222.169.216
syslog.megacorpone.com.                  5        IN    A        51.222.169.217
test.megacorpone.com.                    5        IN    A        51.222.169.219
vpn.megacorpone.com.                     5        IN    A        51.222.169.220
www.megacorpone.com.                     5        IN    A        149.56.244.87
www2.megacorpone.com.                    5        IN    A        149.56.244.87


megacorpone.com class C netranges:
___________________________________

 51.79.37.0/24
 51.222.39.0/24
 51.222.169.0/24
 66.70.207.0/24
 149.56.244.0/24


Performing reverse lookup on 1280 ip addresses:
________________________________________________

18.37.79.51.in-addr.arpa.                86400    IN    PTR      ns1.megacorpone.com.
...
```

Information gathering has a cyclic pattern, so we'll need to
perform all the other passive and active enumeration tasks on this new subset of hosts to disclose any new potential details.

## NSlookup

nslookup is another great utility for Windows DNS enumeration and still used during 'Living off the Land' scenarios.

```Powershell
C:\Users\student>nslookup mail.megacorptwo.com
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.50.151

Name:    mail.megacorptwo.com
Address:  192.168.50.154

C:\Users\student>nslookup -type=TXT info.megacorptwo.com 192.168.50.151
Server:  UnKnown
Address:  192.168.50.151

info.megacorptwo.com    text =

        "greetings from the TXT record body"
```

## Port Scanning

The process of inspecting TCP or UDP ports on a remote machine with the intention of detecting what services are running on the target and what potential attack vectors may exist.

- Comprehensive port scans can overload servers and network links, as well as set off IDS/IPS.

- Great to run in the background while performing other enumeration.

- Port scanning should be understood as a dynamic process that is unique to each engagement. 

- The results of one scan determine the type and scope of the next scan.

## Netcat

Netcat is not a port scanner, but it can be used as such in a rudimentary way to showcase how a typical port scanner works.

### TCP Port Scanning Techniques

aka CONNECT scanning

- relies on the three-way TCP handshake

We can demonstrate this by running a TCP Netcat port scan on ports 3388-3390. We'll use the -w option to specify the connection timeout in seconds, as well as -z to specify zero-I/O mode, which is used for scanning and sends no data.
```bash
kali@kali:~$ nc -nvv -w 1 -z 192.168.50.152 3388-3390
(UNKNOWN) [192.168.50.152] 3390 (?) : Connection refused
(UNKNOWN) [192.168.50.152] 3389 (ms-wbt-server) open
(UNKNOWN) [192.168.50.152] 3388 (?) : Connection refused
 sent 0, rcvd 0
 ```

 Wireshark points out your scan.

Let's run a UDP Netcat port scan against ports 80, 153 & 443 on a different target. We'll use the only nc option we have not covered yet, -u, which indicates a UDP scan. Since UDP is stateless and does not involve a three-way handshake, the mechanism behind UDP port scanning is different from TCP.

```bash
kali@kali:~$ nc -nv -w 1 -u -z 173.213.236.147 80 153 443
Connection to 173.213.236.147 80 port [udp/*] succeeded!
Connection to 173.213.236.147 153 port [udp/*] succeeded!
Connection to 173.213.236.147 443 port [udp/*] succeeded!

```

- Most UDP scanners tend to use the standard "ICMP port unreachable" message to infer the status of a target port. However, this method can be completely unreliable when the target port is filtered by a firewall. In fact, in these cases the scanner will report the target port as open because of the absence of the ICMP message.

*Could you use this information to find information about an entity's firewalls?*

- Many port scanners do not scan all available ports, and usually have a pre-set list of "interesting ports" that are scanned.

- Use a protocol-specific UDP port scanner to obtain more accurate results. 

### iptables

A user-space utility program that allows a system administrator to configure the IP packet filter rules of the Linux kernel firewall, implemented as different Netfilter modules.

Let's use the -I option to insert a new rule into a given chain, which in this case includes both the INPUT (Inbound) and OUTPUT (Outbound) chains, followed by the rule number. We can use -s to specify a source IP address, -d to specify a destination IP address, and -j to ACCEPT the traffic. Finally, we'll use the -Z option to zero the packet
and byte counters in all chains.

```bash
kali@kali:~$ sudo iptables -I INPUT 1 -s 192.168.50.149 -j ACCEPT

kali@kali:~$ sudo iptables -I OUTPUT 1 -d 192.168.50.149 -j ACCEPT

kali@kali:~$ sudo iptables -Z
```

You can review some iptables statistics to get a clearer idea of how much traffic our scan generated. We can use the -v option to add some verbosity to our output, -n to enable numeric output, and -L to list the rules present in all chains.
```bashrc
kali@kali:~$ sudo iptables -vn -L
Chain INPUT (policy ACCEPT 1270 packets, 115K bytes)
 pkts bytes target     prot opt in     out     source               destination
 1196 47972 ACCEPT     all  --  *      *       192.168.50.149      0.0.0.0/0

Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
 pkts bytes target     prot opt in     out     source               destination

Chain OUTPUT (policy ACCEPT 1264 packets, 143K bytes)
 pkts bytes target     prot opt in     out     source               destination
 1218 72640 ACCEPT     all  --  *      *       0.0.0.0/0            192.168.50.149
```
According to the output, this default 1000-port scan generated around 72 KB of traffic.

## Nmap 

#### TLDR

- Extensive port scan on the whole range, see what ports are open, "nmap 123.123.123.123 nmap -p- -sV -sC -sT $IP —open -oA nmap/fullscan.nmap" # You can also do -A (all scripts) instead of -sC (simple scripts)
- Run a UDP scan, "sudo nmap -sU 192.168.50.149"

```bashrc
kali@kali:~$ nmap -p 1-65536 192.168.50.149
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-09 05:12 EST
Nmap scan report for 192.168.50.149
Host is up (0.10s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Nmap done: 1 IP address (1 host up) scanned in 10.95 seconds
```
- A local tcp port scan explicitly probing all 65535 ports generated about 4 MB of traffic - a significantly higher amount than if you only scanned the default. However, this full port scan has discovered more ports than the default TCP scan found.

- Our results imply that a full Nmap scan of a class C network (254 hosts) would result in sending over 1000 MB of traffic to the network. This is especially true for larger networks, such as a class A or B network assessment.

- **MASSCAN and RustScan**, although faster than Nmap, generate a substantial amount of concurrent traffic. Nmap, on the other hand, imposes some traffic rate limiting that results in less bandwidth congestion and more covert behavior.

#### SYN ("stealth") Scanning

SYN scanning is a TCP port scanning method that involves sending SYN packets to various ports on a target machine without completing a TCP handshake. 

- If a TCP port is open, a SYN-ACK should be sent back from the target machine, informing us that the port is open. At this point, the port scanner does not bother to send the final ACK to complete the three-way handshake.

- default when raw socket priviledges

```bash
kali@kali:~$ sudo nmap -sS 192.168.50.149
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-09 06:31 EST
Nmap scan report for 192.168.50.149
Host is up (0.11s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
...
```

- Because the three-way handshake is never completed, the information is not passed to the application layer and as a result, will not appear in any application logs. A SYN scan is also faster and more efficient because fewer packets are sent and received.

- Modern firewalls will still log incomplete TCP connections

### TCP Connect Scanning

- default when doesn't have raw socket priviledges
- performs a three-way handshake, uses Berkeley sockets API
- takes much longer
- please also (at least) check for snmp on port 161 (udp)

We may occasionally need to perform a connect scan using nmap, such as when scanning via certain types of proxies. We can use the -sT option to start a connect scan.
```bashrc
kali@kali:~$ nmap -sT 192.168.50.149
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-09 06:44 EST
Nmap scan report for 192.168.50.149
Host is up (0.11s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
...
```
The output shows that the connect scan resulted in a few open services that are only active on the Windows-based host, especially Domain Controllers, as we'll cover shortly. One major takeaway, even from this simple scan, is that we can already infer the underlying OS and role of the target host.

### UDP Scanning

For most ports, it will use the standard "ICMP port unreachable" method described earlier by sending an empty packet to a given port. However, for common ports, such as port 161, which is used by SNMP, it will send a protocol-specific SNMP packet in an attempt to get a response from an application bound to that port.

```bash
kali@kali:~$ sudo nmap -sU 192.168.50.149
Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-04 11:46 EST
Nmap scan report for 192.168.131.149
Host is up (0.11s latency).
Not shown: 977 closed udp ports (port-unreach)
PORT      STATE         SERVICE
123/udp   open          ntp
389/udp   open          ldap
...
Nmap done: 1 IP address (1 host up) scanned in 22.49 seconds
```

The UDP scan (-sU) can also be used in conjunction with a TCP SYN scan (-sS) to build a more complete picture of our target.

### Network Sweeping

- Begin with broad scans, then use more specific scans against hosts of interest. 
- Helps deal with large volumes of hosts

When performing a network sweep with Nmap using the -sn option, the host discovery process consists of more than just sending an ICMP echo request. Nmap also sends a TCP SYN packet to port 443, a TCP ACK packet to port 80, and an ICMP timestamp request to verify whether a host is available.

**Use Nmap's "greppable" output parameter, -oG, to save these results in a more manageable format**

Using nmap to perform a network sweep and then using grep to find live hosts.
```bash
kali@kali:~$ nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-10 03:21 EST
Initiating Ping Scan at 03:21
...
Read data files from: /usr/bin/../share/nmap
Nmap done: 254 IP addresses (13 hosts up) scanned in 3.74 seconds
...

kali@kali:~$ grep Up ping-sweep.txt | cut -d " " -f 2
192.168.50.6
192.168.50.8
192.168.50.9
...
```

We can also sweep for specific TCP or UDP ports across the network, probing for common services and ports in an attempt to locate systems that may be useful or have known vulnerabilities.
```bash
kali@kali:~$ nmap -p 80 192.168.50.1-253 -oG web-sweep.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-10 03:50 EST
Nmap scan report for 192.168.50.6
Host is up (0.11s latency).

PORT   STATE SERVICE
80/tcp open  http

Nmap scan report for 192.168.50.8
Host is up (0.11s latency).

PORT   STATE  SERVICE
80/tcp closed http
...

kali@kali:~$ grep open web-sweep.txt | cut -d" " -f2
192.168.50.6
192.168.50.20
192.168.50.21
```

To save time and network resources, we can also scan multiple IPs, probing for a short list of common ports. Let's conduct a
TCP connect scan for the top 20 TCP ports with the --top-ports option and enable OS version detection, script scanning, and traceroute with -A.
```bash
kali@kali:~$ nmap -sT -A --top-ports=20 192.168.50.1-253 -oG top-port-sweep.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-10 04:04 EST
Nmap scan report for 192.168.50.6
Host is up (0.12s latency).

PORT     STATE  SERVICE       VERSION
21/tcp   closed ftp
22/tcp   open   ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 56:57:11:b5:dc:f1:13:d3:50:88:b8:ab:a9:83:e2:29 (RSA)
|   256 4f:1d:f2:55:cb:40:e0:76:b4:36:90:19:a2:ba:f0:44 (ECDSA)
|_  256 67:46:b3:97:26:a9:e3:a8:4d:eb:20:b3:9b:8d:7a:32 (ED25519)
23/tcp   closed telnet
25/tcp   closed smtp
53/tcp   closed domain
80/tcp   open   http          Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Under Construction
110/tcp  closed pop3
111/tcp  closed rpcbind
...
```

**OS fingerprinting can be enabled with the -O option, or --osscan-guess for best guess.**
```bash
kali@kali:~$ sudo nmap -O 192.168.50.14 --osscan-guess
...
Running (JUST GUESSING): Microsoft Windows 2008|2012|2016|7|Vista (88%)
OS CPE: cpe:/o:microsoft:windows_server_2008::sp1 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista::sp1:home_premium
Aggressive OS guesses: Microsoft Windows Server 2008 SP1 or Windows Server 2008 R2 (88%), Microsoft Windows Server 2012 or Windows Server 2012 R2 (88%), Microsoft Windows Server 2012 R2 (88%), Microsoft Windows Server 2012 (87%), Microsoft Windows Server 2016 (87%), Microsoft Windows 7 (86%), Microsoft Windows Vista Home Premium SP1 (85%), Microsoft Windows 7 Professional (85%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
...
```

Once we have recognized the underlying operating system, we can go further and identify services running on specific ports by inspecting service banners with -A parameter which also runs various OS and service enumeration scripts against the target.

**Use --script *script* option for more complex nmap scripts**

- To view more information about a script, use the --script-help *script* option

### Test-NetConnection

For Windows

Checks if an IP responds to ICMP and whether a specified TCP port on the target is open.

Testing whether the SMB port 445 is open on a domain controller.
```bash
PS C:\Users\student> Test-NetConnection -Port 445 192.168.50.151

ComputerName     : 192.168.50.151
RemoteAddress    : 192.168.50.151
RemotePort       : 445
InterfaceAlias   : Ethernet0
SourceAddress    : 192.168.50.152
TcpTestSucceeded : True
```
Check if *TcpTestSucceeded* is true or false.

### TcpClient

For Windows

Script the process of scanning the first 1024 ports. Instantiate a TcpClient Socket object as Test-NetConnection.
```bash
PS C:\Users\student> 1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("172.16.156.20", $_)) "TCP port $_ is open"} 2>$null
TCP port 88 is open
...
```
We start by piping the first 1024 integer into a for-loop which assigns the incremental integer value to the $_ variable. Then, we create a Net.Sockets.TcpClient object and perform a TCP connection against the target IP on that specific port, and if the connection is successful, it prompts a log message that includes the open TCP port.

SMB has historically been a point of vulnerability due to its complex implementation and open nature. 

NetBIOS is an independent session layer protocol and service that allows computers on a local network to communicate with each other. While modern implementations of SMB can work without NetBIOS, NetBIOS over TCP (NBT) is required for backward compatibility and these are often enabled together. This also means the enumeration of these two services often goes hand-in-hand. These services can be scanned with nmap.

```bash
kali@kali:~$ nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254

kali@kali:~$ cat smb.txt
# Nmap 7.92 scan initiated Thu Mar 17 06:03:12 2022 as: nmap -v -p 139,445 -oG smb.txt 192.168.50.1-254
# Ports scanned: TCP(2;139,445) UDP(0;) SCTP(0;) PROTOCOLS(0;)
Host: 192.168.50.1 ()	Status: Down
...
Host: 192.168.50.21 ()	Status: Up
Host: 192.168.50.21 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
...
Host: 192.168.50.217 ()	Status: Up
Host: 192.168.50.217 ()	Ports: 139/closed/tcp//netbios-ssn///, 445/closed/tcp//microsoft-ds///
# Nmap done at Thu Mar 17 06:03:18 2022 -- 254 IP addresses (15 hosts up) scanned in 6.17 seconds
```

If you're specifically looking to identify NBT, you can use *nbtscan*. The following queries the NetBIOS name service for valid NetBIOS names, specifying the originating UDP port as 137 with the -r option.
```bash
kali@kali:~$ sudo nbtscan -r 192.168.50.0/24
Doing NBT name scan for addresses from 192.168.50.0/24

IP address       NetBIOS Name     Server    User             MAC address
------------------------------------------------------------------------------
192.168.50.124   SAMBA            <server>  SAMBA            00:00:00:00:00:00
192.168.50.134   SAMBAWEB         <server>  SAMBAWEB         00:00:00:00:00:00
...
```
This kind of information can be used to further improve the context of the scanned hosts, as NetBIOS names are often very descriptive about the role of the host within the organization.

**NSE scripts are located in /usr/share/nmap/scripts/**

- The SMB discovery script works only if SMBv1 is enabled on the target, which is not the default case on modern versions of Windows.

The following script is run on the Windows 11 client, and shows how the nmap scripting engine should be taken with a grain of salt.
```bash
kali@kali:~$ nmap -v -p 139,445 --script smb-os-discovery 192.168.50.152
...
PORT    STATE SERVICE      REASON
139/tcp open  netbios-ssn  syn-ack
445/tcp open  microsoft-ds syn-ack

Host script results:
| smb-os-discovery:
|   OS: Windows 10 Pro 22000 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: client01
|   NetBIOS computer name: CLIENT01\x00
|   Domain name: megacorptwo.com
|   Forest name: megacorptwo.com
|   FQDN: client01.megacorptwo.com
|_  System time: 2022-03-17T11:54:20-07:00
...
```

- NSE scripting provides extra information, such as the doamin and other details related to Active Directory Domain Services, and is more likely to go unnoticed (produces less traffic).

## SMTP & SMB

#### Net View 

Useful tool for enumerating SMB shares within Windows environments.It lists domains, resources, and computers belonging to a given host

```bash
C:\Users\student>net view \\dc01 /all
Shared resources at \\dc01

Share name  Type  Used as  Comment

-------------------------------------------------------------------------------
ADMIN$      Disk           Remote Admin
C$          Disk           Default share
IPC$        IPC            Remote IPC
NETLOGON    Disk           Logon server share
SYSVOL      Disk           Logon server share
The command completed successfully.
```
By providing the /all keyword, we can list the administrative shares ending with the dollar sign.

We can also gather information about a host or network from vulnerable mail servers. 
- VRFY request asks the server to verify an email address
- EXPN asks the server for the membership of a mailing list

Using nc to validate SMTP users.
```bash
kali@kali:~$ nc -nv 192.168.50.8 25
(UNKNOWN) [192.168.50.8] 25 (smtp) open
220 mail ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
^C
```

If not already enabled, install the Microsoft vrsion of the Telnet client. Requires admin priviledges. 
```bash
PS C:\Windows\system32> dism /online /Enable-Feature /FeatureName:TelnetClient  
...
```
If low-priviledge user, grab the Telnet binary located on another development machine of ours at c:\windows\system32\telnet.exe and transfer it to the Windows machine that we are testing from.

Once we have enabled Telnet on the testing machine, we can connect to  the target machine and perform enumeration as we did from Kali.
```bash
C:\Windows\system32>telnet 192.168.50.8 25
220 mail ESMTP Postfix (Ubuntu)
VRFY goofy
550 5.1.1 <goofy>: Recipient address rejected: User unknown in local recipient table
VRFY root
252 2.0.0 root
```
Interacting with the SMTP service via Telnet on Windows.

**Simple Network Management Protocol (SNMP) is not well-understood by many network administrators. This often results in SNMP misconfigurations, which can result in significant information leaks.**
- SNMP is based on UDP, a simple, stateless protocol, and is therefore susceptible to IP spoofing and replay attacks
- Additionally, the commonly used SNMP protocols 1, 2, and 2c offer no traffic encryption, meaning that SNMP information and credentials can be easily intercepted over a local network.
- Traditional SNMP protocols also have weak authentication schemes and are commonly left configured with default public and private community strings.
- Until recently, SNMPv3, which provides authentication and encryption, has been shipped to support only DES-56, proven to be a weak encryption scheme that can be easily brute-forced
- A more recent SNMPv3 implementation supports the AES-256 encryption scheme.

**Make it a point to scan for default nelnet credentials.**
"A quick scan for default cisco / cisco telnet credentials discovered a single low-end Cisco ADSL router. Digging a bit further revealed a set of complex SNMP public and private community strings in the router configuration file. As it turned out, these same public and private community strings were used on every single networking device, for the whole class B range, and beyond – simple management, right?"

To scan for open SNMP ports, we can run nmap, using the  -sU option to perform UDP scanning and the --open option to limit the output and display only open ports.
```bash
kali@kali:~$ sudo nmap -sU --open -p 161 192.168.50.1-254 -oG open-snmp.txt
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-14 06:02 EDT
Nmap scan report for 192.168.50.151
Host is up (0.10s latency).

PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
...
```

#### onesixtyone

Will attempt a brute force attack against a list of IP addresses. First, we must build text files containing community strings and the IP addresses we wish to scan.
```bash
kali@kali:~$ echo public > community
kali@kali:~$ echo private >> community
kali@kali:~$ echo manager >> community

kali@kali:~$ for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips

kali@kali:~$ onesixtyone -c community -i ips
Scanning 254 hosts, 3 communities
192.168.50.151 [public] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
...
```

Once we find SNMP services, we can start querying them for specific MIB data that may be interesting.

#### snmpwalk

Great tool to probe and query SNMP value, provided we know the SNMP read-only community string, which in most cases is "public".

Windows SNMP MIB values.
```bash
1.3.6.1.2.1.25.1.6.0 	System Processes
1.3.6.1.2.1.25.4.2.1.2 	Running Programs
1.3.6.1.2.1.25.4.2.1.4 	Processes Path
1.3.6.1.2.1.25.2.3.1.4 	Storage Units
1.3.6.1.2.1.25.6.3.1.2 	Software Name
1.3.6.1.4.1.77.1.2.25 	User Accounts
1.3.6.1.2.1.6.13.1.3 	TCP Local Ports
```
Use some of the MIB values provided in Table 1 to enumerate their corresponding values. Let's try the following example against a known machine in the labs, which hasa Windows SNMP port exposed with the community string "public". This command enumerates the entire MIB tree using the -c option to specify the community string, and -v to specify the SNMP version number as well as the -t 10 option to increase the timeout period to 10 seconds:
```bash
kali@kali:~$ snmpwalk -c public -v1 -t 10 192.168.50.151
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.3
iso.3.6.1.2.1.1.3.0 = Timeticks: (78235) 0:13:02.35
iso.3.6.1.2.1.1.4.0 = STRING: "admin@megacorptwo.com"
iso.3.6.1.2.1.1.5.0 = STRING: "dc01.megacorptwo.com"
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 79
iso.3.6.1.2.1.2.1.0 = INTEGER: 24
...
```
We can use the output above to obtain target email addresses. This information can be used to craft a social engineering attack against the newly-discovered contacts.

We can parse a specific branch of the MIB Tree called OID. 
```bash
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.4.1.77.1.2.25
iso.3.6.1.4.1.77.1.2.25.1.1.5.71.117.101.115.116 = STRING: "Guest"
iso.3.6.1.4.1.77.1.2.25.1.1.6.107.114.98.116.103.116 = STRING: "krbtgt"
iso.3.6.1.4.1.77.1.2.25.1.1.7.115.116.117.100.101.110.116 = STRING: "student"
iso.3.6.1.4.1.77.1.2.25.1.1.13.65.100.109.105.110.105.115.116.114.97.116.111.114 = STRING: "Administrator"
```
We can also enumerate all the currently running processes:
```bash
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.25.4.2.1.2
iso.3.6.1.2.1.25.4.2.1.2.1 = STRING: "System Idle Process"
iso.3.6.1.2.1.25.4.2.1.2.4 = STRING: "System"
iso.3.6.1.2.1.25.4.2.1.2.88 = STRING: "Registry"
iso.3.6.1.2.1.25.4.2.1.2.260 = STRING: "smss.exe"
iso.3.6.1.2.1.25.4.2.1.2.316 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.372 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.472 = STRING: "svchost.exe"
iso.3.6.1.2.1.25.4.2.1.2.476 = STRING: "wininit.exe"
iso.3.6.1.2.1.25.4.2.1.2.484 = STRING: "csrss.exe"
iso.3.6.1.2.1.25.4.2.1.2.540 = STRING: "winlogon.exe"
iso.3.6.1.2.1.25.4.2.1.2.616 = STRING: "services.exe"
iso.3.6.1.2.1.25.4.2.1.2.632 = STRING: "lsass.exe"
iso.3.6.1.2.1.25.4.2.1.2.680 = STRING: "svchost.exe"
...
```
When combined with the running process list we obtained earlier, this information can become extremely valuable for cross-checking the exact software version a process is running on the target host.

Another SNMP enumeration technique is to list all the current TCP listening ports:
```bash
kali@kali:~$ snmpwalk -c public -v1 192.168.50.151 1.3.6.1.2.1.6.13.1.3
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.88.0.0.0.0.0 = INTEGER: 88
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.135.0.0.0.0.0 = INTEGER: 135
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.389.0.0.0.0.0 = INTEGER: 389
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.445.0.0.0.0.0 = INTEGER: 445
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.464.0.0.0.0.0 = INTEGER: 464
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.593.0.0.0.0.0 = INTEGER: 593
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.636.0.0.0.0.0 = INTEGER: 636
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3268.0.0.0.0.0 = INTEGER: 3268
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.3269.0.0.0.0.0 = INTEGER: 3269
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5357.0.0.0.0.0 = INTEGER: 5357
iso.3.6.1.2.1.6.13.1.3.0.0.0.0.5985.0.0.0.0.0 = INTEGER: 5985
...
```
The integer value from the output above represents the current listening TCP ports on the target. This information can be extremely useful as it can disclose ports that are listening only locally and thus reveal a new service that had been previously unknown.

#### SNMP Brute

Consider using whenever you can.

#### Processes

To look at all processes.

```bash
ps aux
```

Easier to parse through, shown in trees. If you have a reverse shell in an app, you can locate which app you're running in.

```bash
ps -ef --forest | less
```

#### Server Side Template Injection (SSTI)

Check input fields, such as inserting {{7\*7}} and seeing whether you get a string or 49. There are good resources on hacktricks.xyz

#### Modifying Response Header (IDOR)

If you're getting a bunch of 301s and 302s in GoBuster, try modifying the header in BurpSuite to a 200 and see if it's possible to view the webpage. What tips you off is when the 301s and 302s response with varying page sizes in your tool. Alternatively, if it's an account login page, you can try to pass additional parameters straight through Burp - username, password, and possibly a confirmation parameter. If you need a confirmation parameter, you can fuzz for that.

#### What to Check for in GoBuster 

First, always check to see what type of extensions that the IP or website supports. Check for the extensions {.php, .html, .js, .asp, .aspx, .jsp}. If one of them works, use the '-x {extension}' method for better enumeration.

**Also, always check for both domains and subdomains.**

#### Linux SMB

Enumerate users by doing:
```bash
rpclient -U '' -N 123.123.123.123

$>enumdomusers
```
#### Automated Crawling with Cewl

You can use cewl to crawl a website with depth and look for whatever you want, given that you can put it in rules. This example uses cewl to crawl a max of 7 pages deep, and find words that are at least 8 characters long with numbers.

```bash
cewl -d 7 -m 8 --with-numbers -w cewl.out https://123.123.123.123/index.htm
```

#### Word List Generator

OffSec recommends using a word list generator on websites when you have usernames, no passwords, and need to login to a panel in order to continue enumerating.