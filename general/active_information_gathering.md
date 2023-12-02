# Active Information Gathering

"Living off the Land" aka LOLBAS - leveraging the tools available on the workstation. Applications that can provide unintended code execution are normally listed under the LOLBAS project


## DNS Records Defined

	NS: Nameserver records contain the name of the authoritative servers hosting the DNS records for a domain.
	A: Also known as a host record, the "a record" contains the IPv4 address of a hostname (such as www.megacorpone.com).
	AAAA: Also known as a quad A host record, the "aaaa record" contains the IPv6 address of a hostname (such as www.megacorpone.com).
	MX: Mail Exchange records contain the names of the servers responsible for handling email for the domain. A domain can contain multiple MX records.
	PTR: Pointer Records are used in reverse lookup zones and can find the records associated with an IP address.
	CNAME: Canonical Name Records are used to create aliases for other host records.
	TXT: Text records can contain any arbitrary data and be used for various purposes, such as domain ownership verification.


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

## dnsrecon

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

### Netcat

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

#### iptables

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

### Nmap 

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

#### TCP Connect Scanning

- default when doesn't have raw socket priviledges