# SNMP - Port 161

#### SNMPWalk

Always run this is snmp is open:

```bash
snmpwalk -v 2 -c public $ip NET-SNMP-EXTEND-MIB::nsExtendObjects
```

````
sudo nmap --script snmp-* -sU -p161 $IP
sudo nmap -sU -p 161 --script snmp-brute $ip --script-args snmp-brute.communitiesdb=/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
````

````
snmpwalk -c public -v1 $IP
````

##### Hacktricks

````
https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp
````

````
apt-get install snmp-mibs-downloader
sudo download-mibs
sudo vi /etc/snmp/snmp.conf
````

````
$ cat /etc/snmp/snmp.conf     
# As the snmp packages come without MIB files due to license reasons, loading
# of MIBs is disabled by default. If you added the MIBs you can reenable
# loading them by commenting out the following line.
#mibs :

# If you want to globally change where snmp libraries, commands and daemons
# look for MIBS, change the line below. Note you can set this for individual
# tools with the -M option or MIBDIRS environment variable.
#
# mibdirs /usr/share/snmp/mibs:/usr/share/snmp/mibs/iana:/usr/share/snmp/mibs/ietf
````

````
sudo snmpbulkwalk -c public -v2c $ip .
sudo snmpbulkwalk -c public -v2c $ip NET-SNMP-EXTEND-MIB::nsExtendOutputFull 
````