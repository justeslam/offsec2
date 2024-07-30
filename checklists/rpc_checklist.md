# RPC Checklist

````
nmap -sV -p 111 --script=rpcinfo $ip
nmap -sV -p 111 --script=rpc* $ip
rpcdump.py $ip -p 135
````
#List the ports using RPC
rpcinfo 10.10.10.10
> Output would look something like below
    100024    1    udp       0.0.0.0.150.11         status     29
    100024    1    tcp       0.0.0.0.219.244        status     29
    100024    1    udp6      ::.153.127             status     29
    100024    1    tcp6      ::.172.42              status     29

#list accessible RPC service endpoints
rpcinfo -p 10.10.10.10

Domain Enumeration with RPcclient
#Enum using Null Session
rpcclient -U "" 10.10.10.10

#Login as a user
rpcclient -U USERNAME //10.10.10.10

#Find Users in the domain 
rpcclient -Uuser_Name%PASSWORD -c enumdomusers 10.10.10.10

#Find Domian Info
rpcclient -Uuser_Name%PASSWORD -c querydominfo  10.10.10.10

#Find Groups and their Alias
rpcclient -Uuser_Name%PASSWORD -c "enumalsgroups builtin" 10.10.10.10

#Find more info using Alias and note SIDs
rpcclient -Uuser_Name%PASSWORD -c "queryaliasmem builtin 0x244" 10.10.10.10

#Find more info using SIDs
rpcclient $> lookupsids S-1-5-21-586154515854-343543654-8743952433-1105 

#Reset other Users Password
rpcclient -U user1 //10.10.10.10
setuserinfo2 USER2 23 'PASSWORD'

Enum using RPCClient

rpcclient -U DOMAIN\\Username 10.10.10.10   #Enter pass 

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
lsalookupprivvalue SeCreateTokenPrivielge

#Run the below command
for command in $(cat commands.txt); do rpcclient -U "%" -c $command 10.10.10.10; done