## SQL Injection Attacks

SQLi vulnerabilities enable attackers to meddle with SQL queries exchanged between the web application and database. SQL vulnerabilities typically allow the attacker to extend the original application query to include database tables that would normally be inaccessible.

We can better understand this concept by examining the  following backend PHP code portion that is responsible for verifying user-submitted credentials during login:
```bash
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```

When testing a web application, we sometimes lack prior knowledge of the underlying database system, so we should be prepared to interact with different SQL database variants. The most common variants are MySQL and Microsoft SQL Server (MSSQL).

#### MySQL

Using the mysql command, you can connect to the remote SQL instance by specifying root as username and password, along with the default MySQL server port 3306.
```bash
kali@kali:~$ mysql -u root -p'root' -h 192.168.50.16 -P 3306

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```
The root user in this example is the database-specific 
root user, not the the system-wide administrative root user.

Show version and user.
```bash
MySQL [(none)]> select version();
+-----------+
| version() |
+-----------+
| 8.0.21    |
+-----------+
1 row in set (0.107 sec)

MySQL [(none)]> select system_user();
+--------------------+
| system_user()      |
+--------------------+
| root@192.168.20.50 |
+--------------------+
1 row in set (0.104 sec)
```

Collect a list of databases:
```bash
MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| test               |
+--------------------+
5 rows in set (0.107 sec)
```

As an example, let's retrieve the password of the offsec user present in the mysql database.
```bash
MySQL [mysql]> SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
+--------+------------------------------------------------------------------------+
| user   | authentication_string                                                  |
+--------+------------------------------------------------------------------------+
| offsec | $A$005$?qvorPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6|
+--------+------------------------------------------------------------------------+
1 row in set (0.106 sec)
```
To improve its security, the user's password is stored in the authentication_string field as a Caching-SHA-256 algorithm.

#### MSSQL

A built-in command-line tool named SQLCMD allows SQL queries to be run through the Windows command prompt or even remotely from another machine.

Kali Linux includes Impacket, a Python framework that enables network protocol interactions. Among many other protocols, it supports Tabular Data Stream (TDS), the protocol adopted by MSSQL that is implemented in the impacket-mssqlclient tool.

Run **impacket-mssqlclient** to connect to the remote Windows machine running MSSQL by providing a username, a password, and the remote IP, together with the -windows-auth keyword. This forces NTLM authentication (as opposed to Kerberos)
```bash
kali@kali:~$ impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(SQL01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL>
```

Every database management system has its own syntax that we should take into consideration when enumerating a target during a penetration test.
```bash
SQL>SELECT @@version;
...

Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
	Sep 24 2019 13:48:23
	Copyright (C) 2019 Microsoft Corporation
	Express Edition (64-bit) on Windows Server 2022 Standard 10.0 <X64> (Build 20348: ) (Hypervisor)
```

When using a SQL Server command line tool like sqlcmd, we must submit our SQL statement ending with a semicolon followed by GO on a separate line. However, when running the command remotely, we can omit the GO statement since it's not part of the MSSQL TDS protocol.

To list all the available databases, we can select all names from the system catalog.
```bash
SELECT name FROM sys.databases;
name
...
master

tempdb

model

msdb

offsec
```
