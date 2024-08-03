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

````
show databases;
show tables;
use db_name;
select * from passwords;
````

##### Notes

- If you have a valid password, try using that same password for the admin accounts (root)