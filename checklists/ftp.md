# FTP Checklist

1. See if there is anonymous access

```bash
ftp 10.10.10.10
# input anonymous as username and password
# try in the browser
ftp://anonymous:anonymous@10.10.10.98
```

2. Additional Enumeration

```bash
nmap --script ftp-* -p 21 10.10.10.10
```

3. Brute force

```bash
hydra -l USERNAME -P /opt/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -f 192.168.X.XXX ftp -V
```

3. Recursively download content

```bash
> prompt off
> recurse on
> mget *
```

