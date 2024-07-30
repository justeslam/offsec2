#### Telnet and POP3- Ports 23 & 110

##### POP3 Enumeration
````
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p 110 $IP
````

##### Login
````
telnet -l jess 10.2.2.23
````

Telnet to port 110 with valid creds to look at mailbox:

````
USER sales
PASS sales
LIST
RETR 1.
````