# Very informative version of 'ls'
alias ll='ls -lsaht --color=auto'
# ll .

# Quick way to set up a netcat listener
alias listen='ip a | grep tun0; sudo rlwrap -cAz nc -lvnp'
# listen 443

# Alternative to Nmap scan, much faster
alias scan='sudo rustscan -t 3000 --tries 2 -b 2048 -u 16384 -a'
# scan 192.168.45.213 > initial

# So that you can view output of rustscan in sublime, use on output file of rustscan
alias clean='sed -e '\''s/\x1b\[[0-9;]*m//g'\'
# clean initial > rustscan.txt

alias breakout='cat /path/to/breakout.md'

alias revshells='cat /path/to/revshells'