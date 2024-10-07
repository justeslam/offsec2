#!/bin/bash

# Check if at least one target is provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 target1 [target2 ...]"
    exit 1
fi

# Iterate over each target provided as an argument
for target in "$@"; do
    echo "Scanning target: $target"

    # Perform initial fast port scan
    ports=$(nmap -p- --min-rate 1000 "$target" | grep "^ *[0-9]" | grep "open" | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

    if [ -z "$ports" ]; then
        echo "No open ports found on $target."
        continue
    fi

    echo "Running second nmap scan with open ports: $ports"

    # Perform detailed scan on discovered open ports
    nmap -p "$ports" -sC -sV -A "$target" -oN 
done