#!/bin/bash

# Script: nxc.sh
# Purpose: Quickly check authentication of new user, password, hash, ticket or interesting word using NetExec authentication across smb, winrm, ssh, ftp, rdp, wmi, ldap, mssql, vnc. Supports kerberos authentication.
# Author: itsnotgunnar

# Usage function
usage() {
    echo "Usage: $0 [--use-kcache] [-i <ip_address> | -t <targets_file>] -u <username> [-p <password> | -P <passwords_file> | -H <hashes_file>] [-k <ccache_file>] [-o <output_directory>]"
    echo ""
    echo "Options:"
    echo "  -i <ip_address>         Direct IP address to test"
    echo "  -t <targets_file>       File containing list of IP addresses or subnets"
    echo "  -u <username>           Username to test"
    echo "  -p <password>           Password to test"
    echo "  -H <hashes_file>        File containing list of NTLM hashes"
    echo "  -k <ccache_file>        Specify Kerberos credential cache file for authentication"
    echo "  --use-kcache            Use KRB5CCNAME environment variable for authentication (or '-k' arg if given)"
    echo "  -o <output_directory>   Output directory for results"
    exit 1
}

# Default output directory
OUTPUT_DIR="$(pwd)"

# Initialize variables
TARGETS_FILE=""
IP_ADDRESS=""
USERNAME=""
PASSWORD=""
HASHES_FILE=""
CCACHE_FILE=""
USE_KCACHE=0

# Parse command-line arguments
while getopts ":i:t:u:p:H:k:o:-:" opt; do
    case $opt in
        i) IP_ADDRESS="$OPTARG" ;;
        t) TARGETS_FILE="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        H) HASHES_FILE="$OPTARG" ;;
        k) CCACHE_FILE="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        -)
            case "${OPTARG}" in
                use-kcache)
                    USE_KCACHE=1
                    ;;
                *)
                    usage
                    ;;
            esac
            ;;
        *) usage ;;
    esac
done

# Check required arguments
if { [ -z "$TARGETS_FILE" ] && [ -z "$IP_ADDRESS" ]; } || { [ -z "$USERNAME" ] && [ -z "$USERS_FILE" ] && [ "$USE_KCACHE" -eq 0 ]; } || { [ -z "$PASSWORD" ] && [ -z "$PASSWORDS_FILE" ] && [ -z "$HASHES_FILE" ] && [ "$USE_KCACHE" -eq 0 ]; }; then
    usage
fi

# Set Kerberos credential cache file if specified
if [ -n "$CCACHE_FILE" ]; then
    local KRB5CCNAME="$CCACHE_FILE"
fi

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Read targets into an array if a file is provided
if [ -n "$TARGETS_FILE" ]; then
    mapfile -t TARGETS < "$TARGETS_FILE"
elif [ -n "$IP_ADDRESS" ]; then
    TARGETS=("$IP_ADDRESS")
fi

# Define protocols and services to test
SERVICES=("smb" "winrm" "ssh" "ftp" "rdp" "wmi" "ldap" "mssql" "vnc")

# Function to execute NetExec commands
execute_netexec() {
    local ip="$1"
    local service="$2"
    local user="$3"
    local pass="$4"
    local hash_file="$5"
    local ccache_file="$6"
    local use_kcache="$USE_KCACHE"
    echo $ccache_file

    local cmd="nxc $service $ip"
    [[ -n "$user" ]] && cmd+=" -u $user"
    [[ -n "$pass" ]] && cmd+=" -p $pass"
    [[ -n "$hash_file" ]] && cmd+=" -H $hash_file"
    [[ "$use_kcache" -eq 1 ]] && cmd="nxc $service $ip --use-kcache"
    [[  -n "$ccache_file" && "$use_kcache" -eq 0 ]] && cmd+=" -k"

    $cmd | tee -a "$OUTPUT_DIR/nxc.out"
    
    [[ "$service"=="mssql" && -n $user && -n $pass ]] && nxc mssql $ip -u $user -p $pass --local-auth | tee -a "$OUTPUT_DIR/nxc.out"
}

# Export functions and variables for parallel execution
export -f execute_netexec
export USERNAME PASSWORD HASHES_FILE

# Main loop to process each target
for ip in "${TARGETS[@]}"; do
    echo "Processing IP/Range: $ip" | tee -a "$OUTPUT_DIR/nxc.out"

    # Execute commands in parallel for each service
    for service in "${SERVICES[@]}"; do
        echo "Running $service against $ip..." | tee -a "$OUTPUT_DIR/nxc.out"
        execute_netexec "$ip" "$service" "$USERNAME" "$PASSWORD" "$HASHES_FILE" "$CCACHE_FILE" &
    done

    # Wait for all background processes to finish
    wait
done

echo "All tasks completed. Results are stored in the '$OUTPUT_DIR' directory."
