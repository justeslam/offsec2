#!/bin/bash
# Example usage:
#   source /opt/setenv.sh <ip> <domain> <dc>
#   source /opt/setenv.sh <ip> <domain> <dc> <user> <pass>

# Assign positional arguments to variables
export ip="$1"
export dom="$2"
export dc="$3"

# Assign optional arguments if provided
export user="$4"
export pass="$5"

# Check if 'dom' is unset or empty, set 'url' accordingly
if [[ -z "$dom" ]]; then
    export url="http://$ip"
else
    export url="http://$dom"
fi

# Optional: Display the set environment variables for verification
# Uncomment the lines below if you want to see the variables when sourcing
# echo "ip=$ip"
# echo "dom=$dom"
# echo "dc=$dc"
# echo "url=$url"
# if [[ -n "$user" ]]; then
#     echo "user=$user"
# fi
# if [[ -n "$pass" ]]; then
#     echo "pass=$pass"
# fi
