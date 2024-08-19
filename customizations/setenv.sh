#!/bin/bash
# Example usage: source /opt/setenv.sh 192.168.165.40 hokkaido-aerospace.com dc.hokkaido-aerospace.com

export ip=$1
export dom=$2
export dc=$3

# Check if 'dom' is unset or empty, set 'url' accordingly
if [[ -z "$dom" ]]; then
    export url="http://$ip"
else
    export url="http://$dom"
fi
