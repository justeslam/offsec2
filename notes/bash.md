## General Bash

#### Debugging bash script.

Add '#!/bin/bash -x' to your bash script to output what your script is doing as it does it, or you can run it with 'bash -x file.sh'.

```bash
# If you want to be more granular
set -x
code..
set +x
```

#### Variables

You cannot have whitespace around '='.

Echo'ing variable in string.

```bash
book="black hat bash"
echo "This book's name is ${book}"
```

Assigning output of command to variable.

```bash
root_directory="$(ls -ld /)"
echo "${root_directory}"
```

Unsetting variable.

```bash
book="this book"
unset book
echo $book
```

Local variables can only be executed within a section of code.

```bash
#!/bin/bash
PUBLISHER="No Starch Press"
print_name(){
local name
name="Black Hat Bash"
echo "${name} by ${PUBLISHER}"
}
print_name
echo "The variable ${name} will not be printed because it is a local variable."
```

#### Operators

```bash
let result="4 * 5"
result=$((5 * 5))
result=$(expr 5 + 505)
```


```
&& # Second command only executes if first is true
; # Runs either way
;; # Ends a case statement
|| # Runs either way
() # Allows you to group commands, (ls;ps)
```

```bash
# Redirects stdout and stderr to a file
&> or >& 
ls -l / &> stdout_and_stderr.txt
ls -l / 1> stdout.txt 2> stderr.txt
lzl 2> error.txt
cat < output.txt

# Redirects stdout and stderr to a file by appending it to the existing content
&>> 
< # Redirects input to a command

# Called a here document or heredoc, redirects multiple input lines to a command
<< 
cat << EOF
what the
heck
EOF
# The EOF in this example acts as a delimiter marking the start andend points of the input.
```

#### Arrays

```bash
IP_ADDRESSES=(192.168.1.1 192.168.1.2 192.168.1.3)
# Print all elements in the array
echo "${IP_ADDRESSES[*]}"
# Print only the first element in the array
echo "${IP_ADDRESSES[0]}" # in zsh it's 1
unset IP_ADDRESSES[1]
IP_ADDRESSES[1]="192.168.1.10"
```

#### Streams

Streams are files that act as communication channels between a program and its environment.

````
0: Standard Input
1: Standard Output 
2: Standard Error
````

#### Positional Args

```
$0 : The name of the script file
$1, $2, $3, [...] : Positional arguments
$# : The number of passed positional arguments
$* : All positional arguments
$@ : All positional arguments, where each argument is individually quoted
```

```bash
#!/bin/bash
# This script will ping any address provided as an argument.
SCRIPT_NAME="${0}"
TARGET="${1}"
echo "Running the script ${SCRIPT_NAME}..."
echo "Pinging the target: ${TARGET}..."
ping "${TARGET}"
```

#### Input Prompting

```bash
#!/bin/bash
# Takes input from the user and assigns it to variables.
echo "What is your first name?"
read -r firstname
echo "What is your last name?"
read -r lastname
echo "Your first name is ${firstname} and your last name is ${lastname}"
```

#### File Test Operators

```
-d FILE Checks whether the file is a directory
-r FILE Checks whether the file is readable
-x FILE Checks whether the file is executable
-w FILE Checks whether the file is writable
-f FILE Checks whether the file is a regular file
-s FILE Checks whether the file size is greater than zero
```

#### String Comparison Operators

```
= Checks whether a string is equal to another string
== Synonym of = when used within [[ ]] constructs
!= Checks whether a string is not equal to another string
< Checks whether a string comes before another string (in alphabetical order)
> Checks whether a string comes after another string (in alphabetical order)
-z Checks whether a string is null
-n Checks whether a string is not null
> Checks whether a string is greater than another string
```

#### Integer Comparison Operators

```
-eq Checks whether a number is equal to another number
-ne Checks whether a number is not equal to another number
-ge Checks whether a number is greater than or equal to another number
-gt Checks whether a number is greater than another number
-lt Checks whether a number is less than another number
-le Checks whether a number is less than or equal to another number
```

#### If Conditions

```bash
if [[ condition ]]; then
# do something if the condition is met
else
# do something if the condition is not met
fi
```

```bash
#!/bin/bash
FILENAME="flow_control_with_if.txt"
if [[ -f "${FILENAME}" ]]; then
echo "${FILENAME} already exists."
exit 1
else
touch "${FILENAME}"
fi
```

```bash
#!/bin/bash
FILENAME="flow_control_with_if.txt"
if [[ ! -f "${FILENAME}" ]]; then
touch "${FILENAME}"
fi
```

```bash
#!/bin/bash
VARIABLE_ONE="nostarch"
VARIABLE_TWO="nostarch"
if [[ "${VARIABLE_ONE}" == "${VARIABLE_TWO}" ]]; then
echo "They are equal!"
else
echo "They are not equal!"
fi
```

```bash
#!/bin/bash
echo "Hello World!" > file.txt
if [[ -f "file.txt" ]] && [[ -s "file.txt" ]]; then
echo "The file exists and its size is greater than zero".
fi
```

```bash
if command; then
# command was successful
fi
if ! command; then
# command was unsuccessful
fi
```

#### Elif

```bash
#!/bin/bash
USER_INPUT="${1}"
if [[ -z "${USER_INPUT}" ]]; then
echo you must provide an argument!
exit 1
fi
if [[ -f "${USER_INPUT}" ]]; then
echo "${USER_INPUT} is a file"
elif [[ -d "${USER_INPUT}" ]]; then
echo "${USER_INPUT} is a directory"
else
echo "${USER_INPUT} is not a file or a directory"
fi
```

#### Functions

```bash
#!/bin/bash
say_name(){
echo "Black Hat Bash"
}
```

#### Returning Values

```bash
#!/bin/bash
check_if_root(){Black Hat Bash (Early Access) © 2023 by Dolev Farhi and Nick Aleks

if [[ "${EUID}" -eq "0" ]]; then
return 0
else
return 1
fi
}
is_root=$(check_if_root)
if [[ "${is_root}" -eq "0" ]]; then
echo "user is root!"
else
echo "user is not root!"
fi
```

### Loops and Loop Controls

#### While

```bash
while some_condition; do
# run commands while the condition is true
done
```

```bash
#!/bin/bash
SIGNAL_TO_STOP_FILE="stoploop"
while [[ ! -f "${SIGNAL_TO_STOP_FILE}" ]]; do
echo "The file ${SIGNAL_TO_STOP_FILE} does not yet exist..."
echo "Checking again in 2 seconds..."
sleep 2
done
echo "File was found! exiting..."
```

#### Until

```bash
until some_condition; do
	# run some commands until the condition is no longer false
done
```

```bash
#!/bin/bash
FILE="output.txt"
touch "${FILE}"
until [[ -s "${FILE}" ]]; do
echo "$FILE is empty..."
echo "Checking again in 2 seconds..."
sleep 2
done
echo "${FILE} appears to have some content in it!"
```

#### For

```bash
for variable_name in LIST; do
# run some commands for each item in the sequence
done
```

```bash
#!/bin/bash
for ip_address in "$@"; do
echo "Taking some action on IP address ${ip_address}"
done
```

```bash
#!/bin/bash
for file in $(ls .); do
echo "File: ${file}"
done
```

Nested for loop.

```bash
for name in $(cat valid.txt); for name2 in $(cat valid.txt); do echo "sudo swaks --to $name@postfish.off --from $name2@postfish.off --server postfish.off --attach @evil.odt --body 'smokum' --header 'Subject: king'" >> all-swaks.txt; done

for line in $(cat all-swaks.txt); do echo $line|bash; done
```

#### The break and continue statements

```bash
#!/bin/bash
while true; do
echo "in the loop"
break
done
echo "This code block will be reached"
```

```bash
#!/bin/bash
for file in example_file*; do
if [[ "${file}" == "example_file1" ]]; then
echo "Skipping the first file."
continue
fi
echo "${RANDOM}" > "${file}"
done
```

#### Case Statements

```bash
case EXPRESSION in
PATTERN1)
# do something if the first condition is met
;;
PATTERN2)
# do something if the second condition is met
;;
esac
```

```bash
IP_ADDRESS="${1}"
case ${IP_ADDRESS} in
192.168.*)
echo "Network is 192.168.x.x"
;;
10.0.*)
echo "Network is 10.0.x.x"
;;
*)
echo "Could not identify the network."
;;
esac
```

#### Job Control

```bash
jobs
fg %1
bg %1
```

Keep the file running after logout, or closing terminal.

```bash
nohup ./my_script.sh &
```

#### Capturing Terminal Session Activity

```bash
#!/bin/bash
FILENAME="$(date +%m-%d-%y)_${RANDOM}.log"
if [[ ! -d ~/sessions ]]; then
mkdir ~/sessions
fi
# Starting a script session
script -f -a "~/sessions/${FILENAME}"
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```

```bash
```
