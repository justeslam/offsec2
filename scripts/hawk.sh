#!/usr/bin/env bash

# Find Files Owned by Users in Directories Owned by Others
# Find files with permissions differing from it's owning directory
# Writable files, by user
# Readable, writable, and executable files that're owned by root or ( or root group ), per user/group
# Lists permission sets that occur less than 5 times for the user, indicating possible abnormalities.
# Directories owned by non-root users
# Time-Based

# Find Files Owned by Users (Or User's Group) in Directories Owned by Others

# Find files with permissions differing from it's owning directory [x]

# Writable files, by user (except root)

# Readable, writable, and executable files that're owned by root or ( or root group ), per user/group

# Directories owned by non-root users

# 1000 most recently modified files

---------------------------------------------------------------------------------------------------------------------------------------------

# Find Files Owned by Users (Or User's Group) in Directories Owned by Others

**The only problem with this is that it misses out on gid owner. I do not want to miss out on a file if the gid owner is a different user but the uid is the same as the directory owner.**

# Define users to analyze (users with valid login shells)
users=$(awk -F: '/sh$/{print $1}' /etc/passwd 2>/dev/null)

# Define directories to exclude to improve performance and reduce irrelevant data
EXCLUDE_DIRS=( "/proc/*" "/sys/*" "/run/*" "/var/lib" "/var/run" "/var/cache" "/lib" "/lib64" "/snap" )

# Convert EXCLUDE_DIRS into find command parameters
FIND_EXCLUDES=()
for DIR in "${EXCLUDE_DIRS[@]}"; do
    FIND_EXCLUDES+=(-path "$DIR" -prune -o)
done

for user in $users; do
    output_file="/dev/shm/${user}_files_in_foreign_dirs.txt"
    : > "$output_file"  # Clear previous output

    find / -type f -user "$user" \
        \( ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" \) 2>/dev/null |
    while read -r file; do
        dir_owner=$(stat -c "%U" "$(dirname "$file")" 2>/dev/null)
        if [ "$dir_owner" ] && [ "$dir_owner" != "$user" ]; then
            echo "$file (File owner: $user, Directory owner: $dir_owner)" >> "$output_file"
        fi
    done
done

---------------------------------------------------------------------------------------------------------------------------------------------

FILTER_EXT="\.tif$|\.tiff$|\.gif$|\.jpeg$|\.jpg|\.jif$|\.jfif$|\.jp2$|\.jpx$|\.j2k$|\.j2c$|\.fpx$|\.pcd$|\.png$|\.pdf$|\.flv$|\.mp4$|\.mp3$|\.gifv$|\.avi$|\.mov$|\.mpeg$|\.wav$|\.doc$|\.docx$|\.xls$|\.xlsx$|\.svg$"
EXCLUDE_DIRS=( "/proc/*" "/sys/*" "/run/*" "/var/lib" "/var/run" "/var/cache" "/lib" "/lib64" "/snap" )

obmowbe=$(find $ROOT_FOLDER '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null | grep -Ev "$FILTER_EXT" | sort | uniq | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 10){ print line_init; } if (cont == "10"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }' | head -n 200)
find / '(' -type f ')' -group $(id -g) -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*\|.*.python.*\|\..*m2.*\|.*\/go\/.*\|.*\/\.config\/.*\|.*\/venv/.*' -prune 2>/dev/null | grep -Ev "$FILTER_EXT" | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 10){ print line_init; } if (cont == "10"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }'
find / '(' -type f -or -type d ')' -group $(id -g) -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" ! -path "*/venv/*" -path "*/*pycache*/*" -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*\|.*.python.*\|\..*m2.*\|.*\/go\/.*\|.*\/\.config\/.*\|.*\/venv/.*' -prune 2>/dev/null | grep -Ev "$FILTER_EXT" | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 10){ print line_init; } if (cont == "10"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }'
iwfbg=$(find $ROOT_FOLDER '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null | grep -Ev "$notExtensions" | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 10){ print line_init; } if (cont == "10"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }' | head -n 200)

---------------------------------------------------------------------------------------------------------------------------------------------

# Identify directories where the permissions of files owned by a user differ from the directory's permissions

#!/usr/bin/env bash

output_file="/dev/shm/permission_anomalies.txt"

files=$(find / -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/var/cache/*" -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*\|.*cache.*' -prune -o -iregex 2>/dev/null)
for f in $files; do
    dir_perms=$(stat -c "%a" "$(dirname "$f")" 2>/dev/null)
    file_perms=$(stat -c "%a" "$f" 2>/dev/null)
    if [ "$dir_perms" ] && [ "$file_perms" ] && [ "$dir_perms" != "$file_perms" ]; then
        echo "$f (File perms: $file_perms, Directory perms: $dir_perms)" >> $output_file
    fi
done

---------------------------------------------------------------------------------------------------------------------------------------------

# Identify files modified in the last 7 days

# Files modified in the last 7 days
find / -type f -user "$user" -mtime -7 \
    \( ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" \) 2>/dev/null | sort -n -r

---------------------------------------------------------------------------------------------------------------------------------------------

# Readable, writable, executable files belonging to root and readable by me but not world readable

find / -type f -user root ! -perm -o=r ! -path "/proc/*" 2>/dev/null | grep -v "\.journal" | while read f; do if [ -r "$f" ]; then ls -l "$f" 2>/dev/null
find / -type f -user root ! -perm -o=w ! -path "/proc/*" 2>/dev/null | grep -v "\.journal" | while read f; do if [ -r "$f" ]; then ls -l "$f" 2>/dev/null
find / -type f -user root ! -perm -o=x ! -path "/proc/*" 2>/dev/null | grep -v "\.journal" | while read f; do if [ -r "$f" ]; then ls -l "$f" 2>/dev/null

---------------------------------------------------------------------------------------------------------------------------------------------

# One way to go about it is having a pruned database of the fs to uncover anomalies
# Lists permission sets that occur less than 5 times for the user, indicating possible abnormalities.

# To use for creating user dbs
find / -path "/proc/*" -prune -o -path "/sys/*" -prune -o -path "/run/*" -prune -o -path "/var/lib/*" -prune -o -path "/private/var/*" -prune -o -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*\|.*.python.*\|\..*m2.*\|.*\/go\/.*\|.*\/\.config\/.*' -prune -o -user postgres -printf '%M %U %G %p\n' 2>/dev/null

---------------------------------------------------------------------------------------------------------------------------------------------


# Thanks for help with the code. To give you more context, I'm trying to make something that will allow me to visualize what makes users unique within the scope of permissions on the file system by using 'diff' or something better to highlight abnormalities. One potential problem is that there are so many files, for instance, this is the updated output, `ll /dev/shm
total 20M
   0 drwxrwxrwt  2 root     root      260 Oct 17 12:19 .
4.5M -rw-rw-r--  1 kali     kali     4.5M Oct 17 12:19 kali.executable
4.2M -rw-rw-r--  1 kali     kali     4.2M Oct 17 12:19 kali.writable
4.5M -rw-rw-r--  1 kali     kali     4.5M Oct 17 12:19 kali.readable
4.0K -rw-rw-r--  1 kali     kali      164 Oct 17 12:19 postgres.executable
   0 -rw-rw-r--  1 kali     kali        0 Oct 17 12:18 postgres.writable
4.0K -rw-rw-r--  1 kali     kali      164 Oct 17 12:18 postgres.readable
2.9M -rw-rw-r--  1 kali     kali     2.9M Oct 17 12:18 root.executable
4.0K -rw-rw-r--  1 kali     kali     2.1K Oct 17 12:18 root.writable
2.9M -rw-rw-r--  1 kali     kali     2.9M Oct 17 12:18 root.readable`. This is overwhelming and would take a very long time to sort through, which is not the purpose of the code. One potential solution that I'm thinking about is, if there is a directory with more than x files, simply print the directory. The only thing wrong with this approach is that it can miss out on valuable stuff, but that's just my first impression. An idea that I like more is to recognize if a file belongs a user (or the users group - same as username) inside of a directory that is owned by somebody else. Help me think through what I can do that would best allow me to visualize what makes users unique within the scope of permissions on the file system.
# If there is a directory with more than x files, simply print the directory. The only thing wrong with this approach is that it can miss out on valuable stuff. In order to cut down

# Recognize if the user has ptype on a file inside a directory that is owned by somebody else. 

---------------------------------------------------------------------------------------------------------------------------------------------

roops=$(groups | tr ' ' '\n')
users=$(awk -F: '/sh$/{print $1}' /etc/passwd 2>/dev/null)

for f in $ (ls /dev/shm/); do awk 'NF{$1=$1};1' $f && sed -i "/readable\|writable\|executable/d" > ${f}.tmp && mv ${f}.tmp ${f}

for user in users; do
# Valuable insights come when you pivot users & differentiate
for ptype in $(echo "readable" "writable" "executable"); do find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -"${ptype}" 2>/dev/null > /dev/shm/$(whoami)."${ptype}" ; wait ; sort /dev/shm/$(whoami)."${ptype}" | awk 'NF{$1=$1};1' | sed -i "/readable\|writable\|executable/d" > /dev/shm/$(whoami)."${ptype}".tmp && mv /dev/shm/$(whoami)."${ptype}".tmp /dev/shm/$(whoami)."${ptype}" ; done

# Readable files and directories
ll -f $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -readable 2>/dev/null)
# or another interesting  user
for roop in $roops; do ll -f $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -readable -group $roop 2>/dev/null) ; wait ; done

# Writable files and directories
ll -f $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -writable 2>/dev/null)
for roop in $roops; do ll -f $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -writable -group $roop 2>/dev/null) ; wait ; done

# Executable files and directories
ll -d $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -executable 2>/dev/null)
for roop in $roops; do ll -d $(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" ! -path "/private/var/*" -executable -group $roop 2>/dev/null) ; wait ; done
