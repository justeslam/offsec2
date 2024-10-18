#!/usr/bin/env bash

# Find Files Owned by Users in Directories Owned by Others
# Find files with permissions differing from it's owning directory
# Writable files, by user
# Readable, writable, and executable files that're owned by root or ( or root group ), per user/group
# Lists permission sets that occur less than 5 times for the user, indicating possible abnormalities.
# Directories owned by non-root users
# Time-Based

FILTEREXT="\.tif$|\.tiff$|\.gif$|\.jpeg$|\.jpg|\.jif$|\.jfif$|\.jp2$|\.jpx$|\.j2k$|\.j2c$|\.fpx$|\.pcd$|\.png$|\.pdf$|\.flv$|\.mp4$|\.mp3$|\.gifv$|\.avi$|\.mov$|\.mpeg$|\.wav$|\.doc$|\.docx$|\.xls$|\.xlsx$|\.svg$"
grep -Ev "$FILTEREXT"

# One way to go about it is having a pruned database of the fs to uncover anomalies

# Define users to analyze (users with valid login shells)
users=$(awk -F: '/\/(ba)?sh$/{print $1}' /etc/passwd)

# Define directories to exclude to improve performance and reduce irrelevant data
EXCLUDE_DIRS=(
    "/proc" "/sys" "/run" "/dev" "/tmp" "/var/lib"
    "/var/run" "/var/cache" "/var/tmp" "/usr/lib"
    "/usr/share" "/lib" "/lib64" "/snap"
)

# Convert EXCLUDE_DIRS into find command parameters
FIND_EXCLUDES=()
for DIR in "${EXCLUDE_DIRS[@]}"; do
    FIND_EXCLUDES+=(-path "$DIR" -prune -o)
done

---

# Find Files Owned by Users in Directories Owned by Others

obmowbe=$(find $ROOT_FOLDER '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null | grep -Ev "$FILTEREXT" | sort | uniq | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 10){ print line_init; } if (cont == "10"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }' | head -n 200)
find / '(' -type f ')' -group $(id -g) -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*\|.*.python.*\|\..*m2.*\|.*\/go\/.*\|.*\/\.config\/.*\|.*\/venv/.*' -prune 2>/dev/null | grep -Ev "$FILTEREXT" | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 10){ print line_init; } if (cont == "10"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }'
find / '(' -type f -or -type d ')' -group $(id -g) -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" ! -path "*/venv/*" -path "*/*pycache*/*" -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*\|.*.python.*\|\..*m2.*\|.*\/go\/.*\|.*\/\.config\/.*\|.*\/venv/.*' -prune 2>/dev/null | grep -Ev "$FILTEREXT" | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 10){ print line_init; } if (cont == "10"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }'
iwfbg=$(find $ROOT_FOLDER '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null | grep -Ev "$notExtensions" | awk -F/ '{line_init=$0; if (!cont){ cont=0 }; $NF=""; act=$0; if (act == pre){(cont += 1)} else {cont=0}; if (cont < 10){ print line_init; } if (cont == "10"){print "#)You_can_write_even_more_files_inside_last_directory\n"}; pre=act }' | head -n 200)
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

# Identify directories where the permissions of files owned by a user differ from the directory's permissions

#!/usr/bin/env bash

users=$(awk -F: '/sh$/{print $1}' /etc/passwd)

for user in $users; do
    output_file="/dev/shm/${user}_permission_anomalies.txt"
    : > "$output_file"  # Clear previous output

    find / -type f -user "$user" \
        \( ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" \) 2>/dev/null |
    while read -r file; do
        dir_perms=$(stat -c "%a" "$(dirname "$file")" 2>/dev/null)
        file_perms=$(stat -c "%a" "$file" 2>/dev/null)
        if [ "$dir_perms" ] && [ "$file_perms" ] && [ "$dir_perms" != "$file_perms" ]; then
            echo "$file (File perms: $file_perms, Directory perms: $dir_perms)" >> "$output_file"
        fi
    done
done


# Identify files modified in the last 7 days

# Files modified in the last 7 days
find / -type f -user "$user" -mtime -7 \
    \( ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/var/lib/*" \) 2>/dev/null | sort -n -r

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

# To use for creating user dbs
find / -path "/proc/*" -prune -o -path "/sys/*" -prune -o -path "/run/*" -prune -o -path "/var/lib/*" -prune -o -path "/private/var/*" -prune -o -iregex '.*site-packages.*\|^.*/\.cargo.*\|.*stable-x86_64.*\|.*.python.*\|\..*m2.*\|.*\/go\/.*\|.*\/\.config\/.*' -prune -o -user postgres -printf '%M %U %G %p\n' 2>/dev/null