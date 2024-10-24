### PowerShell for Pentesting

# TODO:
# Be more granular. RX -> possibly vulnerable to DLL injection. W access to www -> web service vulnerable to reverse shell. ... [@CheckPermissionsForUser]
# Check www write access
# Exclude known irrelavent directories

# The Chief Architect said that I needed to meticulously break down whether we should implement the following functionality for our internal audit. Among the responsibilities is to come up with all of the additional information that these commands would bring to our code. The Chief Architect only likes redundancy when there are clear advantages.

#### Services

```bash
# Function to check permissions specified user and their groups
# TODO: Be more granular. RX -> possibly vulnerable to DLL injection. W access to www -> web service vulnerable to reverse shell. ... 
function CheckPermissionsForIdentities {
    param(
        [string]$Path,
        [string[]]$Identities
    )
    if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Get-ChildItem -Path C:\ -Directory -Recurse | ForEach-Object {
            $currentPath = $_.FullName
            $acl = Get-Acl -Path $currentPath
            $hasRWX = $false
            foreach ($access in $acl.Access) {
                foreach ($identity in $Identities) {
                    if ($access.IdentityReference -eq $identity) {
                        $rights = $access.FileSystemRights
                        $hasRead = $rights -band [System.Security.AccessControl.FileSystemRights]::Read -eq [System.Security.AccessControl.FileSystemRights]::Read
                        $hasWrite = $rights -band [System.Security.AccessControl.FileSystemRights]::Write -eq [System.Security.AccessControl.FileSystemRights]::Write
                        $hasExecute = $rights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile -eq [System.Security.AccessControl.FileSystemRights]::ExecuteFile
                        if ($hasRead -and $hasWrite -and $hasExecute) {
                            $hasRWX = $true
                            break
                        }
                    }
                }
                if ($hasRWX) {
                    Write-Output $currentPath
                    break  # Stop checking further if RWX already found for this directory
                }
            }
        }
    } else {
        Write-Output "User has admin/system privileges, skipping RWX permissions check."
    }
}

function CheckGroupAccessInProgramFiles {
    param([string]$GroupName)
    Write-Host "Checking access for group: $GroupName in Program Files directories"
    $directories = @('C:\Program Files\', 'C:\Program Files (x86)\')
    foreach ($dir in $directories) {
        if (Test-Path $dir) {
            Get-ChildItem $dir -Recurse | ForEach-Object {
                try {
                    $acl = Get-Acl $_.FullName -ErrorAction SilentlyContinue
                    $acl.Access | Where-Object {
                        $_.IdentityReference -match $GroupName
                    } | ForEach-Object {
                        Write-Host "$GroupName has $($_.FileSystemRights) rights on $($_.Path)"
                    }
                } catch {
                    Write-Host "Failed to process ACL for $($_.FullName)"
                }
            }
        } else {
            Write-Host "Directory $dir not found"
        }
    }
}

function CheckRegistryPermissions {
    param(
        [string]$RegistryPath,
        [string[]]$Identities
    )
    Write-Host "Checking registry modify permissions at $RegistryPath for specified users and their groups..."

    # Get the ACL for each service under the specified registry path
    Get-ChildItem $RegistryPath | ForEach-Object {
        $serviceName = $_.PSChildName
        $servicePath = $_.PSPath
        try {
            $acl = Get-Acl $servicePath
            foreach ($identity in $Identities) {
                # Check if the identity has modify permissions
                $permissions = $acl.Access | Where-Object {
                    $_.IdentityReference -like "*$identity*" -and ($_.FileSystemRights -match 'Write' -or $_.FileSystemRights -match 'Modify')
                }
                foreach ($permission in $permissions) {
                    if ($permission) {
                        Write-Host "$identity has $($permission.FileSystemRights) rights on service $serviceName"
                    }
                }
            }
        } catch {
            Write-Host "Failed to access or process ACL for service $serviceName"
        }
    }
}

# Defining parameters for the script
param(
    [Alias("u", "users")]
    [string]$UserFile,  # File containing user names
    
    [Alias("d", "domain")]
    [string]$Domain     # Domain name
)

# Validate the existence of the user file
if (-not (Test-Path $UserFile)) {
    Write-Host "User file path is invalid or does not exist."
    exit
}

# Ensure the domain parameter is provided
if (-not $Domain) {
    Write-Error "You must specify a domain."
    exit
}

# Read user names from the user file
$users = Get-Content -Path $UserFile

# Initialize a list to store unique user groups
$userGroups = @()
$userDetails = @{}  # Dictionary to store additional user details


# Loop through each user to fetch their group memberships and additional details
foreach ($user in $users) {
    # Ensure each user identifier includes the domain
    if ($user -notmatch '\\') {
        $user = "$Domain\$user"
    }

    # Attempt to get domain and local group memberships
    try {
        $adGroups = Get-ADPrincipalGroupMembership -Identity $user | Select-Object -ExpandProperty Name
        $userGroups += $adGroups
    } catch {
        Write-Host "Failed to retrieve AD groups for $user"
    }

    try {
        $localGroups = Get-LocalGroupMember -Member $user | Where-Object { $_.ObjectClass -eq 'Group' } | Select-Object -ExpandProperty Name
        $userGroups += $localGroups
    } catch {
        Write-Host "Failed to retrieve local groups for $user"
    }

    # Store user details in a dictionary
    $userDetails[$user] = @{
        DomainGroups = $adGroups
        LocalGroups  = $localGroups
    }

    # Determine a user-specific path to check permissions; adjust as necessary
    $userPath = 'C:\'  # Example path, replace or modify according to actual needs
    Write-Host "Checking permissions for $user on $userPath"
    CheckPermissionsForUser -userPath $userPath -userName $user
}

# Remove duplicates from the user groups list
$userGroups = $userGroups | Select-Object -Unique

# Users & identities combined
$identities = $users + $userGroups

# Output the combined list of user groups
Write-Host "Retrieved Groups:"
$userGroups

# Checking group permissions on executables and DLLs
# TODO: If nobody in users can modify, output who CAN modify (excluding those in Administrators)
Write-Host "Checking Group Permissions on Executables and DLLs:"
try {
    Get-Process | Where-Object {$_.Path -NotMatch "system32"} | ForEach-Object {
        $proc = $_
        $path = $proc.Path
        if (Test-Path $path) {
            $acl = Get-Acl $path
            $acl.Access | Where-Object {
                $userGroups -contains $_.IdentityReference -and
                ($_.FileSystemRights -match 'Modify' -or $_.FileSystemRights -match 'FullControl')
            } | ForEach-Object {
                Write-Host "$($proc.Name) at $($path): $($_.IdentityReference) can modify"
            }
        } else {
            Write-Host "$($proc.Name) at $($path): Path not found or inaccessible"
        }
    }
} catch {
    Write-Host "Failed to check group permissions on executables and DLLs"
}

# Assume $userGroups contains all groups retrieved in earlier part of the script
foreach ($group in $userGroups) {
    CheckGroupAccessInProgramFiles -GroupName $group
}

# Assuming $users is an array of user identifiers from your script
$registryPath = "HKLM:\System\CurrentControlSet\Services"
CheckServiceRegistryPermissions -RegistryPath $registryPath -UserNames $user

# Security Context and Privileges Check
Write-Host "Security Context and Privileges:"
try {
    Get-Process | ForEach-Object {
        $proc = $_
        if (Test-Path $proc.Path) {
            $secObj = Get-Acl $proc.Path
            $owner = $secObj.Owner
            $accessRules = $secObj.Access | Where-Object {
                $_.FileSystemRights -match 'FullControl' -or $_.FileSystemRights -match 'Modify'
            } | ForEach-Object {
                "$($_.IdentityReference) has $($_.FileSystemRights) on $($proc.Path)"
            }
            if ($accessRules) {
                Write-Host "$($proc.Name) running as $owner with special permissions: $($accessRules -join ', ')"
            } else {
                Write-Host "$($proc.Name) running as $owner with no special permissions"
            }
        } else {
            Write-Host "$($proc.Name) path not accessible or does not exist"
        }
    }
} catch {
    Write-Host "Failed to retrieve security context"
}

# Executing CheckPermissionsForIdentities
$directoryPath = 'C:\'
CheckPermissionsForIdentities -Path $directoryPath -Identities $identities

# Output process owner information
Write-Host "Process Owners:"
try {
    Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} |
    Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} |
    ft -AutoSize | Out-String -Width 4096 | Write-Host
} catch {
    Write-Host "Failed to retrieve process owners"
}

# Define headers for scheduled tasks CSV parsing
$header = "HostName", "TaskName", "NextRunTime", "Status", "LogonMode", "LastRunTime", "LastResult",
          "Author", "TaskToRun", "StartIn", "Comment", "ScheduledTaskState", "IdleTime", "PowerManagement",
          "RunAsUser", "DeleteTaskIfNotRescheduled", "StopTaskIfRunsXHoursandXMins", "Schedule",
          "ScheduleType", "StartTime", "StartDate", "EndDate", "Days", "Months", "RepeatEvery",
          "RepeatUntilTime", "RepeatUntilDuration", "RepeatStopIfStillRunning"
                                                                                                                                                                                                                                            
# Query scheduled tasks, convert from CSV, select unique tasks based on specific fields, and filter based on conditions                                                                                                                     
Write-Output "Querying and filtering scheduled tasks..."                                                         
$scheduledTasks = schtasks /query /fo csv /nh /v |
ConvertFrom-Csv -Header $header |
Select-Object -Unique TaskName, NextRunTime, Status, TaskToRun, RunAsUser |
Where-Object {
    $_.RunAsUser -ne $env:UserName -and
    $_.TaskToRun -notlike "%windir%*" -and
    $_.TaskToRun -ne "COM handler" -and
    $_.TaskToRun -notlike "%systemroot%*" -and
    $_.TaskToRun -notlike "C:\Windows\*" -and
    $_.TaskName -notlike "\Microsoft\Windows\*"
}
                                                                                                                                                                                                                                            
# Output the filtered scheduled tasks
Write-Output "Filtered Scheduled Tasks:"
$scheduledTasks | Format-Table -AutoSize

###############################

# Setting the error action preference to silently continue on encountering errors
$ErrorActionPreference = 'SilentlyContinue'

# Output basic process information
Write-Host "Basic Process Information:"
try {
    # Retrieves and displays selected properties of all processes
    Get-Process | Select-Object Id, ProcessName, Path, WS, PM, NPM, SI, VM |
    Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
} catch {
    Write-Host "Failed to retrieve basic process info"
}

# Output paths and command lines of executables
Write-Host "Executable Paths and Command Lines:"
try {
    # Retrieves and displays command line and executable path for each process
    Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath |
    Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
} catch {
    try {
        # Fallback to retrieve only basic process information if previous command fails
        Get-Process | Select-Object Id, ProcessName, Path, CommandLine |
        Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
    } catch {
        Write-Host "Failed to retrieve executable paths."
    }
}

# Output service association information 
Write-Host "Service Associations:"
try {
    # Retrieves and displays information about services and their associated processes
    Get-WmiObject -class Win32_Service -Property Name, DisplayName, ProcessId, StartMode, State, PathName |
    Where { $_.PathName -notlike "C:\Windows*" } | select Name, DisplayName, ProcessId, StartMode, State, PathName |
    Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
} catch {
    Write-Host "Failed to retrieve service associations"
}

# Output network connections
Write-Host "Network Connections:"
try {
    # Retrieves and displays TCP connections
    $tcpConnections = Get-NetTCPConnection | Where-Object { $_.Protocol -eq 'tcp' } |
    Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State |
    Format-Table -AutoSize
    Write-Host "TCP Connections:"
    Write-Host $tcpConnections
} catch {
    Write-Host "Failed to retrieve TCP connections using Get-NetTCPConnection. Trying netstat..."
    try {
        # Uses netstat as a fallback to display TCP connections if PowerShell cmdlet fails
        $netstatOutput = netstat -ano | Select-String -Pattern "TCP" | Out-String -Width 4096
        Write-Host "Netstat TCP Connections:"
        Write-Host $netstatOutput
    } catch {
        Write-Host "Failed to retrieve TCP connections using netstat. Trying Get-Process with netstat..."
        try {
            # Further fallback using netstat with process info
            $processes = Get-Process -IncludeUserName | Select-Object Id, UserName
            $netstatInfo = netstat -anob | Select-String -Pattern "TCP" |
            ForEach-Object {
                $parts = $_ -split '\s+'
                $pid = $parts[-1]
                $process = $processes | Where-Object { $_.Id -eq $pid }
                [PSCustomObject]@{
                    LocalAddress = $parts[1]
                    RemoteAddress = $parts[2]
                    PID = $pid
                    UserName = $process.UserName
                }
            } | Format-Table -AutoSize
            Write-Host "Enhanced Netstat TCP Connections with Process Info:"
            Write-Host $netstatInfo
        } catch {
            Write-Host "Failed to retrieve network connections using all methods."
        }
    }
}

# Output process start times
Write-Host "Process Start Times:"
try {
    # Retrieves and displays the start time for each process
    Get-Process | Select-Object ProcessName, StartTime |
    Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
} catch {
    Write-Host "Failed to retrieve process start times"
}

# Output listening processes
Write-Host "Listening Processes:"
try {
    # Retrieves and displays processes that are listening on any port
    Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} |
    Select-Object OwningProcess, LocalAddress, LocalPort |
    Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
} catch {
    Write-Host "Failed to retrieve listening processes"
}

# Output loaded modules and DLLs
Write-Host "Loaded Modules and DLLs:"
try {
    # Retrieves and displays loaded modules for each process
    Get-Process | ForEach-Object {
        Get-Process -Id $_.Id | Select-Object -ExpandProperty Modules |
        Format-Table -AutoSize | Out-String -Width 4096 | Write-Host
    }
} catch {
    Write-Host "Failed to retrieve loaded modules"
}

```

Checking for permissions of all folders inside PATH (how to modify for any path).
    - for group in $(whoami /groups); put group in command

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

```bash
$SpecificPath = "C:\"

$output = icacls $SpecificPath 2>$null | Select-String -Pattern "(F) (M) (W) :\" | Select-String -Pattern ":\\ everyone authenticated users todos $env:username"
if ($output) { Write-Output "`n" }
```

Get every binary that is executed by a service using wmic (not in system32) and check your permissions using icacls.

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

You can also use sc and icacls.

```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

#### FINDING EXPLOITABLE SERVICES

<!-- Not in c:/windows.

```bash
Get-WmiObject -class Win32_Service -Property  Name,DisplayName,ProcessId,StartMode,State,PathName | Where { $_.PathName -notlike "C:\Windows*" } | select Name,DisplayName,ProcessId,StartMode,State,PathName
``` -->

<!-- List Processes with Process Owner.

```bash
Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
``` -->


<!-- Get permissions of running process binaries.

```bash
$process = ( Get-Process | Where-Object {$_.Path -NotMatch "system32"} ).Path
$process | Where-Object { $_ -NE $null } | Foreach-Object {
  Get-Acl $_ -ErrorAction SilentlyContinue
} |
Out-GridView
```
 -->

<!-- Batch version. ^^

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
  for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
    icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
  )
)
pause
``` -->

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

Checking permissions of the folders of the processes binaries.

<!-- ```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v 
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
    icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users 
todos %username%" && echo.
)
``` -->


<!-- Check for RWX Permissions of current user.

```bash
if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Get-ChildItem -Path C:\ -Directory -Recurse | ForEach-Object {$path = $_.FullName; $acl = Get-Acl -Path $path; $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $hasRWX = $false; foreach ($access in $acl.Access) {if ($access.IdentityReference -eq $currentUser) {$rights = $access.FileSystemRights; $hasRead = $rights -band [System.Security.AccessControl.FileSystemRights]::Read -eq [System.Security.AccessControl.FileSystemRights]::Read; $hasWrite = $rights -band [System.Security.AccessControl.FileSystemRights]::Write -eq [System.Security.AccessControl.FileSystemRights]::Write; $hasExecute = $rights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile -eq [System.Security.AccessControl.FileSystemRights]::ExecuteFile; if ($hasRead -and $hasWrite -and $hasExecute) {$hasRWX = $true; break;}}}; if ($hasRWX) {Write-Output $path;}} } else { Write-Output 'User has admin/system privileges, skipping RWX permissions check.' }
``` -->

```bash
icacls "C:\Program Files\" /T /C 2>nul | findstr "Everyone"
```

<!-- ```bash
Get-ChildItem 'C:\Program Files\','C:\Program Files (x86)\' -Recurse | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match '$GROUPNANE'} } catch {}} 
Get-ChildItem 'C:\Program Files\','C:\Program Files (x86)\' -Recurse | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}} 
``` -->

Weak file permissions.

```bash
accesschk.exe -qwsu "Everyone" *
accesschk.exe -qwsu "Authenticated Users" *
accesschk.exe -qwsu "Users" *
```

Checking for permissions of all folders inside PATH (how to modify for any path).
    - for group in $(whoami /groups); put group in command

```bash
for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )
```

```bash
$SpecificPath = "C:\"

$output = icacls $SpecificPath 2>$null | Select-String -Pattern "(F) (M) (W) :\" | Select-String -Pattern ":\\ everyone authenticated users todos $env:username"
if ($output) { Write-Output "`n" }
```

Get every binary that is executed by a service using wmic (not in system32) and check your permissions using icacls.

```bash
for /f "tokens=2 delims='='" %a in ('wmic service list full^|find /i "pathname"^|find /i /v "system32"') do @echo %a >> %temp%\perm.txt

for /f eol^=^"^ delims^=^" %a in (%temp%\perm.txt) do cmd.exe /c icacls "%a" 2>nul | findstr "(M) (F) :\"
```

You can also use sc and icacls.

```bash
sc query state= all | findstr "SERVICE_NAME:" >> C:\Temp\Servicenames.txt
FOR /F "tokens=2 delims= " %i in (C:\Temp\Servicenames.txt) DO @echo %i >> C:\Temp\services.txt
FOR /F %i in (C:\Temp\services.txt) DO @sc qc %i | findstr "BINARY_PATH_NAME" >> C:\Temp\path.txt
```

Services registry modify permissions. You should check if each user can modify any service registry. You can check your permissions over a service registry doing:

<!-- ```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
``` -->

To change the Path of the binary executed:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

#### Scheduled Tasks

<!-- ```bash     
$header="HostName","TaskName","NextRunTime","Status","LogonMode","LastRunTime","LastResult","Author","TaskToRun","StartIn","Comment","ScheduledTaskState","IdleTime","PowerManagement","RunAsUser","DeleteTaskIfNotRescheduled","StopTaskIfRunsXHoursandXMins","Schedule","ScheduleType","StartTime","StartDate","EndDate","Days","Months","RepeatEvery","RepeatUntilTime","RepeatUntilDuration","RepeatStopIfStillRunning"

schtasks /query /fo csv /nh /v | ConvertFrom-Csv -Header $header | select -uniq TaskName,NextRunTime,Status,TaskToRun,RunAsUser | Where-Object {$_.RunAsUser -ne $env:UserName -and $_.TaskToRun -notlike "%windir%*" -and $_.TaskToRun -ne "COM handler" -and $_.TaskToRun -notlike "%systemroot%*" -and $_.TaskToRun -notlike "C:\Windows\*" -and $_.TaskName -notlike "\Microsoft\Windows\*"}
```
 -->
#### Search for files

```bash
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*.kdbx,*.git,*.rdp,*.config,*cups*,*print*,*secret*,*cred*,*.ini,*oscp*,*ms01*,*pass*,*ms02*,*dc01*,SYSTEM,SAM,SECURITY,ntds.dit,id_rsa,authorized_keys -File -Recurse -ErrorAction SilentlyContinue | Where-Object { -not ($_.FullName -like "C:\Windows\servicing\LCU\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework\*") -and -not ($_.FullName -like "C:\Windows\WinSxS\amd*") -and -not ($_.FullName -like "C:\Windows\WinSxS\x*")}
Get-ChildItem -Path C:\Users -Include *.xml,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log -File -Recurse -ErrorAction SilentlyContinue
```

#### List folders in C:\Program Files, C:\ProgramData and C:\Program Files (x86)

<!-- ```bash
Get-ChildItem -Path "C:\Program Files", "C:\Program Files (x86)", "C:\ProgramData" -Directory
``` -->

#### Get User Information

List users' home folders.

```bash
Get-ChildItem 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { $_.GetValue('ProfileImagePath') }
```

Groups.

```bash
$tableLayout = @{Expression={((New-Object System.Security.Principal.SecurityIdentifier($_.Value)).Translate([System.Security.Principal.NTAccount])).Value};Label=”Group Name”},
@{Expression={$_.Value};Label=”Group SID”},
@{Expression={$_.Type};Label=”Group Type”}

([Security.Principal.WindowsIdentity]::GetCurrent()).Claims | Format-Table $tableLayout -AutoSize
```

All local accounts.

```bash
Get-CimInstance -ComputerName $env:computername -Class Win32_UserAccount -Filter "LocalAccount=True" | Select PSComputername, Name, Status, Disabled, AccountType, Lockout, PasswordRequired, PasswordChangeable | Out-GridView
#Get Current or last logged in username
$CurrentUser = Get-CimInstance -ComputerName $Computer -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
```


#### Check www write access

Try the three typical wwwroot paths, c:\inetpub\wwwroot\ , c:\xampp\htdocs\ , c:\wamp\www ".

```bash
Check Write Permissions for C:\inetpub\wwwroot
Write-Host "`nChecking Write Permissions for C:\inetpub\wwwroot..."
if (Test-Path "C:\inetpub\wwwroot") {
    $hasWriteAccess = $false
    try {
        [IO.File]::WriteAllText("C:\inetpub\wwwroot\test.txt", "test")
        Remove-Item "C:\inetpub\wwwroot\test.txt"
        $hasWriteAccess = $true
    } catch {
        $hasWriteAccess = $false
    }
    
    if ($hasWriteAccess) {
        Write-Host "You have write access to C:\inetpub\wwwroot. Consider writing an ASPX shell to escalate privileges as IISSVC using SeImpersonate."
    } else {
        Write-Host "You don't have write access to C:\inetpub\wwwroot."
    }
}
else {
    Write-Host "C:\inetpub\wwwroot does not exist."
}
```

#### Check Powershell history

```bash
# Check for PowerShell History
$psHistoryPath = "C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$psHistoryFiles = Get-ChildItem -Path $psHistoryPath -File -ErrorAction SilentlyContinue
if ($psHistoryFiles) {
    Write-Host "Found PowerShell history. You might want to sift through these for juicy details:"
    $psHistoryFiles.FullName
} else {
    Write-Host "No PowerShell history found."
}
```

#### List Processes with Process Owner

<!-- ```bash
Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```
 -->

#### Get permissions of running process binaries

<!-- ```bash
$process = (Get-Process | Where-Object {$_.Path -NotMatch "system32"} ).Path
$process | Where-Object { $_ -NE $null } | Foreach-Object {
  Get-Acl $_ -ErrorAction SilentlyContinue
} |
Out-GridView
``` -->

Batch.

<!-- ```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
  for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
    icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
  )
)
pause
``` -->

#### Check for RWX Permissions

<!-- ```bash
if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Get-ChildItem -Path C:\ -Directory -Recurse | ForEach-Object {$path = $_.FullName; $acl = Get-Acl -Path $path; $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $hasRWX = $false; foreach ($access in $acl.Access) {if ($access.IdentityReference -eq $currentUser) {$rights = $access.FileSystemRights; $hasRead = $rights -band [System.Security.AccessControl.FileSystemRights]::Read -eq [System.Security.AccessControl.FileSystemRights]::Read; $hasWrite = $rights -band [System.Security.AccessControl.FileSystemRights]::Write -eq [System.Security.AccessControl.FileSystemRights]::Write; $hasExecute = $rights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile -eq [System.Security.AccessControl.FileSystemRights]::ExecuteFile; if ($hasRead -and $hasWrite -and $hasExecute) {$hasRWX = $true; break;}}}; if ($hasRWX) {Write-Output $path;}} } else { Write-Output 'User has admin/system privileges, skipping RWX permissions check.' }`
``` -->

```bash
icacls "C:\Program Files\" /T /C 2>nul | findstr "Everyone"
```

<!-- ```bash
Get-ChildItem 'C:\Program Files\','C:\Program Files (x86)\' -Recurse | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 

Get-ChildItem 'C:\Program Files\','C:\Program Files (x86)\' -Recurse | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}} 
``` -->

```bash
accesschk.exe -qwsu "Everyone" *
accesschk.exe -qwsu "Authenticated Users" *
accesschk.exe -qwsu "Users" *
```

#### CList Installed Softwares.

<!-- ```
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
``` -->

#### CList only the running services. (Filter Out )

<!-- ```
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-Process | Where-Object {$_.Status -eq "Running"}
```
 -->
Installed & Running Software, Process Information, Service Information,

<!-- ```bash
Start-Transcript -Path "C:\Windows\Tasks\custom.txt" -Append; try { $installedSoftwares = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate -Unique; $runningServices = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, Status -Unique; $processInfo = Get-Process | Select-Object Id, @{Name="CPU(s)";Expression={$_.CPU.ToString("N")+"%"}}, ProcessName -Unique; $combinedResults = @($installedSoftwares, $runningServices, $processInfo); $combinedResults | ForEach-Object { $_ | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } } catch { Write-Host "An error occurred: $_" } finally { Stop-Transcript }
``` -->

#### User info

<!-- ```
Get-ADUser -Identity YourUsername -Properties *
```
 -->

### CONVERTED TO ONE LINE

```bash
$ErrorActionPreference = 'SilentlyContinue'; Write-Host "Basic Process Information:"; try { Get-Process | Select-Object Id, ProcessName, Path, WS, PM, NPM, SI, VM | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve basic process info" }; Write-Host "Executable Paths and Command Lines:"; try { Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { try { Get-Process | Select-Object Id, ProcessName, Path, CommandLine | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve executable paths." } }; Write-Host "Service Associations:"; try { Get-WmiObject Win32_Service | Select-Object Name, ProcessId, StartMode, State, PathName | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve service associations" }; Write-Host "Network Connections:"; try { $tcpConnections = Get-NetTCPConnection | Where-Object { $_.Protocol -eq 'tcp' } | Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize; Write-Host "TCP Connections:"; Write-Host $tcpConnections } catch { Write-Host "Failed to retrieve TCP connections using Get-NetTCPConnection. Trying netstat..."; try { $netstatOutput = netstat -ano | Select-String -Pattern "TCP" | Out-String -Width 4096; Write-Host "Netstat TCP Connections:"; Write-Host $netstatOutput } catch { Write-Host "Failed to retrieve TCP connections using netstat. Trying Get-Process with netstat..."; try { $processes = Get-Process -IncludeUserName | Select-Object Id, UserName; $netstatInfo = netstat -anob | Select-String -Pattern "TCP" | ForEach-Object { $parts = $_ -split '\s+'; $pid = $parts[-1]; $process = $processes | Where-Object { $_.Id -eq $pid }; [PSCustomObject]@{ LocalAddress = $parts[1]; RemoteAddress = $parts[2]; PID = $pid; UserName = $process.UserName } } | Format-Table -AutoSize; Write-Host "Enhanced Netstat TCP Connections with Process Info:"; Write-Host $netstatInfo } catch { Write-Host "Failed to retrieve network connections using all methods." } } } Write-Host "Process Owners:"; try { Get-WmiObject Win32_Process | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "Owner" -Value ($_.GetOwner().User); $_ } | Select-Object ProcessId, Owner | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve process owners" }; Write-Host "Process Start Times:"; try { Get-Process | Select-Object ProcessName, StartTime | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve process start times" }; Write-Host "Listening Processes:"; try { Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object OwningProcess, LocalAddress, LocalPort | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve listening processes" }; Write-Host "Loaded Modules and DLLs:"; try { Get-Process | ForEach-Object { Get-Process -Id $_.Id | Select-Object -ExpandProperty Modules } | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve loaded modules" }; Write-Host "Security Context and Privileges:"; try { Get-Process | ForEach-Object { $proc = $_; $secObj = Get-Acl $proc.Path; $owner = $secObj.Owner; $accessRules = $secObj.Access | Where-Object { $_.FileSystemRights -match 'FullControl' -or $_.FileSystemRights -match 'Modify' } | ForEach-Object { "$($_.IdentityReference) has $($_.FileSystemRights) on $($proc.Path)" }; if ($accessRules) { Write-Host "$($proc.Name) running as $owner with special permissions: $($accessRules -join ', ')" } else { Write-Host "$($proc.Name) running as $owner with no special permissions" } } } catch { try { Get-WmiObject Win32_LogicalFileSecuritySetting -Filter "Path='$($_.Path)'" | ForEach-Object { $acl = $_.GetSecurityDescriptor().Descriptor.DACL; foreach ($ace in $acl) { if ($ace.AccessMask -eq 2032127) { Write-Host "$($proc.Name) has $($ace.Trustee.Name) with FullControl" } } } } catch { Write-Host "Failed to retrieve security context using both methods" } }; Write-Host "Checking Group Permissions on Executables and DLLs:"; try { $userGroups = Get-ADPrincipalGroupMembership $env:USERNAME | Select -ExpandProperty Name; Get-Process | ForEach-Object { $proc = $_; $path = $proc.Path; if (Test-Path $path) { $acl = Get-Acl $path; $acl.Access | Where-Object { $userGroups -contains $_.IdentityReference -and ($_.FileSystemRights -match 'Modify' -or $_.FileSystemRights -match 'FullControl') } | ForEach-Object { Write-Host "$($proc.Name) at $($path): $($_.IdentityReference) can modify" } } else { Write-Host "$($proc.Name) at $($path): Path not found or inaccessible" } } } catch { Write-Host "Failed to check group permissions on executables and DLLs" };

```