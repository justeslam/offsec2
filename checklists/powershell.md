### PowerShell for Pentesting


#### Services

```bash
$env:path

$ErrorActionPreference = 'SilentlyContinue'; Write-Host "Basic Process Information:"; try { Get-Process | Select-Object Id, ProcessName, Path, WS, PM, NPM, SI, VM | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve basic process info" }; Write-Host "Executable Paths and Command Lines:"; try { Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { try { Get-Process | Select-Object Id, ProcessName, Path, CommandLine | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve executable paths." } }; Write-Host "Service Associations:"; try { Get-WmiObject Win32_Service | Select-Object Name, ProcessId, StartMode, State, PathName | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve service associations" }; Write-Host "Network Connections:"; try { $tcpConnections = Get-NetTCPConnection | Where-Object { $_.Protocol -eq 'tcp' } | Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize; Write-Host "TCP Connections:"; Write-Host $tcpConnections } catch { Write-Host "Failed to retrieve TCP connections using Get-NetTCPConnection. Trying netstat..."; try { $netstatOutput = netstat -ano | Select-String -Pattern "TCP" | Out-String -Width 4096; Write-Host "Netstat TCP Connections:"; Write-Host $netstatOutput } catch { Write-Host "Failed to retrieve TCP connections using netstat. Trying Get-Process with netstat..."; try { $processes = Get-Process -IncludeUserName | Select-Object Id, UserName; $netstatInfo = netstat -anob | Select-String -Pattern "TCP" | ForEach-Object { $parts = $_ -split '\s+'; $pid = $parts[-1]; $process = $processes | Where-Object { $_.Id -eq $pid }; [PSCustomObject]@{ LocalAddress = $parts[1]; RemoteAddress = $parts[2]; PID = $pid; UserName = $process.UserName } } | Format-Table -AutoSize; Write-Host "Enhanced Netstat TCP Connections with Process Info:"; Write-Host $netstatInfo } catch { Write-Host "Failed to retrieve network connections using all methods." } } } Write-Host "Process Owners:"; try { Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, , @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve process owners" }; Write-Host "Process Start Times:"; try { Get-Process | Select-Object ProcessName, StartTime | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve process start times" }; Write-Host "Listening Processes:"; try { Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object OwningProcess, LocalAddress, LocalPort | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve listening processes" }; Write-Host "Loaded Modules and DLLs:"; try { Get-Process | ForEach-Object { Get-Process -Id $_.Id | Select-Object -ExpandProperty Modules } | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve loaded modules" }; Write-Host "Security Context and Privileges:"; try { Get-Process | ForEach-Object { $proc = $_; $secObj = Get-Acl $proc.Path; $owner = $secObj.Owner; $accessRules = $secObj.Access | Where-Object { $_.FileSystemRights -match 'FullControl' -or $_.FileSystemRights -match 'Modify' } | ForEach-Object { "$($_.IdentityReference) has $($_.FileSystemRights) on $($proc.Path)" }; if ($accessRules) { Write-Host "$($proc.Name) running as $owner with special permissions: $($accessRules -join ', ')" } else { Write-Host "$($proc.Name) running as $owner with no special permissions" } } } catch { try { Get-WmiObject Win32_LogicalFileSecuritySetting -Filter "Path='$($_.Path)'" | ForEach-Object { $acl = $_.GetSecurityDescriptor().Descriptor.DACL; foreach ($ace in $acl) { if ($ace.AccessMask -eq 2032127) { Write-Host "$($proc.Name) has $($ace.Trustee.Name) with FullControl" } } } } catch { Write-Host "Failed to retrieve security context using both methods" } }; Write-Host "Checking Group Permissions on Executables and DLLs:"; try { $userGroups = Get-ADPrincipalGroupMembership $env:USERNAME | Select -ExpandProperty Name; Get-Process | ForEach-Object { $proc = $_; $path = $proc.Path; if (Test-Path $path) { $acl = Get-Acl $path; $acl.Access | Where-Object { $userGroups -contains $_.IdentityReference -and ($_.FileSystemRights -match 'Modify' -or $_.FileSystemRights -match 'FullControl') } | ForEach-Object { Write-Host "$($proc.Name) at $($path): $($_.IdentityReference) can modify" } } else { Write-Host "$($proc.Name) at $($path): Path not found or inaccessible" } } } catch { Write-Host "Failed to check group permissions on executables and DLLs" };
```

Get-WmiObject Win32_Process | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "Owner" -Value ($_.GetOwner().User); $_ } | Select-Object ProcessId, Owner | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host

#### FINDING EXPLOITABLE SERVICES

Not in c:/windows.

```bash
Get-WmiObject -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where { $_.PathName -notlike "C:\Windows*" } | select Name,DisplayName,StartMode,PathName
```

List Processes with Process Owner.

```bash
Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

Get permissions of running process binaries.

```bash
$process = (Get-Process | Where-Object {$_.Path -NotMatch "system32"} ).Path
$process | Where-Object { $_ -NE $null } | Foreach-Object {
  Get-Acl $_ -ErrorAction SilentlyContinue
} |
Out-GridView
```

Batch version. ^^

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
  for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
    icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
  )
)
pause
```

```bash
accesschk.exe -uwcqv "Authenticated Users" * /accepteula
accesschk.exe -uwcqv %USERNAME% * /accepteula
accesschk.exe -uwcqv "BUILTIN\Users" * /accepteula 2>nul
accesschk.exe -uwcqv "Todos" * /accepteula ::Spanish version
```

Checking permissions of the folders of the processes binaries.

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v 
"system32"^|find ":"') do for /f eol^=^"^ delims^=^" %%y in ('echo %%x') do (
    icacls "%%~dpy\" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users 
todos %username%" && echo.
)
```


Check for RWX Permissions of current user.

```bash
if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Get-ChildItem -Path C:\ -Directory -Recurse | ForEach-Object {$path = $_.FullName; $acl = Get-Acl -Path $path; $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $hasRWX = $false; foreach ($access in $acl.Access) {if ($access.IdentityReference -eq $currentUser) {$rights = $access.FileSystemRights; $hasRead = $rights -band [System.Security.AccessControl.FileSystemRights]::Read -eq [System.Security.AccessControl.FileSystemRights]::Read; $hasWrite = $rights -band [System.Security.AccessControl.FileSystemRights]::Write -eq [System.Security.AccessControl.FileSystemRights]::Write; $hasExecute = $rights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile -eq [System.Security.AccessControl.FileSystemRights]::ExecuteFile; if ($hasRead -and $hasWrite -and $hasExecute) {$hasRWX = $true; break;}}}; if ($hasRWX) {Write-Output $path;}} } else { Write-Output 'User has admin/system privileges, skipping RWX permissions check.' }`
```

```bash
icacls "C:\Program Files\" /T /C 2>nul | findstr "Everyone"
```

```bash
Get-ChildItem 'C:\Program Files\','C:\Program Files (x86)\' -Recurse | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 
Get-ChildItem 'C:\Program Files\','C:\Program Files (x86)\' -Recurse | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}} 
```

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
$SpecificPath = "C:\fakepath"

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

Services registry modify permissions. You should check if you can modify any service registry. You can check your permissions over a service registry doing:

```bash
reg query hklm\System\CurrentControlSet\Services /s /v imagepath #Get the binary paths of the services

#Try to write every service with its current content (to check if you have write permissions)
for /f %a in ('reg query hklm\system\currentcontrolset\services') do del %temp%\reg.hiv 2>nul & reg save %a %temp%\reg.hiv 2>nul && reg restore %a %temp%\reg.hiv 2>nul && echo You can modify %a

get-acl HKLM:\System\CurrentControlSet\services\* | Format-List * | findstr /i "<Username> Users Path Everyone"
```

To change the Path of the binary executed:

```bash
reg add HKLM\SYSTEM\CurrentControlSet\services\<service_name> /v ImagePath /t REG_EXPAND_SZ /d C:\path\new\binary /f
```

#### Scheduled Tasks

```bash     
$header="HostName","TaskName","NextRunTime","Status","LogonMode","LastRunTime","LastResult","Author","TaskToRun","StartIn","Comment","ScheduledTaskState","IdleTime","PowerManagement","RunAsUser","DeleteTaskIfNotRescheduled","StopTaskIfRunsXHoursandXMins","Schedule","ScheduleType","StartTime","StartDate","EndDate","Days","Months","RepeatEvery","RepeatUntilTime","RepeatUntilDuration","RepeatStopIfStillRunning"

schtasks /query /fo csv /nh /v | ConvertFrom-Csv -Header $header | select -uniq TaskName,NextRunTime,Status,TaskToRun,RunAsUser | Where-Object {$_.RunAsUser -ne $env:UserName -and $_.TaskToRun -notlike "%windir%*" -and $_.TaskToRun -ne "COM handler" -and $_.TaskToRun -notlike "%systemroot%*" -and $_.TaskToRun -notlike "C:\Windows\*" -and $_.TaskName -notlike "\Microsoft\Windows\*"}
```

#### Search for files

```bash
Get-ChildItem -Path C:\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*.log,*.kdbx,*.git,*.rdp,*.config,*cups*,*print*,*secret*,*cred*,*.ini,*oscp*,*ms01*,*pass*,*ms02*,*dc01*,SYSTEM,SAM,SECURITY,ntds.dit,id_rsa,authorized_keys -File -Recurse -ErrorAction SilentlyContinue | Where-Object { -not ($_.FullName -like "C:\Windows\servicing\LCU\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework\*") -and -not ($_.FullName -like "C:\Windows\WinSxS\amd*") -and -not ($_.FullName -like "C:\Windows\WinSxS\x*")}
Get-ChildItem -Path C:\Users -Include *.xml,*.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log -File -Recurse -ErrorAction SilentlyContinue
```

#### List folders in C:\Program Files, C:\ProgramData and C:\Program Files (x86)

```bash
Get-ChildItem -Path "C:\Program Files", "C:\Program Files (x86)", "C:\ProgramData" -Directory
```

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

```bash
Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```

#### Get permissions of running process binaries

```bash
$process = (Get-Process | Where-Object {$_.Path -NotMatch "system32"} ).Path
$process | Where-Object { $_ -NE $null } | Foreach-Object {
  Get-Acl $_ -ErrorAction SilentlyContinue
} |
Out-GridView
```

Batch.

```bash
for /f "tokens=2 delims='='" %%x in ('wmic process list full^|find /i "executablepath"^|find /i /v "system32"^|find ":"') do (
  for /f eol^=^"^ delims^=^" %%z in ('echo %%x') do (
    icacls "%%z" 2>nul | findstr /i "(F) (M) (W) :\\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo.
  )
)
pause
```

#### Check for RWX Permissions

```bash
if (-not (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Get-ChildItem -Path C:\ -Directory -Recurse | ForEach-Object {$path = $_.FullName; $acl = Get-Acl -Path $path; $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name; $hasRWX = $false; foreach ($access in $acl.Access) {if ($access.IdentityReference -eq $currentUser) {$rights = $access.FileSystemRights; $hasRead = $rights -band [System.Security.AccessControl.FileSystemRights]::Read -eq [System.Security.AccessControl.FileSystemRights]::Read; $hasWrite = $rights -band [System.Security.AccessControl.FileSystemRights]::Write -eq [System.Security.AccessControl.FileSystemRights]::Write; $hasExecute = $rights -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile -eq [System.Security.AccessControl.FileSystemRights]::ExecuteFile; if ($hasRead -and $hasWrite -and $hasExecute) {$hasRWX = $true; break;}}}; if ($hasRWX) {Write-Output $path;}} } else { Write-Output 'User has admin/system privileges, skipping RWX permissions check.' }`
```

```bash
icacls "C:\Program Files\" /T /C 2>nul | findstr "Everyone"
```

```bash
Get-ChildItem 'C:\Program Files\','C:\Program Files (x86)\' -Recurse | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}} 

Get-ChildItem 'C:\Program Files\','C:\Program Files (x86)\' -Recurse | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}} 
```

```bash
accesschk.exe -qwsu "Everyone" *
accesschk.exe -qwsu "Authenticated Users" *
accesschk.exe -qwsu "Users" *
```

#### CList Installed Softwares.

```
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
```

#### CList only the running services. (Filter Out )

```
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-Process | Where-Object {$_.Status -eq "Running"}
```

Installed & Running Software, Process Information, Service Information,

```bash
Start-Transcript -Path "C:\Windows\Tasks\custom.txt" -Append; try { $installedSoftwares = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate -Unique; $runningServices = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, Status -Unique; $processInfo = Get-Process | Select-Object Id, @{Name="CPU(s)";Expression={$_.CPU.ToString("N")+"%"}}, ProcessName -Unique; $combinedResults = @($installedSoftwares, $runningServices, $processInfo); $combinedResults | ForEach-Object { $_ | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } } catch { Write-Host "An error occurred: $_" } finally { Stop-Transcript }
```

#### User info

```
Get-ADUser -Identity YourUsername -Properties *
```
