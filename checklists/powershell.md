### PowerShell for Pentesting


#### Services

```bash
$env:path

$ErrorActionPreference = 'SilentlyContinue'; Write-Host "Basic Process Information:"; try { Get-Process | Select-Object Id, ProcessName, Path, WS, PM, NPM, SI, VM | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve basic process info" }; Write-Host "Executable Paths and Command Lines:"; try { Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { try { Get-Process | Select-Object Id, ProcessName, Path, CommandLine | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve executable paths." } }; Write-Host "Service Associations:"; try { Get-WmiObject Win32_Service | Select-Object Name, ProcessId, StartMode, State, PathName | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve service associations" }; Write-Host "Network Connections:"; try { $tcpConnections = Get-NetTCPConnection | Where-Object { $_.Protocol -eq 'tcp' } | Select-Object OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize; Write-Host "TCP Connections:"; Write-Host $tcpConnections } catch { Write-Host "Failed to retrieve TCP connections using Get-NetTCPConnection. Trying netstat..."; try { $netstatOutput = netstat -ano | Select-String -Pattern "TCP" | Out-String -Width 4096; Write-Host "Netstat TCP Connections:"; Write-Host $netstatOutput } catch { Write-Host "Failed to retrieve TCP connections using netstat. Trying Get-Process with netstat..."; try { $processes = Get-Process -IncludeUserName | Select-Object Id, UserName; $netstatInfo = netstat -anob | Select-String -Pattern "TCP" | ForEach-Object { $parts = $_ -split '\s+'; $pid = $parts[-1]; $process = $processes | Where-Object { $_.Id -eq $pid }; [PSCustomObject]@{ LocalAddress = $parts[1]; RemoteAddress = $parts[2]; PID = $pid; UserName = $process.UserName } } | Format-Table -AutoSize; Write-Host "Enhanced Netstat TCP Connections with Process Info:"; Write-Host $netstatInfo } catch { Write-Host "Failed to retrieve network connections using all methods." } } } Write-Host "Process Owners:"; try { Get-WmiObject Win32_Process | ForEach-Object { $_ | Add-Member -MemberType NoteProperty -Name "Owner" -Value ($_.GetOwner().User); $_ } | Select-Object ProcessId, Owner | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve process owners" }; Write-Host "Process Start Times:"; try { Get-Process | Select-Object ProcessName, StartTime | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve process start times" }; Write-Host "Listening Processes:"; try { Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object OwningProcess, LocalAddress, LocalPort | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve listening processes" }; Write-Host "Loaded Modules and DLLs:"; try { Get-Process | ForEach-Object { Get-Process -Id $_.Id | Select-Object -ExpandProperty Modules } | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } catch { Write-Host "Failed to retrieve loaded modules" }; Write-Host "Security Context and Privileges:"; try { Get-Process | ForEach-Object { $proc = $_; $secObj = Get-Acl $proc.Path; $owner = $secObj.Owner; $accessRules = $secObj.Access | Where-Object { $_.FileSystemRights -match 'FullControl' -or $_.FileSystemRights -match 'Modify' } | ForEach-Object { "$($_.IdentityReference) has $($_.FileSystemRights) on $($proc.Path)" }; if ($accessRules) { Write-Host "$($proc.Name) running as $owner with special permissions: $($accessRules -join ', ')" } else { Write-Host "$($proc.Name) running as $owner with no special permissions" } } } catch { try { Get-WmiObject Win32_LogicalFileSecuritySetting -Filter "Path='$($_.Path)'" | ForEach-Object { $acl = $_.GetSecurityDescriptor().Descriptor.DACL; foreach ($ace in $acl) { if ($ace.AccessMask -eq 2032127) { Write-Host "$($proc.Name) has $($ace.Trustee.Name) with FullControl" } } } } catch { Write-Host "Failed to retrieve security context using both methods" } }; Write-Host "Checking Group Permissions on Executables and DLLs:"; try { $userGroups = Get-ADPrincipalGroupMembership $env:USERNAME | Select -ExpandProperty Name; Get-Process | ForEach-Object { $proc = $_; $path = $proc.Path; if (Test-Path $path) { $acl = Get-Acl $path; $acl.Access | Where-Object { $userGroups -contains $_.IdentityReference -and ($_.FileSystemRights -match 'Modify' -or $_.FileSystemRights -match 'FullControl') } | ForEach-Object { Write-Host "$($proc.Name) at $($path): $($_.IdentityReference) can modify" } } else { Write-Host "$($proc.Name) at $($path): Path not found or inaccessible" } } } catch { Write-Host "Failed to check group permissions on executables and DLLs" };

```

List Installed Softwares.

```
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
```

List only the running services. (Filter Out )

```
Get-Service | Where-Object {$_.Status -eq "Running"}
Get-Process | Where-Object {$_.Status -eq "Running"}
```
Installed & Running Software, Process Information, Service Information,  
```bash
Start-Transcript -Path "C:\Windows\Tasks\custom.txt" -Append; try { $installedSoftwares = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate -Unique; $runningServices = Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name, Status -Unique; $processInfo = Get-Process | Select-Object Id, @{Name="CPU(s)";Expression={$_.CPU.ToString("N")+"%"}}, ProcessName -Unique; $combinedResults = @($installedSoftwares, $runningServices, $processInfo); $combinedResults | ForEach-Object { $_ | Format-Table -AutoSize | Out-String -Width 4096 | Write-Host } } catch { Write-Host "An error occurred: $_" } finally { Stop-Transcript }
```

#### (4) . Get Process id's , names and their CPU usage !

```
Get-Process | Format-Table -Property Id, @{Label="CPU(s)";Expression={$_.CPU.ToString("N")+"%"};Alignment="Right"}, ProcessName -AutoSize
```
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate


#### (6) Powershell Transcript

A PowerShell transcript is a record of all commands and output in a PowerShell session. It allows you to log and save everything that happens in the session, which can be useful for troubleshooting, auditing, or documentation purposes.

To Enable Transcript

```
Start-Transcript -Path "C:\Transcripts\MyTranscript.txt"
```

Start in All Sessions

```
Start-Transcript -Path "C:\Transcripts\MyTranscript.txt" -Append
```

To Disable Transcipt

`Stop-Transcript`

#### (7) List all running processes sorted by CPU usage, with the highest usage at the top of the list

```
Get-Process | Sort-Object -Descending CPU
```

#### (8)  Get Process id's , names and their CPU usage !

```
Get-Process | Format-Table -Property Id, @{Label="CPU(s)";Expression={$_.CPU.ToString("N")+"%"};Alignment="Right"}, ProcessName -AutoSize
```
#### (9) List the Default and 3rd party running apps 

Link for PS Script : <a href="https://github.com/Whitecat18/Ps-script-for-Hackers-and-Pentesters/blob/main/scripts/list_process.ps1" > click Here </a>

#### 

```
Get-ChildItem -Path C:\ -Recurse -Include *.conf, *.ini, *.xml, *.cfg | Select-String -Pattern "password|secret|api_key"
```
This command searches for sensitive configuration files on a local or remote machine, and looks for common keywords such as "password", "secret", or "api_key" within those files.

#### 

```
Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'} | Select-Object -Property Name, DisplayName
```

This command retrieves a list of all services on a local or remote machine that are set to start automatically but are currently not running.

#### 

```
Clear-Host
$Processes = Get-Process | Sort-Object -Property CPU, WorkingSet64 -Descending

while ($true) {
    $Processes | Format-Table -AutoSize | Out-Host
    Start-Sleep 1
}
```
Fetches Windows Task Manager and Displays Process in Bytes . To change the speed increase the Sleep Time or Remove the While Loop . 

Example : 

```
Clear-Host
$Processes = Get-Process | Sort-Object -Property CPU, WorkingSet64 -Descending
$Processes | Format-Table -AutoSize | Out-Host
```

#### 

```
Get-ADUser -Identity YourUsername -Properties *
```

Retrieve information about an Active Directory user.

#### 

```
Get-WinEvent -LogName System -EntryType Error -After (Get-Date).AddDays
```


```
Get-Service | Where-Object { $_.Status -eq "Running" }
```

Use this to identify vulnerable running Processes . use it to prives it or manual exploit . 


```
Get-CimInstance -ClassName Win32_BIOS
```

Get PC'S BIOS Information


```
Get-CimInstance -ClassName Win32_Service | Select-Object -Property Status, Name, DisplayName
```

Display service status 


```
Get-CimInstance -ClassName Win32_Processor | Select-Object -ExcludeProperty "CIM*"
```

Get CPU Information


```
Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, DriveType, @{Name="SizeRemaining";Expression={[math]::Round($_.SizeRemaining/1GB,2)}}, @{Name="Size";Expression={[math]::Round($_.Size/1GB,2)}}
```

Get system's Disk's Information such as volume, Storage info in readable format .


```
Get-ChildItem Env: | Select-Object Name, Value
```

Get system enviroinment vaiables .


```
Get-WinEvent -FilterHashtable @{ LogName='security'; Id='4800' }
```

Command to read event logs for Lock/screensaver


```
Get-WinEvent -FilterHashtable @{ LogName='security'; Id='4801' }
```


```
Get-WinEvent -FilterHashtable @{ LogName='security'; Id='4802' }
```


```
Get-WinEvent -FilterHashtable @{ LogName='security'; Id='4803' }
```
