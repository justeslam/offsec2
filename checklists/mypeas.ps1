<#
.SYNOPSIS
    Comprehensive PowerShell script for internal audit.

.DESCRIPTION
    This script performs various checks and gathers system information:
    - Reads users from a specified text file and validates them.
    - Retrieves all groups associated with these users.
    - Validates users during group retrieval.
    - Checks for concerning permissions (Write, Read/Execute, etc.) for specified users and groups.
    - Gathers process information including command lines.
    - Collects network connections, services, scheduled tasks, and registry permissions.
    - Outputs results to three files:
        * InterestingFiles.txt
        * RegexSearchResults.txt
        * GeneralOutput.txt

.PARAMETER UserFile
    The path to the text file containing user names (one per line).

.PARAMETER Domain
    The domain name to which the users belong.

.PARAMETER DCIP
    The IP address of the domain controller.

.EXAMPLE
    .\AuditScript.ps1 -UserFile "C:\users.txt" -Domain "MYDOMAIN" -DCIP "192.168.1.10"
#>

param(
    [Parameter(Mandatory = $true)]
    [Alias("u")]
    [string]$UserFile,  # File containing user names

    [Parameter(Mandatory = $true)]
    [Alias("d")]
    [string]$Domain,     # Domain name

    [Parameter(Mandatory = $true)]
    [Alias("dc")]
    [string]$DCIP        # Domain Controller IP
)

# Set error action preference to continue on errors
$ErrorActionPreference = 'Continue'
$Global:GeneralOutputFile = "C:\Windows\Tasks\litty.out"

# Function to log messages with timestamp
function Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $MessageToLog = "[$timestamp] $Message"
    Write-Host $MessageToLog
    # Also write to GeneralOutput.txt
    $MessageToLog | Out-File -FilePath $Global:GeneralOutputFile -Append -Encoding UTF8
}

# Output files
$OutputDir = "C:\Windows\Tasks"
$GeneralOutputFile = "$OutputDir\GeneralOutput.txt"
$InterestingFilesFile = "$OutputDir\InterestingFiles.txt"
$RegexSearchResultsFile = "$OutputDir\RegexSearchResults.txt"

# Create output directory if it doesn't exist
if (-not (Test-Path $OutputDir)) {
    New-Item -Path $OutputDir -ItemType Directory | Out-Null
}

# Clear output files if they exist
foreach ($file in @($GeneralOutputFile, $InterestingFilesFile, $RegexSearchResultsFile)) {
    if (Test-Path $file) {
        Remove-Item $file -Force
    }
}

# Validate the existence of the user file
if (-not (Test-Path $UserFile)) {
    Log "User file path '$UserFile' is invalid or does not exist."
    exit 1
}

# Read user names from the user file
$users = Get-Content -Path $UserFile | Where-Object { $_ -ne '' }

# Initialize a list to store unique user groups
$userGroups = @()
$userDetails = @{}

# Import Active Directory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Log "Failed to import ActiveDirectory module: $_"
    exit 1
}

# Loop through each user to fetch their group memberships and additional details
foreach ($user in $users) {
    $fullUserName = $user
    # Ensure each user identifier includes the domain
    #if ($user -notmatch '\\') {
    #    $fullUserName = "$Domain\$user"
    #}

    # Attempt to validate the user and get domain and local group memberships
    $adGroups = @()
    $localGroups = @()
    $userValid = $false

    try {
        $userObject = Get-ADUser -Identity $fullUserName -ErrorAction Stop
        $userValid = $true
        Log "User '$fullUserName' is valid."
    } catch {
        Log "User '$fullUserName' is not valid or cannot be queried: $_"
    }

    if ($userValid) {
        try {
            $adGroups = Get-ADPrincipalGroupMembership -Identity $fullUserName | Select-Object -ExpandProperty Name
            $adGroups
            $userGroups += $adGroups
            Log "AD Groups for user '$fullUserName':"
            write-host "past agfuv"
            $adGroups | ForEach-Object { Log " - $_" }
            write-host "past weird log"
        } catch {
            Log "Failed to retrieve AD groups for '$fullUserName': $_"
        }

        try {
            $localGroups = Get-NetGroup -MemberIdentity $fullUserName -ErrorAction Stop | Where-Object { $_.ObjectClass -eq 'Group' } | Select-Object -ExpandProperty Name
            $userGroups += $localGroups
            Log "Local Groups for user '$fullUserName':"
            $localGroups | ForEach-Object { Log " - $_" }
        } catch {
            Log "Failed to retrieve local groups for '$fullUserName': $_"
        }
    }

    # Store user details in a dictionary
    $userDetails[$fullUserName] = @{
        DomainGroups = $adGroups
        LocalGroups  = $localGroups
    }
}

Write-Host "made it"
# Remove duplicates from the user groups list
$userGroups = $userGroups | Select-Object -Unique

# Users & identities combined
$identities = $users + $userGroups

# Output the combined list of user groups
Log "`nRetrieved Groups:"
$userGroups | ForEach-Object { Log " - $_" }

# Function to check permissions for specified identities
function CheckPermissionsForIdentities {
    param(
        [string]${Path},
        [string[]]$Identities
    )
    Log "`nChecking permissions in ${Path} for specified identities..."

    try {
        Get-ChildItem -Path ${Path} -Recurse -ErrorAction Stop | ForEach-Object {
            $currentPath = $_.FullName
            $acl = Get-Acl -Path $currentPath -ErrorAction SilentlyContinue
            if ($null -eq $acl) {
                return
            }
            foreach ($access in $acl.Access) {
                foreach ($identity in $Identities) {
                    if ($access.IdentityReference -like "*$identity*") {
                        $rights = $access.FileSystemRights
                        # Concerning permissions
                        $concerningRights = @(
                            [System.Security.AccessControl.FileSystemRights]::Write,
                            [System.Security.AccessControl.FileSystemRights]::Modify,
                            [System.Security.AccessControl.FileSystemRights]::FullControl,
                            [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
                        )
                        foreach ($right in $concerningRights) {
                            if ($rights -band $right) {
                                Log "$identity has $right permission on $currentPath"
                                "$identity has $right permission on $currentPath" | Out-File -FilePath $GeneralOutputFile -Append -Encoding UTF8
                                break
                            }
                        }
                    }
                }
            }
        }
    } catch {
        Log "Error checking permissions in ${Path}: $_"
    }
}

# Collecting user and group information
Log "`nCollecting current user and group information..."

# Get current user's domain and username
try {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $currentUser.Name
    Log "Current user: $userName"
    $userGroups = $currentUser.Groups | ForEach-Object {
        try {
            $_.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $_.Value
        }
    }
    Log "Current user's groups:"
    $userGroups | ForEach-Object { Log " - $_" }
} catch {
    Log "Error retrieving current user information: $_"
}

# Checking permissions for identities
CheckPermissionsForIdentities -Path "C:\" -Identities $identities

# Gathering process information with redundancy
Log "`nGathering process information..."

try {
    $processes = Get-CimInstance Win32_Process -ErrorAction Stop | where-object {$_.Name -notlike "svchost*" -and $_.Path -notlike "C:\Windows\*" -and $_.Name -ne $null }
    foreach ($proc in $processes) {
        $cmdLine = $proc.CommandLine
        if ($null -eq $cmdLine -or $cmdLine -eq "") {
            $cmdLine = "N/A"
        }
        $procInfo = "PID: $($proc.ProcessId), Name: $($proc.Name), ProcessName: $($proc.ProcessName), Path: $($proc.ExecutablePath), CommandLine: $cmdLine, StartTime: $($proc.StartTime)"
        Log $procInfo
    }
} catch {
    Log "Error retrieving processes using Get-CimInstance: $_"
    # Alternative method
    try {
        $processes = Get-Process -ErrorAction Stop | where-object {$_.Name -notlike "svchost*" -and $_.Path -notlike "C:\Windows\*"  -and $_.Name -ne $null }
        foreach ($proc in $processes) {
            $cmdLine = "N/A"
            try {
                $procDetails = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($proc.Id)" -ErrorAction Stop
                $cmdLine = $procDetails.CommandLine
            } catch {
                # Can't retrieve command line
            }
            $procInfo = "PID: $($proc.Id), Name: $($proc.ProcessName), Path: $($proc.Path), CommandLine: $cmdLine"
            Log $procInfo
        }
    } catch {
        Log "Error retrieving processes using Get-Process: $_"
    }
}

# Output process owner information
Write-Host "Process Owners:"
try {
    Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*" -and $_.Path -notlike "C:\Windows\*" -and $_.Name -ne $null } |
    Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} |
    ft -AutoSize | Out-String -Width 4096 | Write-Host
} catch {

    Write-Host "Failed to retrieve process owners"
}   

function Get-ProcessOwner {
    param (
        [int]$ProcessId
    )
    try {
        $process = Get-WmiObject Win32_Process -Filter "ProcessId = $ProcessId"
        if ($process) {
            $ownerInfo = $process.GetOwner()
            if ($ownerInfo.ReturnValue -eq 0) {
                return "$($ownerInfo.Domain)\$($ownerInfo.User)"
            } else {
                return "N/A"
            }
        } else {
            return "Unknown"
        }
    } catch {
        return "Error retrieving owner"
    }
}

# Output header
Log "`n=== Listening Processes Audit ===`n"

try {
    # Retrieve all listening TCP connections
    $listeningTCP = Get-NetTCPConnection -State Listen -ErrorAction Stop

    # Retrieve all listening UDP endpoints
    $listeningUDP = Get-NetUDPEndpoint -ErrorAction Stop

    # Define the maximum UDP port number to include (e.g., 50000)
    $maxUdpPort = 50000

    # Filter UDP connections to exclude high-numbered ports
    $filteredUDP = $listeningUDP | Where-Object { $_.LocalPort -lt $maxUdpPort }

    # Combine TCP and filtered UDP for processing
    $allListening = @()

    foreach ($tcp in $listeningTCP) {
        $procId = $tcp.OwningProcess
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        $procName = $proc.ProcessName
        $exePath = $proc.Path
        $procOwner = Get-ProcessOwner -ProcessId $procId

        $allListening += [PSCustomObject]@{
            Protocol      = "TCP"
            ProcessName   = $procName
            PID           = $procId
            ExecutablePath = $exePath
            LocalAddress  = $tcp.LocalAddress
            LocalPort     = $tcp.LocalPort
            ProcessOwner  = $procOwner
            State         = $tcp.State
        }
    }

    foreach ($udp in $filteredUDP) {
        $procId = $udp.OwningProcess
        $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
        $procName = $proc.ProcessName
        $exePath = $proc.Path
        $procOwner = Get-ProcessOwner -ProcessId $procId

        $allListening += [PSCustomObject]@{
            Protocol      = "UDP"
            ProcessName   = $procName
            PID           = $procId
            ExecutablePath = $exePath
            LocalAddress  = $udp.LocalAddress
            LocalPort     = $udp.LocalPort
            ProcessOwner  = $procOwner
            State         = "Listening"
        }
    }

    # Display the results in a formatted table
    $allListening | Sort-Object Protocol, LocalPort | Format-Table -AutoSize
} catch {
    Log "Error retrieving listening processes: $_"

    # Fallback to netstat if native cmdlets fail
    try {
        Log "`n--- Fallback to netstat ---`n"
        $netstatOutput = netstat -ano | Select-String "LISTENING" | ForEach-Object {
            $line = $_.Line.Trim()
            $tokens = $line -split '\s+'

            if ($tokens.Count -ge 4) {
                $protocol = $tokens[0]
                $localAddress = $tokens[1]
                $pid = $tokens[-1]

                # Extract the port from the local address
                if ($localAddress -match ":(\d+)$") {
                    $port = [int]$matches[1]
                } else {
                    $port = "Unknown"
                }

                # Only process UDP with port < maxUdpPort
                if ($protocol -eq "UDP" -and $port -ge 50000) {
                    return
                }

                # Get process information
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                $procName = $proc.ProcessName
                $exePath = $proc.Path
                $procOwner = Get-ProcessOwner -ProcessId $pid

                # Determine state for TCP
                $state = if ($protocol -eq "TCP") { $tokens[3] } else { "Listening" }

                # Create custom object
                [PSCustomObject]@{
                    Protocol      = $protocol
                    ProcessName   = $procName
                    PID           = $pid
                    ExecutablePath = $exePath
                    LocalAddress  = $localAddress
                    LocalPort     = $port
                    ProcessOwner  = $procOwner
                    State         = $state
                }
            }
        }

        # Display netstat results
        if ($netstatOutput) {
            $netstatOutput | Sort-Object Protocol, LocalPort | Format-Table -AutoSize
        } else {
            Log "No listening processes found via netstat."
        }
    } catch {
        Log "Failed to retrieve listening processes using netstat: $_"
    }
}

# Output service association information
Log "`nService Associations:"
try {
    $services = Get-WmiObject -Class Win32_Service -ErrorAction Stop
    foreach ($service in $services) {
        $serviceInfo = "Name: $($service.Name), DisplayName: $($service.DisplayName), ProcessId: $($service.ProcessId), StartMode: $($service.StartMode), State: $($service.State), PathName: $($service.PathName)"
        Log $serviceInfo
    }
} catch {
    Log "Failed to retrieve service associations: $_"
}

# Gathering network connections
Log "`nNetwork Connections:"
try {
    $netConns = Get-NetTCPConnection -ErrorAction Stop
    foreach ($conn in $netConns) {
        $connInfo = "State: $($conn.State), Local: $($conn.LocalAddress):$($conn.LocalPort), Remote: $($conn.RemoteAddress):$($conn.RemotePort), PID: $($conn.OwningProcess)"
        Log $connInfo
    }
} catch {
    Log "Error retrieving network connections using Get-NetTCPConnection: $_"
    # Alternative method using netstat
    try {
        $netstatOutput = netstat -ano | ForEach-Object {
            Log $_
        }
    } catch {
        Log "Error retrieving network connections using netstat: $_"
    }
}

# Gathering scheduled tasks
Log "`nGathering scheduled tasks..."
try {
    $scheduledTasks = schtasks /query /fo LIST /v
    $scheduledTasks | ForEach-Object {
        Log $_
    }
} catch {
    Log "Error retrieving scheduled tasks using schtasks: $_"
    # Alternative method
    try {
        $scheduledTasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $scheduledTasks) {
            $taskInfo = "TaskName: $($task.TaskName), Path: $($task.Path), State: $($task.State), LastRunTime: $($task.LastRunTime), NextRunTime: $($task.NextRunTime)"
            Log $taskInfo
        }
    } catch {
        Log "Error retrieving scheduled tasks using Get-ScheduledTask: $_"
    }
}

# Gathering registry permissions
function CheckRegistryPermissions {
    param(
        [string]$RegistryPath,
        [string[]]$Identities
    )
    Log "`nChecking registry permissions at $RegistryPath..."

    try {
        Get-ChildItem -Path $RegistryPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            $regItem = $_.PSPath
            $acl = Get-Acl -Path $regItem -ErrorAction SilentlyContinue
            if ($null -eq $acl) {
                return
            }
            foreach ($access in $acl.Access) {
                foreach ($identity in $Identities) {
                    if ($access.IdentityReference -like "*$identity*") {
                        if ($access.RegistryRights -band [System.Security.AccessControl.RegistryRights]::WriteKey -or
                            $access.RegistryRights -band [System.Security.AccessControl.RegistryRights]::FullControl) {
                            Log "$identity has $($access.RegistryRights) on $regItem"
                            "$identity has $($access.RegistryRights) on $regItem" | Out-File -FilePath $GeneralOutputFile -Append -Encoding UTF8
                        }
                    }
                }
            }
        }
    } catch {
        Log "Error checking registry permissions: $_"
    }
}

# Checking registry permissions for services
$registryPath = "HKLM:\System\CurrentControlSet\Services"
CheckRegistryPermissions -RegistryPath $registryPath -Identities $identities

# Function to find interesting files
function FindInterestingFiles {
    param(
        [string[]]$FilePatterns,
        [string]$StartPath
    )
    Log "`nFinding interesting files starting from $StartPath..."

    try {
        $interestingFiles = Get-ChildItem -Path $StartPath -Recurse -Include $FilePatterns -ErrorAction SilentlyContinue
        foreach ($file in $interestingFiles) {
            $fileInfo = "Path: $($file.FullName), Size: $($file.Length)"
            Log $fileInfo
            $fileInfo | Out-File -FilePath $InterestingFilesFile -Append -Encoding UTF8
        }
        return $interestingFiles
    } catch {
        Log "Error finding interesting files: $_"
    }
}

# Function to perform regex search within files
function RegexSearchInFiles {
    param(
        [System.IO.FileInfo[]]$Files,
        [string[]]$Patterns
    )
    Log "`nPerforming regex search within files..."

    foreach ($file in $Files) {
        foreach ($pattern in $Patterns) {
            try {
                $matches = Select-String -Path $file.FullName -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue
                foreach ($match in $matches) {
                    $matchInfo = "File: $($file.FullName), Pattern: '$pattern', Match: $($match.Line)"
                    Log $matchInfo
                    $matchInfo | Out-File -FilePath $RegexSearchResultsFile -Append -Encoding UTF8
                }
            } catch {
                Log "Error searching in file '$($file.FullName)' with pattern '$pattern': $_"
            }
        }
    }
}

# Define file patterns and regex patterns
$filestosearch = @("*.txt","*.pdf","*.xls","*.xlsx","*.xlsm","*.doc","*.docx","Unattend.xml","sysprep.xml","sysprep.inf","*.log","*.kdbx","*.git","*password*","*sensitive*","*admin*","*login*","*secret*","*.vmdk","*.rdp","*.config","*.cnf","*.y*ml","*.bat","*.bak","*.conf","*.vbs","*.sql","*.reg","*cups*","*print*","*cred*","*.ini","id_rsa","authorized_keys")

$patterns = @("user","pass","svc\.","admin", "secret", "cred", "key", "password", "login")

# Find interesting files
$interestingFiles = FindInterestingFiles -FilePatterns $filestosearch -StartPath "C:\"

# Perform regex search within those files
RegexSearchInFiles -Files $interestingFiles -Patterns $patterns

# Conclusion
Log "`nAudit script completed. Logs are saved in '$OutputDir'."
