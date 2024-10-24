# Powershell script designed to be run on Windows 7 workstations and above. 

# Gets the following information which is useful in a pentest:
#  * A list of domain users (useful for finding intersting comments
#  * Finds interesting files
#  * Searches for creds. May take awhile.

##################################################################################################################

# TODO

# Implement the ability to specify (in a txt document, one word per line) words to be included, than append every string to every word to $filestosearch in the form of "*$customWord*", as well as $pattern in the form of "$customWord", as well as adding a new $regexSearch.add() that matches the presence of the word.

# Implement the ability to specify (in a txt document, one word per line) words to be included, that are to be used in functions like..

foreach ($customUser in $additionalUsers) {
Get-CimInstance -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize # Replace .User
}

# Implement the ability to specify (in a txt document, one word per line) groups that will be checked in functions like 'accesschk.exe /accepteula -uwcqv "$additionalGroup" *' 

# Run 'Import-Module .\SharpHound.ps1 ; Invoke-BloodHound -CollectionMethod All,GPOLocalGroup -OutputDirectory C:\Windows\Tasks\ -OutputPrefix "local"'

# Have an argument -dcip that takes in the domain controller ip

# Run '.\Snaffler.exe -o snaffled.txt -s -m c:\Users -d oscp.exam -u -c $dcip -r 10000000 -l 100000000'

# Run '.\laZagne.exe all -oN -output c:\windows\tasks\lazagne.txt'
# Run 
. .\powerview.ps1
import-module activedirectory
.\litty.ps1 -u users.txt -d resourced -dc 192.168.219.175
 . .\powerup.ps1
# Find the last 1000 modified files

# Make sure that the code is able to function as assumed

# Find other directories that are not work checking for to save time (C:\Windows\Microsoft.NET\Framework64,C:\Windows\Microsoft.NET\Framework64,C:\Windows\Microsoft.NET\assembly, C:\Windows\servicing\LCU\,C:\Windows\Help,C:\Windows\INF,C:\Windows\assembly\Native*,'C:\Windows\Program Files\VMware\*','C:\Windows\Program Files*\WindowsPowerShell\Modules\Pester\*', 'C:\Program Files (x86)\windows nt\tabletextservice\')


foreach ($customWord in $customWords) {
    'accesschk.exe /accepteula -uwcqv "$additionalGroup" *'; # Vulnerable Services
    'accesschk.exe /accepteula -uwdqs "$additionalGroup" c:\'; # Vulnerable Folder Permissions
    'accesschk.exe /accepteula -uwqs "$additionalGroup" c:\*.*'; # Vulnerable File Permissions
}

##################################################################################################################

<#
.SYNOPSIS
    Searches for sensitive information in specified files across the system.

.DESCRIPTION
    This script scans through various file types to identify potential sensitive information such as usernames, passwords, and other credentials. It logs the findings for further analysis.

.PARAMETER customWords
    Path to the file containing custom words (e.g., usernames) to search for.

.EXAMPLE
    .\SensitiveInfoScanner.ps1 -customWords "C:\Path\to\customWords.txt"
#>

#### MAKE IT WHERE PEOPLE DONT NEED TO PUT WORDS FILE

param(
    [Parameter(Mandatory = $true)]
    [Alias("w")]
    [string]$customWords,  # File containing user names
)

# ===========================
# Configuration and Setup
# ===========================

# Define directories and log files
$dir = "C:\Windows\Tasks"
$listingsdir = $dir

# Create necessary directories
New-Item -ItemType Directory -Path $dir -Force | Out-Null

# Define log files
$logfile = "$dir\log.out"
$passwordfile = "$dir\passwordsearch.out"

# Define timeout (if needed for future enhancements)
$timeout = 4

# Search configurations
$dopasswordsearch = $true  # Set to $false to disable password search

# Regex search flags
$password = $true
$username = $true
$webAuth = $true
$detailed = $true

# Define file extensions to search
$fileExtensions = @("*.txt","*.pdf","*.xls","*.xlsx","*.doc","*.docx","*.log","*.kdbx","*.git","*.rdp","*.config","*.bat","*.bak","*.conf","*.vbs","*.sql","*.reg","*password*","*sensitive*","*admin*","*login*","*secret*","*.vmdk","*cups*","*print*","*secret*","*cred*","*.ini","*oscp*","*ms01*","*pass*","*ms02*","*dc01*","SYSTEM","SAM","SECURITY","ntds.dit","id_rsa","authorized_keys")

# Initialize search paths (limit to essential directories for performance)
$searchPaths = @("C:\")  # Add or modify as needed

# ===========================
# Function Definitions
# ===========================

function Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $logfile -Append -Encoding UTF8
}

# ===========================
# Initial Cleanup
# ===========================

# Delete old log files safely with logging
$filesToDelete = @($logfile, $sharefile, $dirfile, $passwordfile)
foreach ($file in $filesToDelete) {
    if (Test-Path $file) {
        try {
            Remove-Item -Path $file -Force -ErrorAction Stop
            Log "Deleted old log file: $file"
        }
        catch {
            Log "Failed to delete file $file: $_"
        }
    }
}

# ===========================
# Validate and Read Custom Words
# ===========================

# Validate the existence of the user file
if (-not (Test-Path $customWords -PathType Leaf)) {
    Log "File path '${customWords}' is invalid or does not exist."
    Write-Error "File path '${customWords}' is invalid or does not exist."
    exit 1
}

# Read and sanitize words from the file
$words = Get-Content -Path $customWords | Where-Object { $_.Trim() -ne '' }

if ($words.Count -eq 0) {
    Log "No valid words found in the custom words file."
    Write-Error "No valid words found in the custom words file."
    exit 1
}

# ===========================
# Prepare Search Patterns
# ===========================

# Basic patterns to search for
$pattern = @("user","pass","svc\.", "admin", "secret", "cred", "key", "ms01", "ms02", "dc01", "oscp")

# Add custom words to patterns and filestosearch
foreach ($customWord in $words) {
    $safeWord = [regex]::Escape($customWord)
    $fileExtensions += "*$safeWord*"
    $pattern += $safeWord
    $regexSearch.Add("Custom_$safeWord", "$safeWord.*[=:].+")
}

# ===========================
# Search for Interesting Files
# ===========================

Write-Host "Searching for interesting files..." -ForegroundColor Cyan
Log "Starting search for interesting files."

# Initialize an array to hold interesting files
$interestingFiles = @()

foreach ($searchPath in $searchPaths) {
    if (Test-Path $searchPath) {
        try {
            $foundFiles = Get-ChildItem -Path $searchPath -Recurse -Include $fileExtensions -ErrorAction Stop -Force |
                Where-Object {
                    -not ($_.FullName -like "C:\Windows\servicing\LCU\*") -and
                    -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework\*") -and
                    -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework64\*") -and
                    -not ($_.FullName -like "C:\Windows\WinSxS\x*") -and
                    -not ($_.FullName -like "C:\Windows\Microsoft.NET\assembly\*") -and
                    -not ($_.FullName -like "C:\Windows\Help*") -and
                    -not ($_.FullName -like "C:\Windows\Program Files\VMware\*") -and
                    -not ($_.FullName -like "C:\Windows\Program Files*\WindowsPowerShell\Modules\Pester\*") -and
                    -not ($_.FullName -like "C:\Program Files*\windows nt\tabletextservice*") -and
                    -not ($_.FullName -like "C:\Windows\Tasks\*")
                }
            $interestingFiles += $foundFiles
        }
        catch {
            Log "Error searching in $searchPath: $_"
            Write-Warning "Error searching in $searchPath: $_"
        }
    }
    else {
        Log "Search path does not exist: $searchPath"
        Write-Warning "Search path does not exist: $searchPath"
    }
}

Log "Found $($interestingFiles.Count) interesting files."

# ===========================
# Analyze Found Files
# ===========================

Write-Host "Analyzing found files..." -ForegroundColor Cyan

foreach ($file in $interestingFiles) {
    $filePath = $file.FullName

    # Skip files with 'lang' in their path
    if ($filePath -match "(?i).*lang.*") {
        continue
    }

    # Check if the file name contains 'pass'
    if ($filePath -match "(?i).*\\.*Pass.*") {
        Write-Host "$filePath contains the word 'pass'" -ForegroundColor Blue
        Log "Found 'pass' in: $filePath"
    }

    # Check if the file name contains 'user' but exclude specific directories if needed
    if ($filePath -match "(?i).*\\.*user.*") {
        Write-Host "$filePath contains the word 'user'" -ForegroundColor Blue
        Log "Found 'user' in: $filePath"
    }

    # If the file is an Excel file, perform additional search (optional)
    if ($filePath -match ".*\.(xls|xlsx|xlsm)$") {
        Write-Host "Check out the Excel files manually" -ForegroundColor Yellow
        Log "Excel file detected: $filePath"
    }

    # Perform regex searches for custom patterns
    foreach ($key in $regexSearch.Keys) {
        try {
            $passwordFound = Get-Content -Path $filePath -ErrorAction Stop | Select-String -Pattern $regexSearch[$key] -Context 1,1
            if ($passwordFound) {
                Write-Host "Possible sensitive data found with pattern '$key' in: $filePath" -ForegroundColor Yellow
                Log "Pattern '$key' matched in: $filePath"
                Log $passwordFound.Context.PreContext
                Log $passwordFound.Context.PostContext
            }
        }
        catch {
            Log "Error reading file $filePath: $_"
        }
    }
}

# ===========================
# Completion Message
# ===========================

Write-Host "Scan completed. Check the log file at $logfile for details." -ForegroundColor Green
Log "Scan completed."

# ===========================
# End of Script
# ===========================

# Change the following to $FALSE if you don't want to search for passwords
$dopasswordsearch = $TRUE

# Set these values to true to add them to the regex search by default
$password = $true
$username = $true
$webAuth = $true
$detailed = $true

# Delete the old log files
del -ErrorAction SilentlyContinue $logfile
del -ErrorAction SilentlyContinue $sharefile
del -ErrorAction SilentlyContinue $dirfile
del -ErrorAction SilentlyContinue $passwordfile

# Validate the existence of the user file
if (-not (Test-Path $customWords)) {
    Log "File path '${customWords}' is invalid or does not exist."
    exit 1
}

# Read words from the file
$words = Get-Content -Path $customWords | Where-Object { $_ -ne '' }

# Regex for optional password search
$filestosearch = ("*.txt","*.pdf","*.xls","*.xlsx","*.doc","*.docx","*.log","*.kdbx","*.git","*.rdp","*.config","*.bat","*.bak","*.conf","*.vbs","*.sql","*.reg","*password*","*sensitive*","*admin*","*login*","*secret*","*.vmdk","*cups*","*print*","*secret*","*cred*","*.ini","*oscp*","*ms01*","*pass*","*ms02*","*dc01*","SYSTEM","SAM","SECURITY","ntds.dit","id_rsa","authorized_keys")

# Simple patterns to search for
$pattern = ("user","pass","svc\.","admin", "secret", "cred", "key", "ms01", "ms02", "dc01", "oscp") # Append any other information that is unique to machine, like all the usernames, hostname, passwords, ..

# Initializing more complex regex search
$regexSearch = @{}

foreach ($customWord in $customWords) {
    $filestosearch += "*${customWord:*"
    $pattern += "${customWord}"
    $regexSearch.Add("Custom_${customWord}", "${customWord}.*[=:].+")
}


if ($password) {
  $regexSearch.add("Simple Passwords1", "pass.*[=:].+")
  $regexSearch.add("Simple Passwords2", "pwd.*[=:].+")
  $regexSearch.add("Apr1 MD5", '\$apr1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $regexSearch.add("Apache SHA", "\{SHA\}[0-9a-zA-Z/_=]{10,}")
  $regexSearch.add("Blowfish", '\$2[abxyz]?\$[0-9]{2}\$[a-zA-Z0-9_/\.]*')
  $regexSearch.add("Drupal", '\$S\$[a-zA-Z0-9_/\.]{52}')
  $regexSearch.add("Joomlavbulletin", "[0-9a-zA-Z]{32}:[a-zA-Z0-9_]{16,32}")
  $regexSearch.add("Linux MD5", '\$1\$[a-zA-Z0-9_/\.]{8}\$[a-zA-Z0-9_/\.]{22}')
  $regexSearch.add("phpbb3", '\$H\$[a-zA-Z0-9_/\.]{31}')
  $regexSearch.add("sha512crypt", '\$6\$[a-zA-Z0-9_/\.]{16}\$[a-zA-Z0-9_/\.]{86}')
  $regexSearch.add("Wordpress", '\$P\$[a-zA-Z0-9_/\.]{31}')
  $regexSearch.add("md5", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{32}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha1", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{40}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha256", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{64}([^a-zA-Z0-9]|$)")
  $regexSearch.add("sha512", "(^|[^a-zA-Z0-9])[a-fA-F0-9]{128}([^a-zA-Z0-9]|$)")
  $regexSearch.add("Base64", "(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+\/]+={0,2}")
}

# For username in usernames
if ($username) {
  $regexSearch.add("Usernames1", "username[=:].+")
  $regexSearch.add("Usernames2", "user[=:].+")
  $regexSearch.add("Usernames3", "login[=:].+")
  $regexSearch.add("Emails", "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}")
  $regexSearch.add("Net user add", "net user .+ /add")
}

if ($detailed) {
  $regexSearch.add("Authorization Basic", "basic [a-zA-Z0-9_:\.=\-]+")
  $regexSearch.add("Authorization Bearer", "bearer [a-zA-Z0-9_\.=\-]+")
  $regexSearch.add("Basic Auth Credentials", "://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+")
  $regexSearch.add("Private Keys", "\-\-\-\-\-BEGIN PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN RSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN OPENSSH PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN PGP PRIVATE KEY BLOCK\-\-\-\-\-|\-\-\-\-\-BEGIN DSA PRIVATE KEY\-\-\-\-\-|\-\-\-\-\-BEGIN EC PRIVATE KEY\-\-\-\-\-")
  $regexSearch.add("Travis CI Access Token", "([a-z0-9]{22})")
  $regexSearch.add("Jenkins Creds", "<[a-zA-Z]*>{[a-zA-Z0-9=+/]*}<")
  $regexSearch.add("Generic Secret", "[sS][eE][cC][rR][eE][tT].*['""][0-9a-zA-Z]{32,45}['""]")
  $regexSearch.add("Basic Auth", "//(.+):(.+)@")
  $regexSearch.add("PHP Passwords", "(pwd|passwd|password|PASSWD|PASSWORD|dbuser|dbpass|pass').*[=:].+|define ?\('(\w*pass|\w*pwd|\w*user|\w*datab)")
  $regexSearch.add("Config Secrets (Passwd / Credentials)", "passwd.*|creden.*|^kind:[^a-zA-Z0-9_]?Secret|[^a-zA-Z0-9_]env:|secret:|secretName:|^kind:[^a-zA-Z0-9_]?EncryptionConfiguration|\-\-encryption\-provider\-config")
  $regexSearch.add("Generic API Key", "((key|api|token|secret|password)[a-z0-9_ \.,\-]{0,25})(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
  $regexSearch.add("Generiac API tokens search", "(access_key|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key| amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret| api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret| application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket| aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password| bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key| bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver| cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret| client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password| cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|conn.login| connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test| datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password| digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd| docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid| dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password| env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)[a-z0-9_ .,<\-]{0,25}(=|>|:=|\|\|:|<=|=>|:).{0,5}['""]([0-9a-zA-Z_=\-]{8,64})['""]")
}


# Find files that match $filestosearch
Write-Host "Finding interesting files ..."
$interestingFiles = get-childitem  -path c:\ -ErrorAction SilentlyContinue -include $filestosearch -recurse | Where-Object { -not ($_.FullName -like "C:\Windows\servicing\LCU\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework64\*") -and -not ($_.FullName -like "C:\Windows\WinSxS\x*") and -not ($_.FullName -like "C:\Windows\Microsoft.NET\assembly\*") and -not ($_.FullName -like "C:\Windows\Help*") and -not ($_.FullName -like "C:\Windows\Program Files\VMware\*") and -not ($_.FullName -like "C:\Windows\Program Files*\WindowsPowerShell\Modules\Pester\*") and -not ($_.FullName -like "C:\Program Files*\windows nt\tabletextservice*") and -not ($_.FullName -like "C:\Windows\Tasks\*.") }

# Print Interesting Files & Save them to interestingFiles.txt
Write-Host "Finding interesting files ..."


Get-ChildItem C:\ -Recurse -Include $fileExtensions -ErrorAction SilentlyContinue -Force | 
Where-Object { -not ($_.FullName -like "C:\Windows\servicing\LCU\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework64\*") -and -not ($_.FullName -like "C:\Windows\WinSxS\x*") and -not ($_.FullName -like "C:\Windows\Microsoft.NET\assembly\*") and -not ($_.FullName -like "C:\Windows\Help*") and -not ($_.FullName -like "C:\Windows\Program Files\VMware\*") and -not ($_.FullName -like "C:\Windows\Program Files*\WindowsPowerShell\Modules\Pester\*") and -not ($_.FullName -like "C:\Program Files*\windows nt\tabletextservice*") and -not ($_.FullName -like "C:\Windows\Tasks\*.") } |
# Write interesting files to a file!!!!!!!
ForEach-Object {
    $path = $_
    #Exclude files/folders with 'lang' in the name
    if ($Path.FullName | select-string "(?i).*lang.*") {
      #Write-Host "$($_.FullName) found!" -ForegroundColor red
    }
    if($Path.FullName | Select-String "(?i).:\\.*\\.*Pass.*"){
      write-host -ForegroundColor Blue "$($path.FullName) contains the word 'pass'"
    }
    if($Path.FullName | Select-String ".:\\.*\\.*user.*" ){
      Write-Host -ForegroundColor Blue "$($path.FullName) contains the word 'user' -excluding the 'users' directory"
    }
    # If path name ends with common excel extensions
    elseif ($Path.FullName | Select-String ".*\.xls",".*\.xlsm",".*\.xlsx") {
      if ($ReadExcel -and $Excel) {
        Search-Excel -Source $Path.FullName -SearchText "user"
        Search-Excel -Source $Path.FullName -SearchText "pass"
      }
    }
    else {
      if ($path.Length -gt 0) {
        # Write-Host -ForegroundColor Blue "Path name matches extension search: $path"
      }
      $regexSearch.keys | ForEach-Object {
        $passwordFound = Get-Content $path.FullName -ErrorAction SilentlyContinue -Force | Select-String $regexSearch[$_] -Context 1, 1
        if ($passwordFound) {
          Write-Host "Possible Password found: $_" -ForegroundColor Yellow
          Write-Host $Path.FullName
          Write-Host -ForegroundColor Blue "$_ triggered"
          Write-Host $passwordFound -ForegroundColor Red
        }
      }
    }  
}

