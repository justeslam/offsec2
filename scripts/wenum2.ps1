# Powershell script designed to be run on Windows 7 workstations and above. 

# Gets the following information which is useful in a pentest:
#  * A list of domain users (useful for finding intersting comments
#  * A list of shares in the domain (typically includes all Windows workstations/servers connected to the domain)
#  * A list of ACLs for each share, in a nice HTML table that can be copy/pasted into Word
#  * A list of files/directories in the root of each share
#  * A full recursive directory listing of each share (useful for finding interesting file names)
#  * A search for files containing specific strings. This often takes a long long time, hence is optional

##################################################################################################################

# TODO

# Implement the ability to specify (in a txt document, one word per line) words to be included, than append every string to every word to $filestosearch in the form of "*$customWords*", as well as $pattern in the form of "$customWords", as well as adding a new $regexSearch.add() that matches the presence of the word.

# Implement the ability to specify (in a txt document, one word per line) groups that will be checked in functions like 'accesschk.exe /accepteula -uwcqv "$additionalGroup" *' 

foreach ($customWords in $additionalWords) {
    'accesschk.exe /accepteula -uwcqv "$additionalGroup" *'; # Vulnerable Services
    'accesschk.exe /accepteula -uwdqs "$additionalGroup" c:\'; # Vulnerable Folder Permissions
    'accesschk.exe /accepteula -uwqs "$additionalGroup" c:\*.*';
}

##################################################################################################################

$dir = "C:\windows\tasks"
$listingsdir = "$dir\dirlistings"
md -ErrorAction SilentlyContinue -Path $dir
$logfile = "$dir\log.out"
$sharefile = "$dir\shares.out"
$shareauditfile = "$dir\share_audit.html"
$usersfile = "$dir\users.out"
$passwordfile = "$dir\passwordsearch.out"
$timeout = 4

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

# for user in $(cat users.txt); do echo -n "\"$user\"," ; done

# Regex for optional password search
$filestosearch = ("*.txt","*.pdf","*.xls","*.xlsx","*.xlsm","*.doc","*.docx","Unattend.xml","sysprep.xml","sysprep.inf"."*.log","*.kdbx","*.git","*.rdp","*.config","*.cnf","*.y*ml","*.bat","*.bak","*.conf","*.vbs","*.sql","*.reg","*cups*","*print*","*secret*","*cred*","*.ini","*oscp*","*ms01*","*pass*","*ms02*","*dc01*","SYSTEM","SAM","SECURITY","ntds.dit","id_rsa","authorized_keys")
$pattern = ("user","pass","svc\.","admin", "secret", "cred", "key", "ms01", "ms02", "dc01", "oscp") # Append any other information that is unique to machine, like all the usernames, hostname, passwords, ..

$regexSearch = @{}

# Define additional words to include
$additionalWords = @("word1", "word2", "word3")

foreach ($customWords in $additionalWords) {
    $filestosearch += "*$customWords*"
    $pattern += "$customWords"
    $regexSearch.Add("Custom_$customWords", ".*$customWords.*")
}

Where-Object { -not ($_.FullName -like "C:\Windows\servicing\LCU\*") -and -not ($_.FullName -like "C:\Windows\Microsoft.NET\Framework\*") -and -not ($_.FullName -like "C:\Windows\WinSxS\amd*") -and -not ($_.FullName -like "C:\Windows\WinSxS\x*") -and ($_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath -notlike "*Windows Kits*")}
Get-ChildItem c:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.PSPath -notlike "*C:\temp*" -and $_.PSParentPath -notlike "*Reference Assemblies*" -and $_.PSParentPath -notlike "*Windows Kits*"}| Select-String -Pattern "password" | Out-File C:\temp\password.txt

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

$Drives = Get-PSDrive | Where-Object { $_.Root -like "*:\" }

# Simple logging funciton
function log ($message) {
    $message
    $message | Out-File -Append $logfile
}

md -ErrorAction SilentlyContinue -Path $dir
log -message "Output directory: $dir"

# Dumping users
log -message "Using WMIC to get a list of users ..."
wmic useraccount > $usersfile
log -message "WMIC completed."

# The 'net view' command
log -message "Running net view ..." 
$nv = net view
log -message "Net view completed." 

# An array to store all shares (strings)
$shares = @()

# An array to store all share objects
$shareobjects = @()

# Loop through the servers
foreach ($line in $nv) {
    # Extract the server names from the net view command
    if ($line -match "\\\\([^ ]+) ") {
        $server = $matches[1]

        log -message "Querying $server for shares ..."
		
	# List shares, killing the net view if it takes too long
        # NB we're using net view here, as it works nice with low privs on old boxes
        $job = start-job -ArgumentList $server { param($server) net view \\$server /all}
        sleep $timeout
        $result = Receive-Job -Job $job
        Stop-Job -Job $job

        log -message "Query of $server complete."
	foreach ($share in $result) {
	    if ($share -match "([^ ]+) +Disk +") {
		$name =  $matches[1]
		log -message "Found share \\$server\$name"
		$shares += "\\$server\$name"
		"\\$server\$name" | Out-File -Append $sharefile
	    }
	}
    }
}

foreach ($share in $shares) {

    if (Test-path $share) {
        $acl = get-acl $share | select -expandproperty access | out-string
    }
    else {
        $acl = "No Access"
        continue
    }
    
    log -message "Getting directory listing from the root of the share..."
    $files = Get-ChildItem -ErrorAction SilentlyContinue $share | select -expandproperty name  | out-string
    
    $shareobject = new-object -typename PSObject -Property @{
    'share' = $share
    'files' = $files
    'acl' = $acl
    }
    
    $shareobjects += $shareobject
    
    log -message "Doing full directory listing of $share..."
    $sharefilename = "$listingsdir" + ($share -replace "\\", "_") + "_$date.txt"
    dir -ErrorAction SilentlyContinue -recurse $share | Select -ExpandProperty FullName | Out-File $sharefilename
    log -message "Directory listing of $share completed."
}

# Making pretty HTML output...
# Order the properties of the object, so the output table is created correctly
$shareobjects = $shareobjects | select share,files,acl
# Change the table cells to include <pre> tags
$shareobjects | convertto-html | foreach {if($_ -like "*<td>*") {$_ -replace "<td>","<td><pre>"} elseif ($_ -like "*</td>*") {$_ -replace "</td>","</pre></td>"} else {$_} }| out-file $shareauditfile

# Optional password search
if ($dopasswordsearch) {
    log -message "Doing optional password search ..."
    foreach ($share in $shares) { 
        log -message "Finding passwords in $share ..."
        get-childitem  -path $share -ErrorAction SilentlyContinue -include $filestosearch -recurse | select-string -pattern $pattern | select -unique path | format-table -hidetableheaders | out-file -Append $passwordfile
    }
    log -message "Password search complete."
}
