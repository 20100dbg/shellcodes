
////where to inject this lib ?
//export LD_LIBRARY_PATH=/home/marty/Learning-C/exos/badlib.so
//export LD_PRELOAD=/home/marty/Learning-C/exos/badlib.so
//echo '/home/marty/Learning-C/exos/badlib.so' > /etc/ld.so.preload


////compile this lib
//gcc -ldl badlib.c -fPIC -shared -D_GNU_SOURCE -o badlib.so

#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>


ssize_t write(int fd, const void *buf, size_t count)
{
    //get a reference to the actual write() syscall
    ssize_t (*old_write)(int fd, const void *buf, size_t count);
    old_write = dlsym(RTLD_NEXT, "write");

    int result;
    //listening to a custom trigger
    if (strcmp(buf, "20100dbg") == 0)
    {
        //syscall hooked !
        //lets print or do whatever we want
        result = old_write(fd, "HACK THE PLANET", 15); 
    }
    else
    {
        //do nothing special
        result = old_write(fd, buf, count);
    }

    return result;
}