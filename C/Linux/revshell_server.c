#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h> 
#include <string.h> 

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

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[1]));
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
    listen(sockfd, 5);

    int clilen = sizeof(cli_addr);
    int clientfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

    char *cliip = inet_ntoa(cli_addr.sin_addr);
    printf("[+] Connected to client %s\n", cliip);

    pthread_t thread_id;
    pthread_create(&thread_id, NULL, recvData, (void *)&clientfd);
    //pthread_join(thread_id, NULL);

    char buffer[BUFFER_SIZE];

    do {
        bzero(buffer,BUFFER_SIZE);
        fgets(buffer, BUFFER_SIZE - 1, stdin);
        write(clientfd, buffer, strlen(buffer));

    } while (strcmp(buffer, "exit\n") != 0);

    pthread_cancel(thread_id);
    close(clientfd);
    close(sockfd);

    return 0;
}

void *recvData(void *vargp) 
{ 
    int *clientfd = (int *)vargp;
    char buffer[BUFFER_SIZE];
    while (1)
    {
        bzero(buffer,BUFFER_SIZE);
        int n = read(*clientfd, buffer, BUFFER_SIZE - 1);
        if (n > -1) printf("> %s", buffer);
        sleep(0.5);
    }
    return NULL; 
} 
