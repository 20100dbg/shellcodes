#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h> 
#include <string.h> 

//buffer size may vary
#define BUFFER_SIZE 1024

void *recvData(void *vargp);

int main(int argc, char const *argv[])
{
    if (argc != 3)
    {
        printf("Usage %s <ip> <port>\n", argv[0]);
        exit(1);
    }

    //Create socket and ip+port struct
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(argv[2]));
    inet_aton(argv[1], &serv_addr.sin_addr); //ok

    //connect
    int res = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    //start thread that will receive data. We send sockfd as arg
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, recvData, (void *)&sockfd);
    //pthread_join(thread_id, NULL);

    char buffer[BUFFER_SIZE];

    do {
        //we need to bzero() buffer since it still holds old data
        bzero(buffer,BUFFER_SIZE);
        fgets(buffer, BUFFER_SIZE - 1, stdin);
        write(sockfd, buffer, strlen(buffer));

    } while (strcmp(buffer, "exit\n") != 0);

    //once we exit, don't forget to kill the receive thread
    pthread_cancel(thread_id);
    close(sockfd);

    return 0;
}


void *recvData(void *vargp) 
{ 
    //retrieve sockfd as arg so we can use it in read()
    int *sockfd = (int *)vargp;
    
    char buffer[BUFFER_SIZE];
    while (1)
    {
        //always bzero() before read
        bzero(buffer,BUFFER_SIZE);
        
        //read() is non-blocking
        int n = read(*sockfd, buffer, BUFFER_SIZE - 1);
        if (n > -1) printf("> %s", buffer);

        //just a little pause
        sleep(0.5);
    }
    return NULL; 
} 
