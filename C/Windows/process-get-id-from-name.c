#include <stdio.h>
#include <windows.h>

//EnumProcesses
#include <psapi.h>

//CreateToolhelp32Snapshot
#include <tlhelp32.h>



int get_process_id_1(char* process_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(snap, &pe)) {
        while (Process32Next(snap, &pe)) {
            if (!strcmp(pe.szExeFile, process_name))
            {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }        
        }
    }
    
    return -1;
}



int get_process_id_2(PCWSTR process_name)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        while (Process32NextW(snap, &pe)) {
            if (!strcmp(pe.szExeFile, process_name))
            {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }        
        }
    }
    
    return -1;
}


int get_process_id_3(const char* process_name)
{
    int pid = -1;
    DWORD procs[1024], size, process_count;
    TCHAR sz_process[MAX_PATH];

    // Get the list of process identifiers.
    if ( !EnumProcesses(procs, sizeof(procs), &size) ) 
        return -1;

    // Calculate how many process identifiers were returned.
    process_count = size / sizeof(DWORD);

    for (int i = 0; i < process_count; i++ ) {
        if (procs[i] != 0) {
            // Get a handle to the process.
            HANDLE p = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procs[i]);
            // and find the one we're looking for
            if (p != NULL) {
                HMODULE hModule;
                if (EnumProcessModules(p, &hModule, sizeof(hModule), &size)) {
                    GetModuleBaseName(p, hModule, (LPSTR) sz_process, sizeof(sz_process)/sizeof(TCHAR));
                    if (lstrcmpiA(process_name, sz_process) == 0) {
                        pid = procs[i];
                        break;
                    }
                }
            }
            CloseHandle(p);
        }
    }
    return -1;
}



int main(int argc, char const *argv[])
{
    char process_name1[] = "conhost.exe";
    WCHAR* process_name2 = L"conhost.exe";


    int process_id = get_process_id_1(process_name1);
    printf("1 - %d\n", process_id);
    
    process_id = get_process_id_2(process_name2);
    printf("2 - %d\n", process_id);

    process_id = get_process_id_3(process_name1);
    printf("3 - %d\n", process_id);

    return 0;
}