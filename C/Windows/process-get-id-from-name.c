DWORD getProcessId(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot) {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &entry)) {
            do {
                if (!strcmp(entry.szExeFile, processName)) {
                    return entry.th32ProcessID;
                }
            } while (Process32Next(hSnapshot, &entry));
        }
    }
    else {
        return 0;
    }
}


int getProcessId(WCHAR *processName)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof entry;

    if (!Process32FirstW(snap, &entry)) { return 0; }

    do
    {
        if (wcscmp(entry.szExeFile, processName) == 0)
        {
            return entry.th32ProcessID;
        }
    } while (Process32NextW(snap, &entry));

    return -1;
}
