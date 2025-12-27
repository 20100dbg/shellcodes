#include <windows.h>
#include <stdio.h>
#include <lm.h>

typedef BOOL (WINAPI* sComputerName)(
    LPSTR   lpBuffer,
    LPDWORD nSize
);


int main() {
    
    HMODULE hkernel32 = LoadLibraryA("kernel32.dll");
    sComputerName GetComputer = (sComputerName) GetProcAddress(hkernel32, "GetComputerNameA");

    printf("GetComputerNameA: 0x%p\\n", GetComputer);
    CHAR hostName[260];
    DWORD hostNameLength = 260;
    if (GetComputer(hostName, &hostNameLength)) {
        printf("hostname: %s\\n", hostName);
    }
}
