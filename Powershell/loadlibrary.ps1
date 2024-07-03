$ScriptBlock = { 
    Add-Type -TypeDefinition @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
     
    public static class Kernel32
    {
        [DllImport("kernel32.dll", SetLastError=true, CharSet = CharSet.Ansi)]
            public static extern IntPtr LoadLibrary(
                [MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    }
"@  
     
    [Kernel32]::LoadLibrary("calc.dll")
}
 
Start-Job -Name MSF_Calc -ScriptBlock $ScriptBlock