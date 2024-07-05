using System;
using System.Diagnostics;
using System.ComponentModel;

static class Program
{
    static void Main()
    {
        Console.WriteLine(GetProcessId("explorer"));
    }

    static int GetProcessId(string name)
    {
        Process[] processes = Process.GetProcesses();

        for (int i = 0; i < processes.Length; i++)
        {
            if (processes[i].ProcessName == name)
                return processes[i].Id;
        }

        return -1;
    }
}