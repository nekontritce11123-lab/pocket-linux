using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading;
using System.Windows;
using System.Windows.Threading;

internal static class Bridge { internal static string Root; }
namespace WindowsClaude.Launcher
{
    public partial class App : Application
    {
        public void InitializeComponent() { ShutdownMode = ShutdownMode.OnMainWindowClose; }
    }
    public sealed class MainWindow : Window
    {
        internal void ShowExistingPanel() { throw new Exception("This IPC fixture must never create a window."); }
    }
}
internal static class LauncherInstanceRegression
{
    internal static EventWaitHandle HostEntered, HostReady, HostShown, HostExit, HostHandoff, HostReleased;
    internal static int StartupDelay;
    static int checks;
    static readonly List<Host> hosts = new List<Host>();
    static void Assert(bool value, string message) { if (!value) throw new Exception(message); ++checks; }

    sealed class Host : IDisposable
    {
        internal readonly string Name = "Local\\LauncherInstanceFixture-" + Guid.NewGuid().ToString("N");
        internal readonly EventWaitHandle Entered, Ready, Shown, Exit, Handoff, Released;
        internal readonly Process Process;
        internal Host(string root, int startupDelay = 0, int afterReleaseDelay = 0)
        {
            Entered = Make("entered"); Ready = Make("ready"); Shown = Make("shown");
            Exit = Make("exit"); Handoff = Make("handoff"); Released = Make("released");
            Process = Process.Start(new ProcessStartInfo(Assembly.GetExecutingAssembly().Location,
                "host \"" + root + "\" " + Name + " " + startupDelay + " " + afterReleaseDelay) { UseShellExecute = false, CreateNoWindow = true });
            hosts.Add(this);
        }
        EventWaitHandle Make(string part) { return new EventWaitHandle(false, EventResetMode.ManualReset, Name + "-" + part); }
        public void Dispose()
        {
            Exit.Set();
            if (!Process.WaitForExit(5000)) { Process.Kill(); Process.WaitForExit(); }
            Process.Dispose(); Entered.Dispose(); Ready.Dispose(); Shown.Dispose(); Exit.Dispose(); Handoff.Dispose(); Released.Dispose();
        }
    }
    static EventWaitHandle Open(string name, string part) { return EventWaitHandle.OpenExisting(name + "-" + part); }
    [STAThread] static int Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "host")
        {
            Bridge.Root = args[1]; string name = args[2]; StartupDelay = Int32.Parse(args[3]);
            HostEntered = Open(name, "entered"); HostReady = Open(name, "ready"); HostShown = Open(name, "shown");
            HostExit = Open(name, "exit"); HostHandoff = Open(name, "handoff"); HostReleased = Open(name, "released");
            Type gateType = typeof(WindowsClaude.Launcher.App).GetNestedType("InstallationInstance", BindingFlags.NonPublic);
            var instance = (IDisposable)Activator.CreateInstance(gateType, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { Bridge.Root }, null);
            using (instance)
            {
                bool owner = (bool)gateType.GetField("IsOwner", BindingFlags.Instance | BindingFlags.NonPublic).GetValue(instance);
                if (!owner) return 0;
                HostEntered.Set(); Thread.Sleep(StartupDelay);
                Dispatcher dispatcher = Dispatcher.CurrentDispatcher;
                gateType.GetMethod("Listen", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(instance,
                    new object[] { dispatcher, new Action(delegate { HostShown.Set(); }) });
                Action exit = delegate { try { dispatcher.BeginInvokeShutdown(DispatcherPriority.Normal); } catch (InvalidOperationException) { } };
                ThreadPool.RegisterWaitForSingleObject(HostExit, delegate { exit(); }, null, Timeout.Infinite, true);
                ThreadPool.RegisterWaitForSingleObject(HostHandoff, delegate { exit(); }, null, Timeout.Infinite, true);
                HostReady.Set(); Dispatcher.Run();
            }
            int code = 0;
            HostReleased.Set(); Thread.Sleep(Int32.Parse(args[4])); return code;
        }
        try
        {
            string firstRoot = Path.Combine(args[0], "first-install"), otherRoot = Path.Combine(args[0], "other-install");
            Directory.CreateDirectory(firstRoot); Directory.CreateDirectory(otherRoot);
            var owner = new Host(firstRoot, 800, 1800);
            Assert(owner.Entered.WaitOne(5000), "first startup entered before its panel exists");
            var duplicate = new Host(firstRoot);
            Assert(duplicate.Process.WaitForExit(3000), "same root must not leave a second Launcher process");
            Assert(duplicate.Process.ExitCode == 0 && !duplicate.Ready.WaitOne(0), "duplicate exits without entering a second owner dispatcher");
            Assert(owner.Ready.WaitOne(5000) && owner.Shown.WaitOne(5000), "early repeat startup is queued and invokes the existing owner restore callback");
            owner.Shown.Reset();
            var alias = new Host(Path.Combine(firstRoot, ".").ToUpperInvariant());
            Assert(alias.Process.WaitForExit(3000) && owner.Shown.WaitOne(3000), "case and dot aliases identify the same installation");
            var independent = new Host(otherRoot);
            Assert(independent.Ready.WaitOne(5000) && !independent.Process.HasExited, "different installation roots run independently");
            owner.Handoff.Set();
            Assert(owner.Released.WaitOne(5000) && !owner.Process.HasExited, "handoff releases ownership as App.Run ends, before process teardown");
            var replacement = new Host(firstRoot);
            Assert(replacement.Ready.WaitOne(5000), "replacement acquires ownership after handoff");
            Assert(!independent.Process.HasExited, "handoff in one root leaves another installation running");
            replacement.Exit.Set();
            Assert(replacement.Released.WaitOne(5000), "normal close releases ownership");
            var reopened = new Host(firstRoot);
            Assert(reopened.Ready.WaitOne(5000), "installation can reopen after normal close");
            Console.WriteLine("PASS Linux launcher IPC: " + checks + " checks"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
        finally { for (int i = hosts.Count - 1; i >= 0; --i) hosts[i].Dispose(); }
    }
}

