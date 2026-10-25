using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Threading;
using System.Windows;

namespace WindowsClaude.Launcher
{
    public partial class App : Application
    {
        [STAThread]
        public static int Main(string[] args)
        {
            AppDomain.CurrentDomain.AssemblyResolve += LoadEmbedded;
            try
            {
                using (var instance = new InstallationInstance(Bridge.Root))
                {
                    if (!instance.IsOwner) return 0;
                    return RunApp(instance);
                }
            }
            catch (Exception error)
            {
                if (args.Length > 0) { Console.Error.WriteLine(error.GetType().Name + ": " + error.Message); return 1; }
                // Keep the cause for diagnostics; the message box below stays generic.
                try { Directory.CreateDirectory(Path.Combine(Bridge.Root, "logs")); File.AppendAllText(Path.Combine(Bridge.Root, "logs", "launcher-error.log"), DateTime.Now.ToString("o") + " " + error + Environment.NewLine); } catch (Exception) { }
                MessageBox.Show("Не удалось открыть панель. Проверь целостность комплекта и .NET Framework 4.8.", "Pocket Linux");
                return 1;
            }
        }

        // Kept out of Main so WPF-UI types are resolved only after the handler above is installed.
        [MethodImpl(MethodImplOptions.NoInlining)]
        static int RunApp(InstallationInstance instance)
        {
            // WPF animates at 60 fps by default, which looks choppy on 120-240 Hz screens: follow the screen instead.
            System.Windows.Media.Animation.Timeline.DesiredFrameRateProperty.OverrideMetadata(
                typeof(System.Windows.Media.Animation.Timeline), new FrameworkPropertyMetadata { DefaultValue = ScreenRefreshRate() });
            App app = new App();
            app.InitializeComponent();
            MainWindow window = new MainWindow();
            window.Loaded += delegate { instance.Listen(app.Dispatcher, window.ShowExistingPanel); };
            return app.Run(window);
        }

        sealed class InstallationInstance : IDisposable
        {
            readonly Mutex mutex;
            readonly EventWaitHandle activate;
            RegisteredWaitHandle listener;
            volatile bool disposed;
            internal readonly bool IsOwner;

            internal InstallationInstance(string root)
            {
                string canonical = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).ToUpperInvariant();
                string key;
                using (var hash = SHA256.Create()) key = BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(canonical))).Replace("-", "");
                string name = @"Local\PocketLinux.Launcher." + key;
                // Create first: a second startup may signal before the owner has a window/listener.
                activate = new EventWaitHandle(false, EventResetMode.AutoReset, name + ".Activate");
                mutex = new Mutex(false, name + ".Owner");
                IsOwner = Acquire(0);
                if (!IsOwner)
                {
                    activate.Set();
                    // A closing owner may release between lookup and activation; take over if it does.
                    IsOwner = Acquire(250);
                }
            }

            bool Acquire(int milliseconds)
            {
                try { return mutex.WaitOne(milliseconds); }
                catch (AbandonedMutexException) { return true; }
            }

            internal void Listen(Dispatcher dispatcher, Action show)
            {
                if (listener != null) return;
                listener = ThreadPool.RegisterWaitForSingleObject(activate, delegate {
                    if (disposed || dispatcher.HasShutdownStarted) return;
                    try
                    {
                        dispatcher.BeginInvoke(new Action(delegate {
                            if (disposed || dispatcher.HasShutdownStarted) return;
                            try { show(); } catch (InvalidOperationException) { }
                        }));
                    }
                    catch (InvalidOperationException) { }
                }, null, Timeout.Infinite, false);
            }

            public void Dispose()
            {
                disposed = true;
                if (listener != null) listener.Unregister(null);
                if (IsOwner) mutex.ReleaseMutex();
                mutex.Dispose(); activate.Dispose();
            }
        }

        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern IntPtr GetDC(IntPtr window);
        [System.Runtime.InteropServices.DllImport("user32.dll")] static extern int ReleaseDC(IntPtr window, IntPtr dc);
        [System.Runtime.InteropServices.DllImport("gdi32.dll")] static extern int GetDeviceCaps(IntPtr dc, int index);

        static int? ScreenRefreshRate()
        {
            IntPtr dc = GetDC(IntPtr.Zero);
            if (dc == IntPtr.Zero) return 60;
            try { int hz = GetDeviceCaps(dc, 116); return hz >= 50 && hz <= 360 ? hz : 60; } // 116 = VREFRESH; 0/1 mean "hardware default"
            finally { ReleaseDC(IntPtr.Zero, dc); }
        }

        static Assembly LoadEmbedded(object sender, ResolveEventArgs args)
        {
            if (new AssemblyName(args.Name).Name != "Wpf.Ui") return null;
            using (Stream stream = typeof(App).Assembly.GetManifestResourceStream("Wpf.Ui.dll"))
            {
                if (stream == null) return null;
                byte[] bytes = new byte[stream.Length];
                stream.Read(bytes, 0, bytes.Length);
                return Assembly.Load(bytes);
            }
        }
    }
}
