using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using WindowsClaude.Launcher;

namespace WindowsClaude.Launcher { public partial class App : Application { } }
internal static class Bridge
{
    internal static string Root { get { return AppDomain.CurrentDomain.BaseDirectory; } }
    internal static readonly List<string> Calls = new List<string>();
    internal static Func<string, object, Task<Dictionary<string, object>>> Handler;
    internal static Task<Dictionary<string, object>> RunAsync(string root, string action, object payload) { Calls.Add(action); return Handler(action, payload); }
    internal static Task<Dictionary<string, object>> PendingOperation(Dictionary<string, object> result) { return result.ContainsKey("pending_test") ? (Task<Dictionary<string, object>>)result["pending_test"] : null; }
    internal static bool Ok(Dictionary<string, object> result) { return result != null && result.ContainsKey("ok") && (bool)result["ok"]; }
    internal static string Message(Dictionary<string, object> result) { return result != null && result.ContainsKey("message") ? (string)result["message"] : "Ответ не получен."; }
    internal static Dictionary<string, object> Failure(string message) { return new Dictionary<string, object> { { "ok", false }, { "message", message } }; }
    internal static Dictionary<string, object> Unknown(string message, string code) { var result = Failure(message); result["outcome_unknown"] = true; return result; }
    internal static string Quote(string value) { return "\"" + value + "\""; }
}
internal static class LauncherLifecycleRegression
{
    static int checks;
    static void Assert(bool condition, string message) { if (!condition) throw new Exception(message); ++checks; }
    static object Field(object obj, string name) { return obj.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.Public).GetValue(obj); }
    static void Set(object obj, string name, object value) { obj.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic).SetValue(obj, value); }
    static object Call(object obj, string name, params object[] args) { return obj.GetType().GetMethod(name, BindingFlags.Instance | BindingFlags.NonPublic | BindingFlags.DeclaredOnly).Invoke(obj, args); }
    static void Pump(Func<bool> done)
    {
        var frame = new DispatcherFrame(); var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(5) };
        DateTime until = DateTime.UtcNow.AddSeconds(10);
        timer.Tick += delegate { if (done() || DateTime.UtcNow >= until) frame.Continue = false; };
        timer.Start(); Dispatcher.PushFrame(frame); timer.Stop(); Assert(done(), "async operation settled");
    }
    static Dictionary<string, object> Report(string work = "stopped", string network = "stopped", bool recover = false, bool force = false)
    {
        return new Dictionary<string, object> { { "ok", !recover }, { "message", "Готово" }, { "checks", new Dictionary<string, object>() },
            { "runtime", new Dictionary<string, object> { { "work", work }, { "gateway", network } } },
            { "connection", new Dictionary<string, object> { { "applied_profile_id", "" } } },
            { "capabilities", new Dictionary<string, object> { { "stop", work != "stopped" || network != "stopped" }, { "recover_session", recover }, { "force_stop", force } } },
            { "settings", new Dictionary<string, object> { { "work_memory_mib", 4096 }, { "vcpus", 2 } } } };
    }
    static MainWindow Window()
    {
        Bridge.Calls.Clear(); Bridge.Handler = (action, payload) => Task.FromResult(Report());
        var window = new MainWindow(); Call(window, "Display", Report()); return window;
    }
    [STAThread] static int Main()
    {
        try
        {
            var app = new App(); app.InitializeComponent();
            var window = Window(); Call(window, "Busy", true);
            Assert(!((StackPanel)Field(window, "SettingsBody")).IsEnabled, "settings locked during save");
            Call(window, "Busy", false);
            var save = new TaskCompletionSource<Dictionary<string, object>>();
            Bridge.Handler = (action, payload) => action == "save-settings" ? save.Task : Task.FromResult(Report());
            ((TextBox)Field(window, "MemoryInput")).Text = "6";
            Call(window, "OnStart", null, new RoutedEventArgs()); Call(window, "OnStart", null, new RoutedEventArgs());
            Assert(Bridge.Calls.Count == 1 && Bridge.Calls[0] == "save-settings", "start awaits one dirty save");
            var saved = Report(); saved["settings"] = new Dictionary<string, object> { { "work_memory_mib", 6144 }, { "vcpus", 2 } };
            save.SetResult(saved); Pump(() => Bridge.Calls.Contains("start"));
            Assert(Bridge.Calls.FindAll(action => action == "start").Count == 1, "start happens once after save");
            window = Window(); ((TextBox)Field(window, "MemoryInput")).Text = "6";
            var older = new TaskCompletionSource<Dictionary<string, object>>(); object latestPayload = null;
            Bridge.Handler = (action, payload) => action == "save-settings" ? older.Task : Task.FromResult(Report());
            var saving = (Task<bool>)Call(window, "SaveSettingsAsync"); Call(window, "OnStart", null, new RoutedEventArgs());
            ((TextBox)Field(window, "MemoryInput")).Text = "8";
            var latest = Report(); latest["settings"] = new Dictionary<string, object> { { "work_memory_mib", 8192 }, { "vcpus", 2 } };
            Bridge.Handler = (action, payload) => { if (action == "save-settings") latestPayload = payload; return Task.FromResult(latest); };
            older.SetResult(saved); Pump(() => Bridge.Calls.Contains("start"));
            Assert(((TextBox)Field(window, "MemoryInput")).Text == "8" && Convert.ToInt32(((Dictionary<string, object>)latestPayload)["work_memory_mib"]) == 8192, "stale save cannot overwrite newer edits");
            window = Window(); ((TextBox)Field(window, "MemoryInput")).Text = "bad";
            var closing = new CancelEventArgs(); Call(window, "OnClosing", window, closing); Pump(() => !(bool)Field(window, "closePending"));
            Assert(closing.Cancel && !(bool)Field(window, "closing") && ((TextBox)Field(window, "MemoryInput")).Text == "bad", "invalid input keeps panel and input");
            window = Window(); ((TextBox)Field(window, "MemoryInput")).Text = "6";
            var closeSave = new TaskCompletionSource<Dictionary<string, object>>();
            Bridge.Handler = (action, payload) => closeSave.Task;
            Call(window, "OnClosing", window, new CancelEventArgs()); Pump(() => Bridge.Calls.Contains("save-settings"));
            Assert(!(bool)Field(window, "closing"), "closing awaits persistence");
            closeSave.SetResult(Bridge.Failure("settings locked")); Pump(() => !(bool)Field(window, "closePending"));
            Call(window, "Display", Report());
            Assert(!(bool)Field(window, "closing") && ((TextBlock)Field(window, "SettingsNote")).Text == "settings locked", "save error remains actionable after refresh");
            window = Window(); ((TextBox)Field(window, "MemoryInput")).Text = "6";
            var successfulCloseSave = new TaskCompletionSource<Dictionary<string, object>>();
            Bridge.Handler = (action, payload) => action == "save-settings" ? successfulCloseSave.Task : Task.FromResult(Report());
            Call(window, "OnClosing", window, new CancelEventArgs()); Pump(() => Bridge.Calls.Contains("save-settings"));
            Assert(!(bool)Field(window, "closing"), "successful close still waits for dirty settings");
            successfulCloseSave.SetResult(saved); Pump(() => (bool)Field(window, "closing"));
            window = Window();
            Call(window, "Display", Report("running", "stopped"));
            Assert((bool)Field(window, "ready") && AttentionPolicy.Classify(true, "running", "stopped", false, false) == null, "offline Linux keeps its original no-network attention policy");
            var stop = new TaskCompletionSource<Dictionary<string, object>>();
            Bridge.Handler = (action, payload) => action == "stop" ? stop.Task : Task.FromResult(Report());
            var first = (Task<bool>)Call(window, "StopSessionAsync", true);
            var duplicate = (Task<bool>)Call(window, "StopSessionAsync", false);
            Assert(Bridge.Calls.FindAll(action => action == "stop").Count == 1 && !(bool)Field(window, "closing"), "stop and tray exit share one awaited operation");
            stop.SetResult(Bridge.Failure("shutdown unconfirmed")); Pump(() => first.IsCompleted && duplicate.IsCompleted);
            Assert(!first.Result && !(bool)Field(window, "closing"), "failed stop cannot exit despite stopped followup report");
            Assert(((string)Field(window, "reportText")).Contains("shutdown unconfirmed"), "stop failure remains in diagnostics");
            Call(window, "Display", Report("running", "stopped"));
            Bridge.Handler = (action, payload) => Task.FromResult(Report());
            var stopped = (Task<bool>)Call(window, "StopSessionAsync", true); Pump(() => stopped.IsCompleted && (bool)Field(window, "closing"));
            Assert(stopped.Result, "tray exits after confirmed Linux and network stop");
            window = Window(); Call(window, "Display", Report("failed", "running", true));
            var recovered = (Task<bool>)Call(window, "StopSessionAsync", false); Pump(() => recovered.IsCompleted);
            Assert(Bridge.Calls.Contains("recover-session") && !Bridge.Calls.Contains("stop"), "fresh recovery capability selects interrupted-session recovery");
            window = Window(); Call(window, "Display", Report("running", "stopped"));
            var pending = new TaskCompletionSource<Dictionary<string, object>>();
            var unknown = Bridge.Unknown("stop pending", "timeout"); unknown["pending_test"] = pending.Task;
            Bridge.Handler = (action, payload) => Task.FromResult(action == "stop" ? unknown : Report());
            var unconfirmed = (Task<bool>)Call(window, "StopSessionAsync", true); Pump(() => unconfirmed.IsCompleted);
            var retry = (Task<bool>)Call(window, "StopSessionAsync", true); Pump(() => retry.IsCompleted);
            Assert(!unconfirmed.Result && !retry.Result && Bridge.Calls.FindAll(action => action == "stop").Count == 1, "pending backend stop cannot duplicate or exit");
            window = Window();
            var forceReport = Report("shutdown-unconfirmed", "running", false, true);
            var session = new Dictionary<string, object> { { "nonce", "fresh" }, { "work", new Dictionary<string, object> { { "pid", 123 }, { "created", "456" }, { "image", "qemu.exe" } } },
                { "supervisor", new Dictionary<string, object> { { "pid", 124 }, { "created", "457" }, { "image", "python.exe" } } } };
            forceReport["force_stop_session"] = session; Call(window, "Display", forceReport);
            var trayItems = (TrayMenu.Item[])Call(window, "TrayItems");
            Assert(trayItems.Length == 3 && trayItems[2].Text == "Выключить Linux и выйти", "Linux tray has three explicit actions");
            Assert(((Button)Field(window, "ForceStopButton")).Visibility == Visibility.Visible, "force is separate and capability gated");
            var cancel = (Task)Call(window, "ForceStopConfirmedAsync", false); Pump(() => cancel.IsCompleted);
            Assert(!Bridge.Calls.Contains("force-stop"), "No confirmation performs no backend action");
            object forcePayload = null;
            Bridge.Handler = (action, payload) => { if (action == "force-stop") forcePayload = payload; return Task.FromResult(Report()); };
            var latestSession = new Dictionary<string, object>(session); latestSession["nonce"] = "latest";
            forceReport["force_stop_session"] = latestSession; Call(window, "Display", forceReport);
            var forced = (Task)Call(window, "ForceStopConfirmedAsync", true); Pump(() => forced.IsCompleted);
            Assert((bool)((Dictionary<string, object>)forcePayload)["confirmed"] && Object.ReferenceEquals(((Dictionary<string, object>)forcePayload)["session"], latestSession), "force sends the exact current Linux session token");
            Call(window, "Display", forceReport);
            var polledSession = new Dictionary<string, object>(session); polledSession["nonce"] = "polled";
            var tokenOnly = Report("shutdown-unconfirmed", "running", false, true); tokenOnly["force_stop_session"] = polledSession;
            Bridge.Handler = (action, payload) => Task.FromResult(tokenOnly);
            var tokenPoll = (Task)Call(window, "RefreshRuntimeAsync"); Pump(() => tokenPoll.IsCompleted);
            Bridge.Handler = (action, payload) => { if (action == "force-stop") forcePayload = payload; return Task.FromResult(Report()); };
            var tokenForce = (Task)Call(window, "ForceStopConfirmedAsync", true); Pump(() => tokenForce.IsCompleted);
            Assert(Object.ReferenceEquals(((Dictionary<string, object>)forcePayload)["session"], polledSession), "token-only status polling replaces the stale force session");
            Call(window, "Display", forceReport);
            var capabilityOnly = Report("shutdown-unconfirmed", "running"); capabilityOnly["force_stop_session"] = null;
            Bridge.Handler = (action, payload) => Task.FromResult(capabilityOnly);
            var polled = (Task)Call(window, "RefreshRuntimeAsync"); Pump(() => polled.IsCompleted);
            Assert(((Button)Field(window, "ForceStopButton")).Visibility == Visibility.Collapsed, "poll updates capability without runtime state change");
            window = Window(); Assert(((Button)Field(window, "StartButton")).IsEnabled, "no profile leaves offline Linux ready to start");
            Assert(((TextBlock)Field(window, "NextStepText")).Text.Contains("без интернета"), "offline launch explains that no network will be started");
            var connected = Report();
            connected["connection"] = new Dictionary<string, object> { { "selected_profile", new Dictionary<string, object> { { "name", "Test" }, { "protocol", "socks5" } } } };
            Call(window, "Display", connected);
            Assert(((TextBlock)Field(window, "NextStepText")).Text.Contains("защищённое подключение"), "selected profile keeps the network startup explanation");
            var offlineRunning = Report("running", "stopped"); offlineRunning["network_warning"] = "Linux запущен без интернета.";
            Call(window, "Display", offlineRunning);
            Assert(((TextBlock)Field(window, "NetworkText")).Text.Contains("без интернета"), "offline session does not ask to repair a nonexistent connection");
            ((Dictionary<string, object>)offlineRunning["connection"])["applied_profile_id"] = "selected";
            Call(window, "Display", offlineRunning);
            Assert(((TextBlock)Field(window, "NetworkText")).Text.Contains("Проверь подключение"), "failed applied connection still explains the required check");
            Bridge.Calls.Clear(); Call(window, "OnUpdate", null, new RoutedEventArgs()); Call(window, "OnCheckUpdates", null, new RoutedEventArgs());
            Assert(Bridge.Calls.Count == 0 && !((Button)Field(window, "CheckUpdatesButton")).IsEnabled && ((Button)Field(window, "InstallUpdateButton")).Visibility == Visibility.Collapsed, "Linux updater remains disabled");
            foreach (string action in new[] { "stop", "recover-session" })
            {
                window = Window(); Call(window, "Display", action == "stop" ? Report("running", "stopped") : Report("failed", "running", true));
                Bridge.Handler = (name, payload) => name == "diagnose" ? Task.FromException<Dictionary<string, object>>(new System.IO.IOException("status unavailable")) : Task.FromResult(new Dictionary<string, object> { { "ok", true }, { "message", "stopped" } });
                var settled = (Task<bool>)Call(window, "StopSessionAsync", false); Pump(() => settled.IsCompleted);
                Assert(!(bool)Field(window, "outcomeUnknown") && ((string)Field(window, "reportText")).Contains("status unavailable"), "settled action keeps its result when followup status fails");
                Bridge.Handler = (name, payload) => Task.FromResult(Report());
                var diagnosed = (Task<bool>)Call(window, "RunAction", "diagnose", false, null); Pump(() => diagnosed.IsCompleted);
                Assert(((Button)Field(window, "StartButton")).IsEnabled, "later status restores launch controls");
            }
            Call(window, "Display", forceReport);
            foreach (double scale in new[] { 1.0, 1.25, 1.5, 2.0 })
            {
                var root = (FrameworkElement)window.Content;
                root.Measure(new Size(744, 418)); root.Arrange(new Rect(0, 0, 744, 418)); root.UpdateLayout();
                var card = (FrameworkElement)Field(window, "LaunchCard");
                foreach (string name in new[] { "StatusText", "NextStepText", "StopButton", "ForceStopButton" })
                {
                    var part = (FrameworkElement)Field(window, name);
                    var bounds = part.TransformToAncestor(card).TransformBounds(new Rect(part.RenderSize));
                    Assert(bounds.Top >= 0 && bounds.Bottom <= card.ActualHeight + 1, name + " fits at DPI " + scale);
                    for (DependencyObject parent = part; parent != card; parent = VisualTreeHelper.GetParent(parent)) Assert(!(parent is Viewbox), name + " text never scales");
                }
                var image = new RenderTargetBitmap((int)(744 * scale), (int)(418 * scale), 96 * scale, 96 * scale, PixelFormats.Pbgra32); image.Render(root);
                Assert(image.PixelWidth == (int)(744 * scale), "native DPI render");
            }
            Console.WriteLine("PASS Linux launcher lifecycle: " + checks + " checks"); return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
