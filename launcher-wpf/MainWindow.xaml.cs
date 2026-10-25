using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Threading;
using Wpf.Ui.Controls;
using TextBlock = System.Windows.Controls.TextBlock;
using Forms = System.Windows.Forms;

namespace WindowsClaude.Launcher
{
    public enum AppPage { Home, Connection, Settings, Diagnostics, Updates, Help }

    // Same state rules as the WinForms launcher (ui/Launcher.cs): an unconfirmed operation blocks
    // everything except diagnostics, the panel hides to the tray while Windows runs, status polls every 3 s.
    public partial class MainWindow : FluentWindow
    {
        static readonly Brush Green = Hex("#34C759"), GreenSoft = Hex("#E3F7E8"), GreenInk = Hex("#1E7A36"),
            Blue = Hex("#3390EC"), BlueSoft = Hex("#E9F2FD"), BlueInk = Hex("#1C5A9A"),
            Grey = Hex("#8A8A8E"), GreySoft = Hex("#EDEDF0"), Orange = Hex("#FF9500"), Red = Hex("#E53935"), Ink = Hex("#1C1C1E");
        static readonly int[,] Modes = { { 800, 600 }, { 1024, 768 }, { 1280, 720 }, { 1280, 800 }, { 1366, 768 }, { 1440, 900 },
            { 1600, 900 }, { 1680, 1050 }, { 1920, 1080 }, { 1920, 1200 }, { 2560, 1440 } };
        const int DefaultMode = 8;
        static readonly string[] Protocols = { "hysteria2", "socks5", "http", "https" };

        readonly DispatcherTimer lifecycleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        readonly DispatcherTimer saveTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(700) };
        readonly DispatcherTimer toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(6) };
        readonly Border[] stepCards = new Border[4];
        readonly TextBlock[] stepTexts = new TextBlock[4];
        readonly Ellipse[] stepDots = new Ellipse[4];
        Forms.NotifyIcon trayIcon;

        Dictionary<string, object> readinessReport, operationResult, settingsHost, originalSettings, originalWindows, originalViewer, originalFiles;
        Task<Dictionary<string, object>> pendingOutcome;
        string pendingStartReceipt, activeOperationAction, workState = "unknown", gatewayState = "unknown", suggestedAction = "retry", reportText = "", displayedChecks;
        bool busy, ready, outcomeUnknown, stopAvailable, testAvailable, runtimeActive, runtimePolling, closing,
            panelHiddenForSession, panelDismissedByUser, settingsLoaded, profilesLoaded, applyingSettings, checksOpen, pulsing;
        int operationRevision, attentionPolls; string shownStatus, lastAttention;
        bool trayNoticeShown, displayNoticeShown, attentionNoticeShown, trayPromotionStarted;
        readonly List<string> folders = new List<string>();

        // Connection editor state
        string profileId, loadedProtocol, loadedObfs; bool authPresent;
        List<Dictionary<string, object>> profiles = new List<Dictionary<string, object>>();

        static Brush Hex(string value) { var brush = (Brush)new BrushConverter().ConvertFromString(value); brush.Freeze(); return brush; }
        static bool Flag(Dictionary<string, object> item, string key) { return item != null && item.ContainsKey(key) && item[key] is bool && (bool)item[key]; }
        static string Text(Dictionary<string, object> value, string key, string fallback) { return value != null && value.ContainsKey(key) && value[key] != null ? Convert.ToString(value[key], CultureInfo.InvariantCulture) : fallback; }
        static Dictionary<string, object> Child(Dictionary<string, object> value, string key) { return value != null && value.ContainsKey(key) ? value[key] as Dictionary<string, object> : null; }
        static Task<Dictionary<string, object>> Run(string action, object payload) { return Bridge.RunAsync(Bridge.Root, action, payload); }
        static void Show(UIElement element, bool visible) { element.Visibility = visible ? Visibility.Visible : Visibility.Collapsed; }
        static readonly IEasingFunction EaseOut = new CubicEase { EasingMode = EasingMode.EaseOut };

        // Fade in while sliding up a little; used for the window parts, list rows and status changes.
        // Never replaces another transform: buttons keep the ScaleTransform their press animation targets.
        static void Rise(UIElement element, double delayMs)
        {
            var begin = TimeSpan.FromMilliseconds(delayMs);
            element.Opacity = 0;
            element.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(320)) { BeginTime = begin, EasingFunction = EaseOut });
            var shift = element.RenderTransform as TranslateTransform;
            if (shift == null && element.RenderTransform != null && element.RenderTransform != Transform.Identity) return;
            if (shift == null || shift.IsFrozen) { shift = new TranslateTransform(); element.RenderTransform = shift; }
            shift.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(12, 0, TimeSpan.FromMilliseconds(380)) { BeginTime = begin, EasingFunction = EaseOut });
        }

        public MainWindow()
        {
            InitializeComponent();
            string[] steps = { "Сеть", "Интернет", "Linux", "Файлы" };
            for (int index = 0; index < 4; index++)
            {
                stepDots[index] = new Ellipse { Width = 7, Height = 7, Margin = new Thickness(0, 0, 5, 0), VerticalAlignment = VerticalAlignment.Center };
                stepTexts[index] = new TextBlock { Text = steps[index], FontSize = 12, VerticalAlignment = VerticalAlignment.Center };
                stepCards[index] = new Border { CornerRadius = new CornerRadius(10), Padding = new Thickness(4, 5, 4, 5), Margin = new Thickness(2),
                    Child = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, Children = { stepDots[index], stepTexts[index] } } };
                Steps.Children.Add(stepCards[index]);
            }
            BuildHelp();
            for (int index = 0; index < Modes.GetLength(0); index++) ResolutionBox.Items.Add(Modes[index, 0] + " × " + Modes[index, 1]);
            VersionText.Text = ReleaseInfo.Read(Bridge.Root).DisplayText;
            UpdateCaption.Text = VersionText.Text;

            InputBindings.Add(new KeyBinding(new Command(() => Navigate(AppPage.Connection)), Key.D2, ModifierKeys.Control));
            InputBindings.Add(new KeyBinding(new Command(() => Navigate(AppPage.Help)), Key.F1, ModifierKeys.None));
            InputBindings.Add(new KeyBinding(new Command(OnEscape), Key.Escape, ModifierKeys.None));
            InputBindings.Add(new KeyBinding(new Command(() => { var task = RunAction("diagnose", true); }), Key.F5, ModifierKeys.None));
            InputBindings.Add(new KeyBinding(new Command(() => {
                if (OpenDesktopButton.IsVisible && OpenDesktopButton.IsEnabled) OnOpenDesktop(null, null);
                else if (StartButton.IsVisible && StartButton.IsEnabled) OnStart(null, null);
            }), Key.Enter, ModifierKeys.Control));

            saveTimer.Tick += async delegate { if (busy) return; saveTimer.Stop(); await SaveSettingsAsync(); };
            toastTimer.Tick += delegate { toastTimer.Stop(); if (!busy) HideToast(); };
            ProtocolBox.SelectedIndex = 1; NewProfile(); Show(FoldersRow, false);
            Busy(false);
            // Fixed window: WPF-UI's chrome still reports resize edges, so turn them into plain client area.
            Loaded += async delegate
            {
                var chrome = System.Windows.Shell.WindowChrome.GetWindowChrome(this);
                if (chrome != null) chrome.ResizeBorderThickness = new Thickness(0);
                Rise(LaunchCard, 0); Rise(HomePage, 90);
                StartLifecycle(); StartShopNudge(); await RunAction("diagnose", false); StartUpdateCheck();
            };
            Closing += OnClosing;
        }

        sealed class Command : ICommand
        {
            readonly Action action; public Command(Action action) { this.action = action; }
            public event EventHandler CanExecuteChanged { add { } remove { } }
            public bool CanExecute(object parameter) { return true; }
            public void Execute(object parameter) { action(); }
        }

        static Border KeyCap(string text)
        {
            return new Border { Background = GreySoft, CornerRadius = new CornerRadius(7), Padding = new Thickness(8, 3, 8, 3), VerticalAlignment = VerticalAlignment.Center,
                Child = new TextBlock { Text = text, FontSize = 12.5, Foreground = Ink } };
        }

        void BuildHelp()
        {
            var keys = new[] { new[] { "Ctrl+Enter", "Запустить или открыть Linux" }, new[] { "Ctrl+Alt+F", "Полный экран и обратно" },
                new[] { "Ctrl+Alt+G", "Освободить мышь" }, new[] { "Ctrl+2", "Подключение" }, new[] { "F5", "Проверить снова" }, new[] { "Esc", "Закрыть лист" } };
            for (int index = 0; index < keys.Length; index++)
            {
                if (index > 0) HelpRows.Children.Add(new Border { Style = (Style)FindResource("Separator"), Margin = new Thickness(16, 0, 0, 0) });
                var row = new DockPanel { Margin = new Thickness(16, 9, 16, 9) };
                var cap = KeyCap(keys[index][0]); DockPanel.SetDock(cap, Dock.Right); row.Children.Add(cap);
                row.Children.Add(new TextBlock { Text = keys[index][1], Style = (Style)FindResource("RowText") });
                HelpRows.Children.Add(row);
            }
        }

        // ---------- Home list, pages over it, and the modal card ----------
        AppPage currentPage = AppPage.Home;

        void Navigate(AppPage page)
        {
            if (page == AppPage.Help) { OpenSheet("Клавиши", HelpSheet); return; }
            CloseSheet();
            ShowPage(page);
        }

        // Pages slide over the home list like iOS; "Назад" returns.
        void ShowPage(AppPage page)
        {
            checksOpen = page == AppPage.Diagnostics;
            if (page == AppPage.Connection && !profilesLoaded && !busy) { var task = LoadProfilesAsync(); }
            if (page == currentPage) return;
            bool forward = currentPage == AppPage.Home;
            currentPage = page;
            if (page != AppPage.Home)
            {
                PageTitle.Text = page == AppPage.Connection ? "Подключения" : page == AppPage.Settings ? "Характеристики" : page == AppPage.Updates ? "Обновления" : "Проверка";
                Show(ConnectionsPane, page == AppPage.Connection); Show(SettingsPane, page == AppPage.Settings); Show(ChecksPanel, page == AppPage.Diagnostics);
                Show(UpdatesPane, page == AppPage.Updates);
                Show(RefreshButton, page == AppPage.Diagnostics);
            }
            if (page != AppPage.Home && !forward) return; // page to page: content already swapped
            // iOS push: the outgoing layer drifts a little and fades, the incoming one slides in from its side.
            bool toPage = page != AppPage.Home;
            UIElement incoming = toPage ? (UIElement)PageHost : HomePage, outgoing = toPage ? (UIElement)HomePage : PageHost;
            Slide(outgoing, 0, toPage ? -40 : 90, 1, 0, 200, () => { if ((currentPage != AppPage.Home) == toPage) Show(outgoing, false); });
            Show(incoming, true); incoming.IsHitTestVisible = true; outgoing.IsHitTestVisible = false;
            Slide(incoming, toPage ? 90 : -40, 0, 0, 1, 340, null);
        }

        static void Slide(UIElement element, double fromX, double toX, double fromOpacity, double toOpacity, int ms, Action done)
        {
            var shift = element.RenderTransform as TranslateTransform;
            if (shift == null || shift.IsFrozen) { shift = new TranslateTransform(); element.RenderTransform = shift; }
            var ease = new QuinticEase { EasingMode = EasingMode.EaseOut };
            var move = new DoubleAnimation(fromX, toX, TimeSpan.FromMilliseconds(ms)) { EasingFunction = ease };
            var fade = new DoubleAnimation(fromOpacity, toOpacity, TimeSpan.FromMilliseconds(ms)) { EasingFunction = ease };
            if (done != null) fade.Completed += delegate { done(); };
            shift.BeginAnimation(TranslateTransform.XProperty, move);
            element.BeginAnimation(OpacityProperty, fade);
        }

        void OpenSheet(string title, UIElement content)
        {
            foreach (var part in new UIElement[] { AddSheet, EditorSheet, ExportSheet, HelpSheet }) Show(part, part == content);
            SheetTitle.Text = title;
            if (SheetHost.Visibility == Visibility.Visible) { content.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200))); return; }
            Show(SheetHost, true);
            SheetDim.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
            Sheet.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
            ((TranslateTransform)Sheet.RenderTransform).BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(24, 0, TimeSpan.FromMilliseconds(240)) { EasingFunction = EaseOut });
        }

        void ShowEditor(string title) { Show(EditorExtras, profileId != null); OpenSheet(title, EditorSheet); }

        void CloseSheet()
        {
            if (SheetHost.Visibility != Visibility.Visible) return;
            var fade = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(160));
            fade.Completed += delegate { Show(SheetHost, false); };
            SheetDim.BeginAnimation(OpacityProperty, new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(160)));
            Sheet.BeginAnimation(OpacityProperty, fade);
        }

        void OnEscape() { if (SheetHost.Visibility == Visibility.Visible) CloseSheet(); else ShowPage(AppPage.Home); }
        void OnCloseSheet(object sender, RoutedEventArgs e) { CloseSheet(); }
        void OnDimClick(object sender, MouseButtonEventArgs e) { CloseSheet(); }
        void OnBack(object sender, RoutedEventArgs e) { ShowPage(AppPage.Home); }
        void OnConnectionRow(object sender, RoutedEventArgs e) { Navigate(AppPage.Connection); }
        void OnSettingsRow(object sender, RoutedEventArgs e) { Navigate(AppPage.Settings); }
        void OnChecksRow(object sender, RoutedEventArgs e) { Navigate(AppPage.Diagnostics); if (readinessReport == null && !busy) { var task = RunAction("diagnose", false); } }
        void OnHelp(object sender, RoutedEventArgs e) { Navigate(AppPage.Help); }
        // The link is pasted once, so it lives in the card, not on the page.
        void OnAddRow(object sender, RoutedEventArgs e) { ProfileErrorText(""); OpenSheet("Новое подключение", AddSheet); LinkInput.Focus(); }

        void UpdateAddRows() { Show(AddSeparator, profiles.Count > 0); }

        void UpdateWindowsSummary()
        {
            WindowsSummary.Text = MemoryInput.Text + " ГиБ памяти, " + CpuInput.Text + " ЦП, экран " + (ResolutionBox.SelectedItem ?? "") + (FilesSwitch.IsChecked == true ? ", файлы ПК" : "");
        }
        // ---------- Toast ----------
        void SetOperation(string text)
        {
            OperationText.Text = text ?? "";
            if (String.IsNullOrEmpty(text)) { HideToast(); return; }
            Show(ToastClose, !busy);
            if (OperationBar.Visibility != Visibility.Visible || OperationBar.Opacity < 1)
            {
                Show(OperationBar, true);
                OperationBar.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
                ((TranslateTransform)OperationBar.RenderTransform).BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(24, 0, TimeSpan.FromMilliseconds(240)) { EasingFunction = EaseOut });
            }
            toastTimer.Stop(); if (!busy) toastTimer.Start();
        }
        void HideToast()
        {
            if (OperationBar.Visibility != Visibility.Visible) return;
            var fade = new DoubleAnimation(0, TimeSpan.FromMilliseconds(180)); fade.Completed += delegate { if (OperationText.Text.Length == 0 || !busy) Show(OperationBar, false); };
            OperationBar.BeginAnimation(OpacityProperty, fade);
        }
        void OnDismissToast(object sender, RoutedEventArgs e) { toastTimer.Stop(); HideToast(); }

        // ---------- Operations ----------
        bool BeginOperation(string action)
        {
            if (closing || busy) return false;
            if (outcomeUnknown && action != "diagnose" && action != "recover-session")
            {
                SetOperation("Предыдущая операция ещё не подтверждена. Сначала нажми «Проверить снова».");
                return false;
            }
            activeOperationAction = action; operationRevision++;
            Busy(true);
            switch (action)
            {
                case "start": SetOperation("Запускаем подключение и Linux…"); break;
                case "stop": SetOperation("Выключаем Linux… Дождись штатного выключения."); break;
                case "repair-gateway": SetOperation("Восстанавливаем компоненты из комплекта…"); break;
                case "recover-session": SetOperation("Восстанавливаем прерванный сеанс… Диск Linux и подключения сохраняются."); break;
                case "prepare-host": SetOperation("Проверяем переносимый запуск на этом ПК…"); break;
                case "prepare-components": SetOperation("Восстанавливаем Python и QEMU…"); break;
                case "save-settings": SetOperation("Сохраняем…"); break;
                case "list-profiles": case "get-profile-view": SetOperation("Загружаем подключения…"); break;
                case "save-profile": case "import-profile": SetOperation("Сохраняем подключение…"); break;
                case "select-profile": SetOperation("Выбираем подключение…"); break;
                case "test-profile": SetOperation("Проверяем подключение… Это займёт до пары минут."); break;
                case "export-profile": SetOperation("Экспортируем подключение…"); break;
                default: SetOperation("Проверяем готовность…"); break;
            }
            return true;
        }

        void Busy(bool value)
        {
            busy = value; Show(BusyRing, value); BusyRing.IsIndeterminate = value; // a hidden indeterminate ring keeps animating
            Show(ToastClose, !value);
            if (!value && OperationText.Text.Length > 0) { toastTimer.Stop(); toastTimer.Start(); }
            foreach (UIElement button in new UIElement[] { RefreshButton, PrepareButton, RepairGatewayButton, NextActionButton, AddLinkButton, SaveProfileButton, ProfileList })
                button.IsEnabled = !value;
            PrepareHostButton.IsEnabled = !value && !runtimeActive;
            TestProfileButton.IsEnabled = !value && testAvailable && profiles.Any(item => Flag(item, "selected"));
            ExportButton.IsEnabled = !value && profiles.Count > 0;
            SettingsBody.IsEnabled = settingsLoaded && !runtimeActive && !outcomeUnknown;
            ConnectionsPane.IsEnabled = true; EditorSheet.IsEnabled = true; AddSheet.IsEnabled = true;
            UpdateLaunchButtons(); UpdateTray(); UpdatePulse(); ShowUpdateOffer();
        }

        void UpdateLaunchButtons()
        {
            StartButton.IsEnabled = !busy && ready && !outcomeUnknown && !runtimeActive;
            Show(StartButton, !runtimeActive && !outcomeUnknown && workState != "running");
            Show(OpenDesktopButton, workState == "running");
            OpenDesktopButton.IsEnabled = !busy && !outcomeUnknown && workState == "running";
            Show(StatusGlyph, StartButton.Visibility != Visibility.Visible && OpenDesktopButton.Visibility != Visibility.Visible);
            Show(StopButton, stopAvailable);
            StopButton.IsEnabled = !busy && !outcomeUnknown && stopAvailable;
        }

        void UpdatePulse()
        {
            bool active = (busy && (activeOperationAction == "start" || activeOperationAction == "stop")) || workState == "starting" || workState == "stopping" || workState == "restarting";
            if (active == pulsing) return;
            pulsing = active;
            var scale = (ScaleTransform)Pulse.RenderTransform;
            if (!active) { Pulse.BeginAnimation(OpacityProperty, null); scale.BeginAnimation(ScaleTransform.ScaleXProperty, null); scale.BeginAnimation(ScaleTransform.ScaleYProperty, null); Pulse.Opacity = 0; return; }
            // The ring fades in from nothing and back to nothing, so the loop restart never shows as a pop.
            var period = TimeSpan.FromSeconds(2.2);
            var grow = new DoubleAnimation(0.8, 1.2, period) { RepeatBehavior = RepeatBehavior.Forever, EasingFunction = new SineEase { EasingMode = EasingMode.EaseOut } };
            scale.BeginAnimation(ScaleTransform.ScaleXProperty, grow); scale.BeginAnimation(ScaleTransform.ScaleYProperty, grow);
            var glow = new DoubleAnimationUsingKeyFrames { Duration = period, RepeatBehavior = RepeatBehavior.Forever };
            glow.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromPercent(0)));
            glow.KeyFrames.Add(new EasingDoubleKeyFrame(0.3, KeyTime.FromPercent(0.3), new SineEase { EasingMode = EasingMode.EaseInOut }));
            glow.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromPercent(1), new SineEase { EasingMode = EasingMode.EaseInOut }));
            Pulse.BeginAnimation(OpacityProperty, glow);
        }

        void TrackUnknownOutcome(Dictionary<string, object> result)
        {
            if (activeOperationAction == "diagnose" || activeOperationAction == "get-settings" || activeOperationAction == "list-profiles" || activeOperationAction == "get-profile-view") return;
            outcomeUnknown = true;
            if (pendingOutcome == null) pendingOutcome = Bridge.PendingOperation(result);
            if (activeOperationAction == "start" && result.ContainsKey("receipt")) pendingStartReceipt = Text(result, "receipt", "");
        }

        async Task RunAction(string action, bool selectDiagnostics)
        {
            if (!BeginOperation(action)) return;
            if (selectDiagnostics) Navigate(AppPage.Diagnostics);
            Dictionary<string, object> completed = null;
            try
            {
                completed = await Run(action, null);
                if (closing) return;
                if (action == "recover-session" && Bridge.Ok(completed)) { outcomeUnknown = false; pendingOutcome = null; pendingStartReceipt = null; }
                Display(completed);
                SetOperation(action == "diagnose" && completed.ContainsKey("checks") ? "" : Friendly(Bridge.Message(completed)));
                if (action == "prepare-components" || action == "prepare-host" || action == "repair-gateway" || action == "recover-session" || action == "stop" || action == "start")
                    await RefreshAfterAsync(completed);
                if (action == "prepare-host" && Flag(completed, "restart_required")) SetOperation("Подготовка завершена. Перезагрузи ПК самостоятельно, затем нажми «Проверить снова».");
                else if (action == "diagnose") CheckedAtText.Text = completed.ContainsKey("checks") ? "Проверено в " + DateTime.Now.ToString("HH:mm") : "Проверка не обновилась. Повтори.";
            }
            catch (Exception) { FailedAction(action, completed); }
            finally
            {
                if (!closing)
                {
                    Busy(false);
                    if (action == "start" && Bridge.Ok(completed) && ready && workState == "running" && !outcomeUnknown) HidePanelForSession("Linux started");
                    else if (panelHiddenForSession && (workState == "stopped" || workState == "failed" || outcomeUnknown || (action == "start" && !Bridge.Ok(completed)))) ShowPanelAutomatically("after " + action + ", work=" + workState);
                    UpdateTray();
                }
            }
        }

        void FailedAction(string action, Dictionary<string, object> completed)
        {
            if (closing) return;
            if (completed != null && Bridge.Ok(completed)) Display(Bridge.Unknown(Bridge.Message(completed) + " Не удалось обновить проверку. Проверь состояние повторно.", "diagnose_failed"));
            else if (action == "diagnose" || action == "get-settings") Display(Bridge.Failure("Не удалось выполнить проверку. Проверь доступ к папке и целостность компонентов."));
            else Display(Bridge.Unknown("Действие не подтверждено. Исход операции неизвестен. Нажми «Проверить снова».", "operation_failed"));
            SetOperation(Bridge.Message(operationResult));
            if (action == "diagnose") CheckedAtText.Text = "Проверка не обновилась. Повтори.";
        }

        async Task RefreshAfterAsync(Dictionary<string, object> completed)
        {
            if (closing || (!Bridge.Ok(completed) && !Flag(completed, "outcome_unknown"))) return;
            var check = await Run("diagnose", null);
            if (closing) return;
            Display(check);
            SetOperation(Friendly(Bridge.Message(completed)));
            CheckedAtText.Text = "Проверено в " + DateTime.Now.ToString("HH:mm");
        }

        // Supervisor messages are written for logs; the full text stays in the copied report.
        static string Friendly(string message)
        {
            if (message == null) return "";
            // Start results end with the receipt path on a second line; only the first line is for people.
            int lineEnd = message.IndexOf('\n'); if (lineEnd >= 0) message = message.Substring(0, lineEnd).TrimEnd();
            if (message.StartsWith("Supervisor", StringComparison.Ordinal))
                return "Linux не запустился: не удалось подключиться к серверу. Проверь подключение и нажми «Запустить» ещё раз.";
            return message;
        }

        void OnStart(object sender, RoutedEventArgs e) { CommitPendingSettings(); var task = RunAction("start", false); }
        void OnStop(object sender, RoutedEventArgs e) { if (stopAvailable) { var task = RunAction("stop", false); } }
        void OnOpenDesktop(object sender, RoutedEventArgs e) { var task = RunAction("show-desktop", false); }
        void OnRefresh(object sender, RoutedEventArgs e) { var task = RunAction("diagnose", true); }
        void OnPrepare(object sender, RoutedEventArgs e) { var task = RunAction("prepare-components", false); }
        void OnRepairGateway(object sender, RoutedEventArgs e) { var task = RunAction("repair-gateway", false); }
        void OnPrepareHost(object sender, RoutedEventArgs e) { var task = RunAction("diagnose", true); }
        void OnCopyReport(object sender, RoutedEventArgs e) { try { Clipboard.SetText(reportText); SetOperation("Отчёт скопирован."); } catch (Exception) { SetOperation("Не удалось скопировать отчёт. Попробуй ещё раз."); } }
        void OnNextAction(object sender, RoutedEventArgs e)
        {
            if (suggestedAction == "settings") Navigate(AppPage.Settings);
            else if (suggestedAction == "connection") Navigate(AppPage.Connection);
            else if (suggestedAction == "repair_gateway") { var task = RunAction("repair-gateway", false); }
            else if (suggestedAction == "recover_session") { var task = RunAction("recover-session", false); }
            else if (suggestedAction == "windows_features") { Navigate(AppPage.Diagnostics); SetOperation("Нажми «Подготовить этот ПК» в проверке. Потребуется UAC; перезагрузка выполняется вручную."); }
            else { var task = RunAction(suggestedAction == "prepare" ? "prepare-components" : "diagnose", suggestedAction != "prepare"); }
        }
        void OnShortcut(object sender, RoutedEventArgs e)
        {
            try { SetOperation("Ярлык создан: " + PortableEntry.CreateShortcut(Bridge.Root, Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory))); }
            catch (Exception error) { SetOperation(error.Message); }
        }

        // ---------- Report display ----------
        static bool ActiveVmState(string state)
        {
            return state == "starting" || state == "restarting" || state == "running" || state == "reconnecting" || state == "stopping"
                || state == "shutdown-unconfirmed" || state == "connection-failed" || state == "control-unavailable-guest-running" || state == "failed";
        }

        static string VmState(string state, bool gateway = false)
        {
            switch (state)
            {
                case "stopped": return "выключен";
                case "starting": return "запускается";
                case "restarting": return "перезагружается";
                case "running": return "работает";
                case "reconnecting": return "восстанавливает связь";
                case "connection-failed": return "ошибка подключения";
                case "control-unavailable-guest-running": return "работает без управления";
                case "shutdown-unconfirmed": return "выключение не подтверждено";
                case "failed": return "ошибка сеанса";
                case "stopping": return "выключается";
                default: return "состояние неизвестно";
            }
        }

        static string RuntimeHeading(string work, string gateway)
        {
            if (ActiveVmState(work)) return work == "failed" || work == "connection-failed" ? "Сеанс Linux требует проверки" : "Linux " + VmState(work);
            if (ActiveVmState(gateway)) return gateway == "connection-failed" ? "Ошибка подключения" : gateway == "failed" ? "Подключение требует проверки" : "Сеть " + VmState(gateway, true);
            return "Готово к запуску";
        }

        static string DisplayState(Dictionary<string, object> report) { return Text(Child(report, "windows_display"), "status", ""); }
        static string FileSharingState(Dictionary<string, object> report) { var files = Child(report, "host_files"); return files == null ? "" : Text(files, "status", ""); }

        Dictionary<string, object> MergeRuntimeStatus(Dictionary<string, object> update)
        {
            if (Text(update, "report_kind", "") != "runtime_status") return update;
            bool hasFullCheck = readinessReport != null && Text(readinessReport, "report_kind", "preflight") == "preflight";
            var result = readinessReport == null ? new Dictionary<string, object>() : new Dictionary<string, object>(readinessReport);
            foreach (var item in update)
                if (item.Key != "checks" && item.Key != "blockers" && item.Key != "ok" && item.Key != "message" && item.Key != "checked_utc" && item.Key != "gateway_version" && item.Key != "report_kind") result[item.Key] = item.Value;
            var checks = Child(result, "checks") != null ? new Dictionary<string, object>(Child(result, "checks")) : new Dictionary<string, object>();
            var liveChecks = Child(update, "checks");
            if (liveChecks != null) foreach (var item in liveChecks) checks[item.Key] = item.Value;
            if (!hasFullCheck) checks["full_check"] = new Dictionary<string, object> { { "passed", false }, { "title", "Нужна проверка комплекта" },
                { "detail", "Нажми «Проверить снова» перед запуском Linux." }, { "action", "retry" }, { "action_label", "Проверить комплект" } };
            var blockers = new List<Dictionary<string, object>>();
            foreach (var item in checks)
            {
                var check = item.Value as Dictionary<string, object>;
                if (check == null || Flag(check, "passed")) continue;
                var blocker = new Dictionary<string, object>(check); blocker["code"] = item.Key; blockers.Add(blocker);
            }
            result["checks"] = checks; result["blockers"] = blockers.ToArray(); result["ok"] = blockers.Count == 0;
            result["message"] = blockers.Count == 0 ? Bridge.Message(update) : Text(blockers[0], "title", "Нужна проверка");
            result["report_kind"] = hasFullCheck ? "preflight" : "runtime_status";
            var capabilities = Child(result, "capabilities");
            if (capabilities != null)
            {
                capabilities = new Dictionary<string, object>(capabilities);
                capabilities["test_profile"] = hasFullCheck && Flag(Child(checks, "gateway_package"), "passed") && Flag(Child(checks, "runtime_state"), "passed") && !Flag(capabilities, "stop");
                result["capabilities"] = capabilities;
            }
            return result;
        }

        static List<Dictionary<string, object>> Checks(Dictionary<string, object> result)
        {
            var checks = new List<Dictionary<string, object>>();
            var source = Child(result, "checks");
            if (source != null)
                foreach (var item in source)
                {
                    var check = item.Value as Dictionary<string, object>; if (check == null) continue;
                    var row = new Dictionary<string, object>(check); if (!row.ContainsKey("title")) row["title"] = item.Key; checks.Add(row);
                }
            return checks.OrderBy(item => Flag(item, "passed")).ToList();
        }

        void Display(Dictionary<string, object> result)
        {
            result = MergeRuntimeStatus(result);
            bool isReadiness = result.ContainsKey("checks");
            if (isReadiness)
            {
                readinessReport = result;
                if (!settingsLoaded && result.ContainsKey("settings")) LoadSettings(result);
                if (result.ContainsKey("host")) { settingsHost = Child(result, "host"); }
                ready = Bridge.Ok(result);
                if (pendingOutcome != null && pendingOutcome.IsCompleted) { outcomeUnknown = false; pendingOutcome = null; }
                var startup = Child(result, "startup");
                if (pendingStartReceipt != null && startup != null && Text(startup, "receipt", "") == pendingStartReceipt
                    && (Text(startup, "phase", "") == "ready" || (!Flag(startup, "supervisor_active") && (Text(startup, "phase", "") == "stopped" || Text(startup, "phase", "") == "error"))))
                { outcomeUnknown = false; pendingStartReceipt = null; }
                var capabilities = Child(result, "capabilities");
                stopAvailable = Flag(capabilities, "stop"); testAvailable = Flag(capabilities, "test_profile");
                var runtime = Child(result, "runtime");
                workState = Text(runtime, "work", "unknown"); gatewayState = Text(runtime, "gateway", "unknown");
                runtimeActive = ActiveVmState(workState) || ActiveVmState(gatewayState);
                var connection = Child(result, "connection");
                var selected = Child(connection, "selected_profile");
                if (selected == null) { ConnectionValue.Text = "Добавить подключение"; ConnectionDetail.Text = "Вставь ссылку от своего Proxy или купи ниже"; ProxyPrice.BeginAnimation(OpacityProperty, new DoubleAnimation(1, 0.55, TimeSpan.FromSeconds(1.6)) { AutoReverse = true, RepeatBehavior = RepeatBehavior.Forever, EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut } }); }
                else
                {
                    string protocol = Text(selected, "protocol", ""); protocol = protocol == "hysteria2" ? "Hysteria2" : protocol.ToUpperInvariant();
                    ConnectionValue.Text = Text(selected, "name", "Профиль");
                    ConnectionDetail.Text = protocol + ", " + (Flag(selected, "needs_credentials") ? "нужно ввести пароль заново" : Flag(connection, "selected_applied") ? "используется в этом сеансе" : "для следующего запуска");
                    ProxyPrice.BeginAnimation(OpacityProperty, null); ProxyPrice.Opacity = 1;
                }
            }
            else
            {
                operationResult = result;
                if (Flag(result, "outcome_unknown")) TrackUnknownOutcome(result);
            }
            var report = readinessReport ?? result;
            var checks = Checks(report);
            int failed = checks.Count(item => !Flag(item, "passed"));
            DiagnosticSummary.Text = checks.Count == 0 ? "Не выполнялась" : failed == 0 ? "Всё в порядке" : failed == 1 ? "1 проблема" : failed + (failed < 5 ? " проблемы" : " проблем");
            DiagnosticPill.Background = checks.Count == 0 ? GreySoft : failed == 0 ? GreenSoft : Hex("#FFF1DE");
            DiagnosticSummary.Foreground = checks.Count == 0 ? Grey : failed == 0 ? GreenInk : Hex("#B36200");
            ChecksHeroTitle.Text = checks.Count == 0 ? "Проверка не выполнялась" : failed == 0 ? "Всё в порядке" : "Нужно исправить: " + failed;
            ChecksHeroDetail.Text = checks.Count == 0 ? "ПК и комплект" : (checks.Count - failed) + " из " + checks.Count + " проверок пройдено";
            ChecksHeroBadge.Background = DiagnosticPill.Background; ChecksHeroGlyph.Foreground = DiagnosticSummary.Foreground;
            ChecksHeroGlyph.Symbol = checks.Count == 0 ? SymbolRegular.Pulse24 : failed == 0 ? SymbolRegular.Checkmark24 : SymbolRegular.Warning24;

            Dictionary<string, object> blocker = null;
            if (!Bridge.Ok(result))
            {
                var blockers = result.ContainsKey("blockers") ? result["blockers"] as IEnumerable : null;
                if (blockers != null) blocker = blockers.Cast<object>().OfType<Dictionary<string, object>>().FirstOrDefault();
                if (blocker == null && isReadiness) blocker = checks.FirstOrDefault(item => !Flag(item, "passed"));
            }
            StatusText.Text = blocker == null ? Friendly(Bridge.Message(result)) : Text(blocker, "title", Bridge.Message(result));
            if (blocker == null && !Bridge.Ok(result) && Friendly(Bridge.Message(result)) != Bridge.Message(result)) StatusText.Text = "Linux не запустился";
            if (isReadiness && Bridge.Ok(result)) StatusText.Text = RuntimeHeading(workState, gatewayState);
            NextStepText.Text = blocker == null ? (Bridge.Ok(result) ? "Сначала поднимется защищённое подключение, затем Linux." : Friendly(Bridge.Message(result))) : Text(blocker, "detail", Bridge.Message(result));
            if (isReadiness && Bridge.Ok(result) && runtimeActive) NextStepText.Text = "Linux: " + VmState(workState) + ". Сеть: " + VmState(gatewayState, true) + ".";
            suggestedAction = blocker == null ? "retry" : Text(blocker, "action", "retry");
            NextActionButton.Content = blocker == null ? "Проверить снова" : Text(blocker, "action_label", "Проверить снова");
            bool restore = blocker != null && (suggestedAction == "prepare" || suggestedAction == "repair_gateway" || suggestedAction == "recover_session");
            // Restoring needs one short line; the full explanation stays on the Проверка page.
            if (blocker != null) { string detail = Text(blocker, "detail", ""); int stop = detail.IndexOf(". "); NextStepText.Text = stop > 0 ? detail.Substring(0, stop + 1) : detail; }
            NextActionButton.Style = (Style)FindResource(restore ? "Pill" : "SoftPill");
            Show(NextActionButton, !Bridge.Ok(result));

            string displayState = DisplayState(report);
            if (Child(report, "windows_settings") != null && (displayState == "failed" || displayState == "unconfirmed") && blocker == null)
                NextStepText.Text = displayState == "failed" ? "Linux не применил выбранное разрешение. Выбери другое после выключения." : "Linux ещё не подтвердил разрешение.";
            string filesState = FileSharingState(report);
            if (blocker == null && (filesState == "failed" || filesState == "unavailable")) NextStepText.Text = "Проверь доступность выбранных папок ПК. Linux подключит их снова при следующем входе.";
            UpdateHero(report, filesState);
            if (StatusText.Text != shownStatus) { shownStatus = StatusText.Text; Rise(StatusText, 0); Rise(NextStepText, 60); }
            string warning = runtimeActive ? Text(report, "network_warning", "") : "";
            NetworkText.Text = warning; Show(NetworkText, warning.Length > 0);

            string signature = new JavaScriptSerializer().Serialize(checks.Select(item => new object[] { Flag(item, "passed"), Text(item, "title", ""), Text(item, "detail", "") }).ToArray()) + Bridge.Message(result);
            if (signature != displayedChecks)
            {
                displayedChecks = signature; CheckCards.Children.Clear();
                // Problems go full width on top; passed checks are tags that wrap, so long names are never cut.
                var passedGrid = new WrapPanel { Margin = new Thickness(10, 7, 10, 7) };
                foreach (var item in checks)
                {
                    var row = CheckRow(Flag(item, "passed"), Text(item, "title", "Проверка"), Text(item, "detail", ""));
                    if (Flag(item, "passed")) passedGrid.Children.Add(row); else CheckCards.Children.Add(row);
                }
                if (passedGrid.Children.Count > 0) CheckCards.Children.Add(passedGrid);
                if (checks.Count == 0) CheckCards.Children.Add(new TextBlock { Text = Bridge.Message(result), Style = (Style)FindResource("Caption"), Margin = new Thickness(16, 6, 16, 10) });
            }
            var lines = checks.Select(item => (Flag(item, "passed") ? "Готово: " : "Нужно исправить: ") + Text(item, "title", "Проверка") + Environment.NewLine + Text(item, "detail", "")).ToList();
            if (checks.Count == 0) lines.Add(Bridge.Message(result));
            if (!isReadiness && !Bridge.Ok(result)) lines.Insert(0, Bridge.Message(result));
            if (warning.Length > 0) lines.Add(warning);
            string reportPath = Text(report, "diagnostic_report", "");
            if (reportPath.Length > 0) lines.Add("Отчёт: " + reportPath);
            ReportLocation.Text = reportPath.Length > 0 ? "Отчёт: " + reportPath : Text(report, "diagnostic_report_error", "");
            reportText = String.Join(Environment.NewLine + Environment.NewLine, lines);
            Busy(busy);
            SettingsNote.Foreground = Grey;
            SettingsNote.Text = runtimeActive ? "Настройки можно менять, когда Linux выключен." : "Сохраняется само, применится при следующем запуске.";
        }

        UIElement CheckRow(bool passed, string title, string detail)
        {
            // A passed check is a small green tag with its detail in a tooltip.
            if (passed)
                return new Border { CornerRadius = new CornerRadius(13), Background = GreenSoft, Padding = new Thickness(8, 3, 10, 3), Margin = new Thickness(2.5), ToolTip = detail.Length > 0 ? detail : null,
                    Child = new StackPanel { Orientation = Orientation.Horizontal, Children = {
                        new SymbolIcon { Symbol = SymbolRegular.Checkmark16, FontSize = 12, Foreground = GreenInk, Margin = new Thickness(0, 0, 5, 0), VerticalAlignment = VerticalAlignment.Center },
                        new TextBlock { Text = title, FontSize = 12.5, Foreground = GreenInk, VerticalAlignment = VerticalAlignment.Center } } } };
            var row = new DockPanel { Margin = new Thickness(16, 9, 12, 9), Background = Brushes.Transparent };
            var dot = new Border { Width = 22, Height = 22, CornerRadius = new CornerRadius(11), Background = Hex("#FFF1DE"), Margin = new Thickness(0, 0, 12, 0), VerticalAlignment = VerticalAlignment.Top,
                Child = new SymbolIcon { Symbol = SymbolRegular.Warning16, FontSize = 12, Foreground = Hex("#B36200") } };
            DockPanel.SetDock(dot, Dock.Left); row.Children.Add(dot);
            var text = new StackPanel { Children = { new TextBlock { Text = title, FontSize = 14, FontWeight = FontWeights.SemiBold, Foreground = Ink, TextTrimming = TextTrimming.CharacterEllipsis } } };
            if (detail.Length > 0) text.Children.Add(new TextBlock { Text = detail, Style = (Style)FindResource("Caption"), Margin = new Thickness(0, 1, 0, 0) });
            row.Children.Add(text);
            return row;
        }

        void UpdateHero(Dictionary<string, object> report, string filesState)
        {
            bool running = workState == "running", starting = ActiveVmState(workState) && !running;
            bool attention = !ready && readinessReport != null && !runtimeActive;
            StatusIcon.Background = running ? GreenSoft : attention ? GreySoft : BlueSoft;
            StatusGlyph.Foreground = running ? Green : attention ? Grey : Blue;
            Pulse.Fill = running ? Green : Blue;
            bool[] done = { gatewayState == "running", Flag(report, "network_verified"), running, filesState == "ready" };
            bool[] active = { ActiveVmState(gatewayState) && gatewayState != "running", gatewayState == "running" && !done[1], starting, running && filesState != "ready" && filesState != "off" && filesState.Length > 0 };
            for (int index = 0; index < 4; index++)
            {
                stepDots[index].Fill = done[index] ? Green : active[index] ? Blue : Hex("#C7C7CC");
                stepTexts[index].Foreground = done[index] ? GreenInk : active[index] ? BlueInk : Grey;
                stepCards[index].Background = done[index] ? GreenSoft : active[index] ? BlueSoft : Brushes.White;
                stepCards[index].ToolTip = index == 3 && filesState == "off" ? "Файлы ПК выключены" : null;
            }
            Show(Steps, (runtimeActive && workState != "running") || (busy && activeOperationAction == "start")); // steps only while starting
        }

        static string FormatGiB(int mib) { return ((decimal)mib / 1024).ToString("0.######", CultureInfo.CurrentCulture); }

        // ---------- Offers: Proxy and Claude Pro are bought in the Telegram bot; until the bot exists the link leads to the seller ----------
        const string ContactUrl = "https://t.me/Daniil_Simples";
        
        void OnBuyProxy(object sender, RoutedEventArgs e) { OpenContact("Хочу купить Proxy за 900 ₽"); }
        void OnClaude(object sender, RoutedEventArgs e) { OpenContact("Хочу купить Claude Pro за 2 000 ₽"); }
        // t.me opens the chat with the message already typed in; a bot takes the same idea as ?start=<code>.
        // Every 5 seconds the shop group lifts by a pixel or two, barely there, so it only seems to have moved; it never grows, because the page clips at its edge.
        void StartShopNudge()
        {
            var scale = new ScaleTransform(1, 1); var lift = new TranslateTransform();
            var group = new TransformGroup(); group.Children.Add(scale); group.Children.Add(lift); ShopGroup.RenderTransform = group;
            var ease = new SineEase { EasingMode = EasingMode.EaseInOut };
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
            timer.Tick += delegate
            {
                if (!ShopGroup.IsVisible || ShopGroup.IsMouseOver || SheetHost.Visibility == Visibility.Visible) return;
                var up = new DoubleAnimationUsingKeyFrames();
                up.KeyFrames.Add(new EasingDoubleKeyFrame(-1.5, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(700)), ease));
                up.KeyFrames.Add(new EasingDoubleKeyFrame(0, KeyTime.FromTimeSpan(TimeSpan.FromMilliseconds(1500)), ease));
                lift.BeginAnimation(TranslateTransform.YProperty, up);
            };
            timer.Start();
        }
        // Linux updates stay disabled until a separately validated Linux updater exists.
        void StartUpdateCheck() { ShowUpdateOffer(); }
        void OnCheckUpdates(object sender, RoutedEventArgs e) { ShowUpdateOffer(); }
        void OnUpdatesRow(object sender, RoutedEventArgs e) { Navigate(AppPage.Updates); ShowUpdateOffer(); }
        void OnUpdate(object sender, RoutedEventArgs e) { ShowUpdateOffer(); }

        void ShowUpdateOffer()
        {
            UpdateCaption.Text = AppUpdate.Notice;
            UpdateStatusTitle.Text = "Обновления Linux пока недоступны";
            UpdateStatusText.Text = AppUpdate.Notice;
            Show(UpdatePill, false); Show(InstallUpdateButton, false);
            Show(UpdatePackageText, false); Show(UpdateProgress, false);
            CheckUpdatesButton.IsEnabled = false;
        }

        static void OpenContact(string message)
        {
            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(ContactUrl + "?text=" + Uri.EscapeDataString(message)) { UseShellExecute = true }); }
            catch (Exception) { System.Windows.MessageBox.Show("Не удалось открыть Telegram. Ссылка на бота: " + ContactUrl, "Pocket Linux"); }
        }

        // ---------- Lifecycle, tray, polling ----------
        void StartLifecycle()
        {
            trayIcon = new Forms.NotifyIcon { Icon = System.Drawing.Icon.ExtractAssociatedIcon(System.Reflection.Assembly.GetExecutingAssembly().Location), Text = "Pocket Linux" };
            trayIcon.DoubleClick += delegate { ShowPanel(false, "tray double click"); };
            trayIcon.MouseUp += delegate (object sender, Forms.MouseEventArgs e) { if (e.Button == Forms.MouseButtons.Right) ShowTrayMenu(); };
            lifecycleTimer.Tick += async delegate { await RefreshRuntimeAsync(); };
            lifecycleTimer.Start(); UpdateTray();
        }

        void UpdateTray()
        {
            if (trayIcon == null || closing) return;
            trayIcon.Visible = runtimeActive || panelHiddenForSession;
            if (trayIcon.Visible && !trayPromotionStarted) PromoteTrayIcon();
        }

        void ShowTrayMenu()
        {
            TrayMenu.ShowAt(Forms.Cursor.Position, new[]
            {
                new TrayMenu.Item { Text = "Открыть панель", Icon = SymbolRegular.Open20, Tint = Blue, Run = delegate { ShowPanel(false, "tray menu"); } },
                new TrayMenu.Item { Text = "Выключить Linux", Icon = SymbolRegular.Power20, Tint = Red, Enabled = stopAvailable && !busy && !outcomeUnknown,
                    Run = async delegate { ShowPanel(false, "tray: stop Linux"); if (stopAvailable) await RunAction("stop", false); } }
            });
        }

        // Windows registers the icon a moment after it appears; retry briefly, then give up quietly.
        void PromoteTrayIcon()
        {
            trayPromotionStarted = true;
            string exe = System.Reflection.Assembly.GetExecutingAssembly().Location; int tries = 0;
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            timer.Tick += delegate
            {
                bool done = TrayPromotion.TryPromote(exe);
                if (done || ++tries >= 6) { timer.Stop(); UiLog("tray icon promotion: " + (done ? "done" : "no registry entry")); }
            };
            timer.Start();
        }

        // Why the panel hid or reappeared goes to logs/launcher-ui.log, so a flicker can be explained afterwards.
        static void UiLog(string message)
        {
            try
            {
                string folder = System.IO.Path.Combine(Bridge.Root, "logs"), path = System.IO.Path.Combine(folder, "launcher-ui.log");
                Directory.CreateDirectory(folder);
                if (File.Exists(path) && new FileInfo(path).Length > 200 * 1024) File.Delete(path);
                File.AppendAllText(path, DateTime.Now.ToString("HH:mm:ss.fff") + " " + message + Environment.NewLine);
            }
            catch (Exception) { }
        }

        void HidePanelForSession(string why)
        {
            panelHiddenForSession = true; attentionPolls = 0; lastAttention = null; UpdateTray(); Hide();
            UiLog("panel hidden: " + why);
            if (trayIcon != null && !trayNoticeShown)
            {
                trayNoticeShown = true;
                trayIcon.ShowBalloonTip(4000, "Pocket Linux", "Панель свёрнута в трей, значок у часов. Двойной щелчок открывает её, меню выключает Linux.", Forms.ToolTipIcon.Info);
            }
        }

        void ShowPanelAutomatically(string why)
        {
            if (!panelDismissedByUser) { ShowPanel(true, "auto: " + why); return; }
            // The user closed the panel on purpose: say so from the tray instead of reopening the window.
            UiLog("auto-show skipped, user closed the panel: " + why);
            if (trayIcon != null && !attentionNoticeShown)
            {
                attentionNoticeShown = true;
                trayIcon.ShowBalloonTip(5000, "Pocket Linux", "Linux требует внимания. Открой панель двойным щелчком по значку.", Forms.ToolTipIcon.Warning);
            }
        }
        void ShowPanel(bool home, string why)
        {
            bool wasHidden = !IsVisible;
            panelDismissedByUser = false; panelHiddenForSession = false; attentionPolls = 0; lastAttention = null; attentionNoticeShown = false;
            if (home && wasHidden) Navigate(AppPage.Home);
            Show(); if (WindowState == WindowState.Minimized) WindowState = WindowState.Normal;
            Activate(); UpdateTray();
            UiLog("panel shown: " + why);
        }

        // Counts consecutive polls with the same reason; only a confirmed one brings the hidden panel back.
        void Attention(string reason)
        {
            attentionPolls = reason == null ? 0 : reason == lastAttention ? attentionPolls + 1 : 1;
            lastAttention = reason;
            if (reason == null) return;
            if (panelHiddenForSession && AttentionPolicy.ShouldReopen(reason, attentionPolls))
            {
                ShowPanelAutomatically(reason + " x" + attentionPolls);
                if (reason == "status-unreadable") SetOperation("Не удалось обновить состояние. Повтори проверку.");
            }
            else UiLog("poll: " + reason + " x" + attentionPolls + (panelHiddenForSession ? ", panel stays in the tray" : ""));
        }

        void OnClosing(object sender, CancelEventArgs e)
        {
            // While Windows runs the tray icon is its only handle, so the panel can hide but never quit.
            if (runtimeActive || outcomeUnknown || (busy && activeOperationAction == "start"))
            { e.Cancel = true; panelDismissedByUser = true; HidePanelForSession("closed by the user while Linux runs"); return; }
            closing = true; lifecycleTimer.Stop(); saveTimer.Stop();
            if (trayIcon != null) { trayIcon.Visible = false; trayIcon.Dispose(); trayIcon = null; }
        }

        async Task RefreshRuntimeAsync()
        {
            if (closing || busy || runtimePolling || (!runtimeActive && !panelHiddenForSession && !outcomeUnknown)) return;
            runtimePolling = true; int revision = operationRevision;
            try
            {
                var report = await Run("status", null);
                if (closing || busy || revision != operationRevision) return;
                if (report == null || !report.ContainsKey("checks"))
                {
                    UiLog("poll: status not readable: " + Bridge.Message(report));
                    Attention(AttentionPolicy.Classify(false, workState, gatewayState, outcomeUnknown));
                    if (IsVisible) { StatusText.Text = "Состояние Linux не подтверждено"; NextStepText.Text = Bridge.Message(report); CheckedAtText.Text = "Состояние не обновилось. Повтори проверку."; }
                    return;
                }
                report = MergeRuntimeStatus(report);
                var state = Child(report, "runtime");
                bool changed = readinessReport == null || state == null || pendingStartReceipt != null
                    || workState != Text(state, "work", "unknown") || gatewayState != Text(state, "gateway", "unknown")
                    || Bridge.Ok(report) != Bridge.Ok(readinessReport) || Flag(report, "network_verified") != Flag(readinessReport, "network_verified")
                    || DisplayState(report) != DisplayState(readinessReport) || FileSharingState(report) != FileSharingState(readinessReport)
                    || Text(report, "message", "") != Text(readinessReport, "message", "") || (pendingOutcome != null && pendingOutcome.IsCompleted);
                if (changed) { Display(report); Busy(false); }
                var connection = Child(report, "connection");
                bool networkExpected = connection == null || Text(connection, "applied_profile_id", "").Length > 0;
                Attention(AttentionPolicy.Classify(true, workState, gatewayState, outcomeUnknown, networkExpected));
                string display = DisplayState(report);
                if (panelHiddenForSession && (display == "failed" || display == "unconfirmed") && !displayNoticeShown && trayIcon != null)
                {
                    displayNoticeShown = true; UiLog("poll: Linux display " + display);
                    trayIcon.ShowBalloonTip(5000, "Pocket Linux", "Разрешение Linux не подтверждено. Открой панель, чтобы посмотреть подробности.", Forms.ToolTipIcon.Warning);
                }
                UpdateTray();
            }
            catch (Exception error)
            {
                UiLog("poll: exception " + error.GetType().Name);
                if (!closing && !busy && revision == operationRevision) Attention(AttentionPolicy.Classify(false, workState, gatewayState, outcomeUnknown));
            }
            finally { runtimePolling = false; }
        }

        // ---------- Settings: saved automatically ----------
        void LoadSettings(Dictionary<string, object> reply)
        {
            originalSettings = new Dictionary<string, object>(Child(reply, "settings"));
            originalWindows = Child(reply, "windows_settings");
            originalViewer = Child(reply, "viewer_settings");
            originalFiles = Child(reply, "file_settings");
            if (reply.ContainsKey("host")) settingsHost = Child(reply, "host");
            settingsLoaded = true; ResetSettings(); Busy(busy);
        }

        void ResetSettings()
        {
            applyingSettings = true;
            try
            {
                int memory; Int32.TryParse(Text(originalSettings, "work_memory_mib", "2048"), out memory);
                MemoryInput.Text = FormatGiB(memory); CpuInput.Text = Text(originalSettings, "vcpus", "2");
                int selected = DefaultMode;
                if (originalWindows != null && !Flag(originalWindows, "fit"))
                    for (int index = 0; index < Modes.GetLength(0); index++)
                        if (Text(originalWindows, "width", "") == Modes[index, 0].ToString() && Text(originalWindows, "height", "") == Modes[index, 1].ToString()) selected = index;
                ResolutionBox.SelectedIndex = selected;                FullscreenSwitch.IsChecked = Flag(originalViewer, "start_fullscreen");
                ClipboardSwitch.IsChecked = originalViewer == null || !originalViewer.ContainsKey("share_clipboard") || Flag(originalViewer, "share_clipboard");
                string mode = Text(originalFiles, "mode", "off");
                folders.Clear();
                var saved = originalFiles != null && originalFiles.ContainsKey("folders") ? originalFiles["folders"] as IEnumerable : null;
                if (saved != null) foreach (var folder in saved) folders.Add(Convert.ToString(folder));
                FilesSwitch.IsChecked = mode != "off"; FilesAll.IsChecked = mode == "all"; FilesSelected.IsChecked = mode != "all";
                UpdateFilesRows(); UpdateWindowsSummary();
            }
            finally { applyingSettings = false; }
        }

        // Leaves room for the PC itself: a quarter of the memory (at least 4 GiB) and of the cores (at least 2).
        int MemoryLimitGiB()
        {
            int total; if (!Int32.TryParse(Text(settingsHost, "ram_total_mib", "0"), out total) || total <= 0) return 32;
            return Math.Max(1, Math.Min(32, (total - Math.Max(4096, total / 4)) / 1024));
        }
        int CpuLimit()
        {
            int cores; if (!Int32.TryParse(Text(settingsHost, "logical_processors", "0"), out cores) || cores <= 0) return 32;
            return Math.Max(1, Math.Min(32, cores - Math.Max(2, cores / 4)));
        }

        void UpdateFilesRows()
        {
            bool on = FilesSwitch.IsChecked == true;
            Show(FoldersRow, on); Show(FolderPanel, FilesSelected.IsChecked == true); Show(AddFolderButton, FilesSelected.IsChecked == true);
            FilesDetail.Text = !on ? "Выключено" : FilesSelected.IsChecked == true ? (folders.Count == 0 ? "Добавь папку" : "Папок: " + folders.Count) : "Все диски ПК";
            FolderPanel.Children.Clear();
            foreach (string folder in folders)
            {
                var row = new DockPanel { Margin = new Thickness(0, 2, 0, 2) };
                string path = folder;
                var remove = new System.Windows.Controls.Button { Style = (Style)FindResource("TextAction"), Content = "Убрать", Foreground = Red };
                remove.Click += delegate { folders.Remove(path); UpdateFilesRows(); ScheduleSave(); };
                DockPanel.SetDock(remove, Dock.Right); row.Children.Add(remove);
                row.Children.Add(new TextBlock { Text = path, FontSize = 13.5, Foreground = Ink, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis });
                FolderPanel.Children.Add(row);
            }
        }

        void ScheduleSave() { if (applyingSettings || !settingsLoaded) return; UpdateWindowsSummary(); saveTimer.Stop(); saveTimer.Start(); }
        void CommitPendingSettings() { if (saveTimer.IsEnabled) { saveTimer.Stop(); var task = SaveSettingsAsync(); } }
        void OnSettingChanged(object sender, RoutedEventArgs e) { ScheduleSave(); }
        void OnSettingEdited(object sender, KeyboardFocusChangedEventArgs e) { ScheduleSave(); }
        void OnNumberKey(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) { Keyboard.ClearFocus(); ScheduleSave(); } }
        void OnFilesSwitch(object sender, RoutedEventArgs e)
        {
            if (FilesSwitch.IsChecked == true && FilesAll.IsChecked != true) FilesSelected.IsChecked = true;
            UpdateFilesRows(); ScheduleSave();
        }
        void OnFilesMode(object sender, RoutedEventArgs e) { UpdateFilesRows(); if (FilesSelected.IsChecked != true || folders.Count > 0) ScheduleSave(); }
        void OnAddFolder(object sender, RoutedEventArgs e)
        {
            using (var dialog = new Forms.FolderBrowserDialog { Description = "Папка ПК, которая будет видна в Linux" })
                if (dialog.ShowDialog() == Forms.DialogResult.OK && !folders.Any(item => String.Equals(item, dialog.SelectedPath, StringComparison.OrdinalIgnoreCase)))
                { folders.Add(dialog.SelectedPath); UpdateFilesRows(); ScheduleSave(); }
        }

        internal static bool TryGiB(string text, out decimal gib)
        {
            return Decimal.TryParse(text.Trim().Replace(',', '.'), NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out gib);
        }
        void StepMemory(decimal delta)
        {
            decimal gib; if (!TryGiB(MemoryInput.Text, out gib)) gib = 4;
            gib = Math.Min(MemoryLimitGiB(), Math.Max(1, Math.Round((gib + delta) * 2, MidpointRounding.AwayFromZero) / 2));
            MemoryInput.Text = gib.ToString("0.#", CultureInfo.CurrentCulture); ScheduleSave();
        }
        void StepCpu(int delta)
        {
            int cpus; if (!Int32.TryParse(CpuInput.Text.Trim(), out cpus)) cpus = 2;
            CpuInput.Text = Math.Min(CpuLimit(), Math.Max(1, cpus + delta)).ToString(CultureInfo.InvariantCulture); ScheduleSave();
        }
        void OnMemoryDown(object sender, RoutedEventArgs e) { StepMemory(-0.5m); }
        void OnMemoryUp(object sender, RoutedEventArgs e) { StepMemory(0.5m); }
        void StepResolution(int delta)
        {
            int next = Math.Min(ResolutionBox.Items.Count - 1, Math.Max(0, ResolutionBox.SelectedIndex + delta));
            if (next != ResolutionBox.SelectedIndex) ResolutionBox.SelectedIndex = next; // SelectionChanged schedules the save
        }
        void OnResolutionDown(object sender, RoutedEventArgs e) { StepResolution(-1); }
        void OnResolutionUp(object sender, RoutedEventArgs e) { StepResolution(1); }        void OnCpuDown(object sender, RoutedEventArgs e) { StepCpu(-1); }
        void OnCpuUp(object sender, RoutedEventArgs e) { StepCpu(1); }

        bool TryGetSettings(out Dictionary<string, object> value, out string error)
        {
            value = null; error = null;
            decimal gib; int original; Int32.TryParse(Text(originalSettings, "work_memory_mib", "0"), out original);
            int memoryMax = Math.Max(MemoryLimitGiB(), (int)Math.Ceiling((decimal)original / 1024));
            if (!TryGiB(MemoryInput.Text, out gib) || gib < 1 || gib > memoryMax) { error = "Память: число от 1 до " + memoryMax + " ГиБ, например 6 или 6,5."; return false; }
            // Unchanged text keeps an old exact MiB value such as 5000.
            int mib = MemoryInput.Text.Trim() == FormatGiB(original) ? original : (int)Math.Round(gib * 1024, MidpointRounding.AwayFromZero);
            int cpus;
            if (!Int32.TryParse(CpuInput.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out cpus) || cpus < 1 || cpus > Math.Max(CpuLimit(), Convert.ToInt32(Text(originalSettings, "vcpus", "1")))) { error = "Процессоры: целое число от 1 до " + CpuLimit() + "."; return false; }
            bool filesOn = FilesSwitch.IsChecked == true;
            string mode = !filesOn ? "off" : FilesAll.IsChecked == true ? "all" : "selected";
            if (mode == "selected" && folders.Count == 0) { error = "Добавь хотя бы одну папку ПК."; return false; }
            int resolution = Math.Max(0, ResolutionBox.SelectedIndex);
            value = new Dictionary<string, object>(originalSettings);
            value["schema"] = 1; value["work_memory_mib"] = mib; value["vcpus"] = cpus;
            value["windows"] = new Dictionary<string, object> { { "schema", 1 }, { "width", Modes[resolution, 0] }, { "height", Modes[resolution, 1] }, { "fit", false } };
            value["viewer"] = new Dictionary<string, object> { { "schema", 1 }, { "start_fullscreen", FullscreenSwitch.IsChecked == true }, { "remember_window", originalViewer == null || !originalViewer.ContainsKey("remember_window") || Flag(originalViewer, "remember_window") }, { "share_clipboard", ClipboardSwitch.IsChecked == true } };
            value["files"] = new Dictionary<string, object> { { "schema", 1 }, { "mode", mode }, { "folders", folders.ToArray() } };
            return true;
        }

        async Task<bool> SaveSettingsAsync()
        {
            Dictionary<string, object> value; string error;
            if (!settingsLoaded || runtimeActive) return false;
            if (!TryGetSettings(out value, out error)) { SettingsNote.Text = error; SettingsNote.Foreground = Red; return false; }
            SettingsNote.Foreground = Grey;
            if (!BeginOperation("save-settings")) { saveTimer.Start(); return false; }
            Dictionary<string, object> completed = null;
            try
            {
                completed = await Run("save-settings", value);
                if (closing) return false;
                if (Bridge.Ok(completed))
                {
                    settingsLoaded = false; LoadSettings(completed);
                    SetOperation("");
                    var check = await Run("diagnose", null);
                    if (!closing) Display(check);
                    SettingsNote.Text = "Сохранено. Применится при следующем запуске.";
                }
                else { SettingsNote.Text = Bridge.Message(completed); SettingsNote.Foreground = Red; SetOperation(Bridge.Message(completed)); if (Flag(completed, "outcome_unknown")) TrackUnknownOutcome(completed); }
                return Bridge.Ok(completed);
            }
            catch (Exception) { FailedAction("save-settings", completed); return false; }
            finally { if (!closing) Busy(false); }
        }

        // ---------- Connection ----------
        async Task<Dictionary<string, object>> ProfileAction(string action, object payload)
        {
            if (action == "test-profile" && !testAvailable) return Bridge.Failure("Проверка подключения сейчас недоступна.");
            if (!BeginOperation(action)) return Bridge.Failure("Дождись завершения текущей операции.");
            Dictionary<string, object> result = null;
            try
            {
                result = await Run(action, payload);
                if (closing) return result;
                operationResult = result; SetOperation(Bridge.Message(result));
                if (!Bridge.Ok(result)) { ProfileErrorText(Bridge.Message(result)); if (Flag(result, "outcome_unknown")) TrackUnknownOutcome(result); return result; }
                ProfileErrorText("");
                if (action == "list-profiles" || action == "get-profile-view") SetOperation("");
                if (result.ContainsKey("profile")) LoadProfileView(Child(result, "profile"));
                if (action == "list-profiles") { profilesLoaded = true; LoadProfileList(result["profiles"]); }
                else if (action == "save-profile" || action == "select-profile" || action == "import-profile")
                {
                    var list = await Run("list-profiles", null);
                    if (Bridge.Ok(list)) { profilesLoaded = true; LoadProfileList(list["profiles"]); }
                    var status = await Run("status", null);
                    if (status != null && status.ContainsKey("checks")) Display(status);
                    SetOperation(Bridge.Message(result));
                }
                else if (action == "test-profile") ProfileStateText.Text = Flag(result, "verified") ? "Проверка пройдена: сервер отвечает." : "Проверка не подтверждена. Подробности в разделе «Проверка».";
                return result;
            }
            catch (Exception)
            {
                if (result != null && Bridge.Ok(result)) { ProfileErrorText("Изменение сохранено, но состояние не обновилось. Нажми «Проверить снова»."); return result; }
                result = action == "list-profiles" || action == "get-profile-view" ? Bridge.Failure("Не удалось загрузить подключения. Проверь компоненты и повтори.")
                    : Bridge.Unknown("Исход действия с подключением неизвестен. Сначала нажми «Проверить снова».", "profile_operation_failed");
                if (!closing) { operationResult = result; SetOperation(Bridge.Message(result)); if (Flag(result, "outcome_unknown")) TrackUnknownOutcome(result); ProfileErrorText(Bridge.Message(result)); }
                return result;
            }
            finally { if (!closing) Busy(false); }
        }

        async Task LoadProfilesAsync()
        {
            if (busy) { ProfileErrorText("Дождись завершения текущей операции и открой снова."); return; }
            await ProfileAction("list-profiles", null);
        }

        void LoadProfileList(object source)
        {
            profiles = (source as IEnumerable ?? new object[0]).Cast<object>().OfType<Dictionary<string, object>>().ToList();
            ProfileList.Children.Clear();
            foreach (var item in profiles)
            {
                if (ProfileList.Children.Count > 0) ProfileList.Children.Add(new Border { Style = (Style)FindResource("Separator") });
                string id = Text(item, "profile_id", ""), protocol = Text(item, "protocol", "");
                protocol = protocol == "hysteria2" ? "Hysteria2" : protocol.ToUpperInvariant();
                bool selected = Flag(item, "selected");
                // The selected connection is marked by its blue check badge and bold name; no square fill inside the rounded group.
                var row = new DockPanel { Background = Brushes.Transparent };
                var edit = new System.Windows.Controls.Button { Style = (Style)FindResource("TextAction"), Content = "Изменить", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 10, 0) };
                edit.Click += async delegate { var view = await ProfileAction("get-profile-view", new Dictionary<string, object> { { "profile_id", id } }); if (Bridge.Ok(view)) ShowEditor("Изменить подключение"); };
                DockPanel.SetDock(edit, Dock.Right); row.Children.Add(edit);
                var badge = new Border { Width = 30, Height = 30, CornerRadius = new CornerRadius(15), Background = selected ? Blue : GreySoft, Margin = new Thickness(16, 0, 14, 0), VerticalAlignment = VerticalAlignment.Center,
                    Child = new SymbolIcon { Symbol = selected ? SymbolRegular.Checkmark20 : SymbolRegular.Globe20, FontSize = 16, Foreground = selected ? Brushes.White : Grey } };
                DockPanel.SetDock(badge, Dock.Left); row.Children.Add(badge);
                row.Children.Add(new StackPanel { VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 9, 0, 9), Children = {
                    new TextBlock { Text = Text(item, "name", "Профиль"), Style = (Style)FindResource("RowText"), FontWeight = selected ? FontWeights.SemiBold : FontWeights.Normal, TextTrimming = TextTrimming.CharacterEllipsis },
                    new TextBlock { Text = protocol + ", " + Text(item, "host", "") + (Flag(item, "needs_credentials") ? ", нужен пароль" : ""), Style = (Style)FindResource("Caption"), TextTrimming = TextTrimming.CharacterEllipsis, TextWrapping = TextWrapping.NoWrap } } });
                var button = new System.Windows.Controls.Button { Style = (Style)FindResource("RowNoScale"), Content = row, Padding = new Thickness(0), ToolTip = selected ? "Используется для запуска" : "Использовать для запуска" };
                button.Click += async delegate { if (!selected) await ProfileAction("select-profile", new Dictionary<string, object> { { "profile_id", id } }); };
                Rise(row, ProfileList.Children.Count * 45); ProfileList.Children.Add(button);
            }
            UpdateAddRows();
            Busy(busy);
        }

        void LoadProfileView(Dictionary<string, object> view)
        {
            if (view == null) return;
            profileId = Text(view, "profile_id", null);
            loadedProtocol = Text(view, "protocol", "socks5"); loadedObfs = Text(view, "obfs", "");
            authPresent = Flag(view, "auth_present") && !Flag(view, "needs_credentials");
            ProfileName.Text = Text(view, "name", ""); ProfileHost.Text = Text(view, "host", ""); ProfilePort.Text = Text(view, "port", "");
            ProfileSni.Text = Text(view, "tls_server_name", "");
            ProtocolBox.SelectedIndex = Math.Max(0, Array.IndexOf(Protocols, loadedProtocol));
            ObfsSwitch.IsChecked = loadedObfs == "salamander";
            ProxyAuthSwitch.IsChecked = loadedProtocol != "hysteria2" && Flag(view, "auth_present");
            ProfileAuth.Password = ProfileObfsPassword.Password = ProfilePassword.Password = ""; ProfileUser.Text = "";
            AuthCaption.Text = authPresent ? "сохранён, можно не вводить" : "пароль от сервера";
            EditorErrorText(""); UpdateProfileRows(); Busy(busy);
        }

        void NewProfile()
        {
            profileId = null; loadedProtocol = null; loadedObfs = null; authPresent = false;
            ProfileName.Text = ProfileHost.Text = ProfileSni.Text = ProfileUser.Text = ""; ProfilePort.Text = "1080";
            ProfileAuth.Password = ProfileObfsPassword.Password = ProfilePassword.Password = "";
            AuthCaption.Text = "пароль от сервера";
            ProtocolBox.SelectedIndex = 1; ObfsSwitch.IsChecked = false; ProxyAuthSwitch.IsChecked = false;
            EditorErrorText(""); UpdateProfileRows(); Busy(busy);
        }

        void OnManualProfile(object sender, RoutedEventArgs e) { NewProfile(); ShowEditor("Новое подключение"); ProfileHost.Focus(); }
        void OnProtocolChanged(object sender, SelectionChangedEventArgs e) { UpdateProfileRows(); }
        void OnProfileToggle(object sender, RoutedEventArgs e) { UpdateProfileRows(); }
        void UpdateProfileRows()
        {
            if (TypeHttps == null) return; // SelectionChanged fires while XAML is still loading
            int kind = Math.Max(0, ProtocolBox.SelectedIndex); bool hy = kind == 0;
            TypeHysteria.IsChecked = kind == 0; TypeSocks.IsChecked = kind == 1; TypeHttp.IsChecked = kind == 2; TypeHttps.IsChecked = kind == 3;
            Show(HysteriaRows, hy); Show(AuthRow, hy); Show(ProxyRows, !hy); Show(ObfsRow, ObfsSwitch.IsChecked == true);
            Show(ProxyAuthRow, ProxyAuthSwitch.IsChecked == true); Show(SniRow, hy || kind == 3);
            UpdateHints();
        }
        // Grey hints sit inside empty fields; PasswordBox has no bindable text, so all are updated here.
        void UpdateHints()
        {
            Show(NameHint, ProfileName.Text.Length == 0); Show(HostHint, ProfileHost.Text.Length == 0); Show(SniHint, ProfileSni.Text.Length == 0);
            Show(AuthCaption, ProfileAuth.Password.Length == 0); Show(ObfsHint, ProfileObfsPassword.Password.Length == 0); Show(ProxyHint, ProfilePassword.Password.Length == 0);
        }
        void OnHintText(object sender, TextChangedEventArgs e) { if (TypeHttps != null) UpdateHints(); }
        void OnSecretChanged(object sender, RoutedEventArgs e) { if (TypeHttps != null) UpdateHints(); }
        void OnTypeClick(object sender, RoutedEventArgs e) { ProtocolBox.SelectedIndex = Convert.ToInt32(((FrameworkElement)sender).Tag, CultureInfo.InvariantCulture); }
        void ProfileErrorText(string text) { ProfileError.Text = text ?? ""; Show(ProfileError, !String.IsNullOrEmpty(text)); EditorErrorText(text); }
        void EditorErrorText(string text) { EditorError.Text = text ?? ""; Show(EditorError, !String.IsNullOrEmpty(text)); Show(EditorExtras, String.IsNullOrEmpty(text) && profileId != null); }

        bool CanReuseCredentials
        {
            get { return profileId != null && authPresent && Protocols[Math.Max(0, ProtocolBox.SelectedIndex)] == loadedProtocol && (ObfsSwitch.IsChecked == true ? "salamander" : "") == (loadedObfs ?? ""); }
        }

        bool TryProfileRequest(out Dictionary<string, object> request)
        {
            request = null; int port;
            if (String.IsNullOrWhiteSpace(ProfileHost.Text)) { EditorErrorText("Укажи адрес сервера."); return false; }
            if (!Int32.TryParse(ProfilePort.Text, NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535) { EditorErrorText("Порт: целое число от 1 до 65535."); return false; }
            int kind = Math.Max(0, ProtocolBox.SelectedIndex); bool hy = kind == 0;
            string name = String.IsNullOrWhiteSpace(ProfileName.Text) ? ProfileHost.Text.Trim() : ProfileName.Text.Trim();
            var profile = new Dictionary<string, object> { { "name", name }, { "protocol", Protocols[kind] }, { "host", ProfileHost.Text.Trim() }, { "port", port } };
            if ((hy || kind == 3) && !String.IsNullOrWhiteSpace(ProfileSni.Text)) profile["tls_server_name"] = ProfileSni.Text.Trim();
            bool obfs = ObfsSwitch.IsChecked == true;
            if (hy && obfs) profile["obfs"] = "salamander";
            if (hy)
            {
                if (ProfileAuth.Password.Length > 0)
                {
                    var secret = new Dictionary<string, object> { { "auth", ProfileAuth.Password } };
                    if (obfs) { if (ProfileObfsPassword.Password.Length == 0) { EditorErrorText("Введи пароль маскировки."); return false; } secret["obfs_password"] = ProfileObfsPassword.Password; }
                    profile["credentials"] = secret;
                }
                else if (ProfileObfsPassword.Password.Length > 0) { EditorErrorText("Для смены маскировки введи и основной пароль."); return false; }
                else if (!CanReuseCredentials) { EditorErrorText("Введи пароль. После смены типа или маскировки пароль нужен заново."); return false; }
            }
            else if (ProxyAuthSwitch.IsChecked != true) profile["credentials"] = new Dictionary<string, object>();
            else if (ProfileUser.Text.Length > 0 || ProfilePassword.Password.Length > 0)
            {
                if (ProfileUser.Text.Length == 0 || ProfilePassword.Password.Length == 0) { EditorErrorText("Нужны и логин, и пароль."); return false; }
                profile["credentials"] = new Dictionary<string, object> { { "username", ProfileUser.Text }, { "password", ProfilePassword.Password } };
            }
            else if (!CanReuseCredentials) { EditorErrorText("Введи логин и пароль. После смены типа пароль нужен заново."); return false; }
            request = new Dictionary<string, object> { { "profile", profile } };
            if (profileId != null) request["profile_id"] = profileId;
            EditorErrorText(""); return true;
        }

        // A saved or imported profile becomes the one used for the next start: that is what "add" means here.
        async Task UseProfile(Dictionary<string, object> result)
        {
            var saved = Child(result, "profile");
            if (!Bridge.Ok(result) || saved == null) return;
            if (!Flag(saved, "selected")) result = await ProfileAction("select-profile", new Dictionary<string, object> { { "profile_id", Text(saved, "profile_id", "") } });
            if (Bridge.Ok(result)) { LinkInput.Text = ""; Navigate(AppPage.Connection); SetOperation("Готово: «" + Text(saved, "name", "подключение") + "» будет использовано при запуске."); }
        }

        async void OnSaveProfile(object sender, RoutedEventArgs e) { Dictionary<string, object> request; if (TryProfileRequest(out request)) await UseProfile(await ProfileAction("save-profile", request)); }
        async void OnTestProfile(object sender, RoutedEventArgs e)
        {
            var selected = profiles.FirstOrDefault(item => Flag(item, "selected"));
            string id = profileId ?? (selected != null ? Text(selected, "profile_id", null) : null);
            if (id != null) await ProfileAction("test-profile", new Dictionary<string, object> { { "profile_id", id } });
        }
        void OnLinkKey(object sender, KeyEventArgs e) { if (e.Key == Key.Enter) OnAddLink(sender, e); }
        async void OnAddLink(object sender, RoutedEventArgs e)
        {
            string link = LinkInput.Text.Trim();
            if (link.Length == 0) { ProfileErrorText("Вставь ссылку подключения от своего сервера."); LinkInput.Focus(); return; }
            await UseProfile(await ProfileAction("import-profile", new Dictionary<string, object> { { "uri", link } }));
        }

        async void OnImportFile(object sender, RoutedEventArgs e)
        {
            var file = new Microsoft.Win32.OpenFileDialog { Filter = "JSON профиль (*.json)|*.json", CheckFileExists = true };
            if (file.ShowDialog(this) != true) return;
            Dictionary<string, object> profile;
            try
            {
                if (new FileInfo(file.FileName).Length > 65536) { ProfileErrorText("Файл больше 64 КиБ."); return; }
                profile = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(File.ReadAllText(file.FileName));
                if (profile == null) { ProfileErrorText("Нужен объект профиля JSON."); return; }
            }
            catch (Exception) { ProfileErrorText("Не удалось прочитать профиль JSON. Проверь формат и доступ к файлу."); return; }
            if (Text(profile, "protocol", "") == "hysteria2" && String.IsNullOrEmpty(Text(Child(profile, "credentials"), "auth", "")))
            {
                NewProfile(); ProfileName.Text = Text(profile, "name", ""); ProfileHost.Text = Text(profile, "host", ""); ProfilePort.Text = Text(profile, "port", "443");
                ProfileSni.Text = Text(profile, "tls_server_name", ""); ObfsSwitch.IsChecked = Text(profile, "obfs", "") == "salamander"; UpdateProfileRows();
                ShowEditor("Введи пароль"); ProfileAuth.Focus(); return;
            }
            await UseProfile(await ProfileAction("import-profile", new Dictionary<string, object> { { "profile", profile } }));
        }

        // Export opens in the same card: the profile being edited, otherwise the selected one.
        string exportId;
        void OnExportProfile(object sender, RoutedEventArgs e)
        {
            var selected = profiles.FirstOrDefault(item => Flag(item, "selected"));
            exportId = profileId ?? (selected != null ? Text(selected, "profile_id", null) : null);
            if (exportId == null) { ProfileErrorText("Сначала добавь подключение."); return; }
            ExportSecretsSwitch.IsChecked = false;
            OpenSheet("Экспорт подключения", ExportSheet);
        }

        async void OnExportChoose(object sender, RoutedEventArgs e)
        {
            var file = new Microsoft.Win32.SaveFileDialog { Title = "Экспорт подключения в новый файл", Filter = "JSON профиль (*.json)|*.json", DefaultExt = "json", AddExtension = true, OverwritePrompt = false, FileName = "connection.json" };
            if (file.ShowDialog(this) != true) return;
            var result = await ProfileAction("export-profile", new Dictionary<string, object> { { "profile_id", exportId }, { "destination", file.FileName }, { "include_secrets", ExportSecretsSwitch.IsChecked == true } });
            if (Bridge.Ok(result)) CloseSheet();
        }
    }
}
