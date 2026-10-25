using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Threading;
using Wpf.Ui.Controls;
using Button = System.Windows.Controls.Button;
using TextBlock = System.Windows.Controls.TextBlock;

namespace WindowsClaude.Launcher
{
    // The tray menu in the panel's own style: a white rounded card of the same rows, shown above the cursor and closed
    // when it loses focus. The stock Windows context menu ignored the panel's palette and fonts.
    sealed class TrayMenu : Window
    {
        internal sealed class Item
        {
            public string Text, Caption;
            public SymbolRegular Icon;
            public Brush Tint;
            public bool Enabled = true;
            public Action Run;
        }

        static TrayMenu current;
        [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);

        internal static void ShowAt(System.Drawing.Point cursor, Item[] items)
        {
            if (current != null) { current.Dismiss(); current = null; }
            current = new TrayMenu(items, cursor);
            current.Show();
        }

        readonly System.Drawing.Point cursor;
        readonly DateTime shown = DateTime.UtcNow;
        bool dismissed;

        // Closing a window that is already closing throws, and Deactivated fires while the click path closes it.
        void Dismiss() { if (dismissed) return; dismissed = true; Close(); }

        TrayMenu(Item[] items, System.Drawing.Point cursor)
        {
            this.cursor = cursor;
            WindowStyle = WindowStyle.None; AllowsTransparency = true; Background = Brushes.Transparent;
            ShowInTaskbar = false; Topmost = true; ResizeMode = ResizeMode.NoResize; SizeToContent = SizeToContent.WidthAndHeight;
            var rows = new StackPanel();
            for (int index = 0; index < items.Length; index++)
            {
                if (index > 0) rows.Children.Add(new Border { Height = 1, Margin = new Thickness(46, 0, 0, 0), Background = (Brush)Application.Current.FindResource("Line") });
                rows.Children.Add(Row(items[index]));
            }
            var card = new Border
            {
                Margin = new Thickness(10), MinWidth = 210, CornerRadius = new CornerRadius(12), ClipToBounds = true,
                Background = (Brush)Application.Current.FindResource("Group"), Child = rows,
                Effect = new DropShadowEffect { BlurRadius = 14, ShadowDepth = 2, Opacity = 0.2, Color = Colors.Black },
                RenderTransform = new TranslateTransform(0, 10)
            };
            Content = card;
            Loaded += delegate
            {
                Place();
                card.BeginAnimation(OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(130)));
                ((TranslateTransform)card.RenderTransform).BeginAnimation(TranslateTransform.YProperty,
                    new DoubleAnimation(10, 0, TimeSpan.FromMilliseconds(170)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } });
                Activate(); SetForegroundWindow(new System.Windows.Interop.WindowInteropHelper(this).Handle);
                // A tray click may not hand focus over; without activation Deactivated never fires, so poll once.
                var guard = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
                guard.Tick += delegate { if (!IsActive && DateTime.UtcNow - shown > TimeSpan.FromMilliseconds(900)) { guard.Stop(); Dismiss(); } };
                guard.Start();
            };
            Deactivated += delegate { if (DateTime.UtcNow - shown > TimeSpan.FromMilliseconds(300)) Dismiss(); };
            KeyDown += delegate (object sender, KeyEventArgs e) { if (e.Key == Key.Escape) Dismiss(); };
            Closed += delegate { if (current == this) current = null; };
        }

        static Button Row(Item item)
        {
            var icon = new Border
            {
                Width = 24, Height = 24, CornerRadius = new CornerRadius(7), Margin = new Thickness(0, 0, 10, 0), Background = item.Tint,
                Child = new SymbolIcon { Symbol = item.Icon, FontSize = 13, Foreground = Brushes.White }
            };
            var text = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            text.Children.Add(new TextBlock { Text = item.Text, Style = (Style)Application.Current.FindResource("RowText"), FontSize = 13.5 });
            if (!String.IsNullOrEmpty(item.Caption))
                text.Children.Add(new TextBlock { Text = item.Caption, Style = (Style)Application.Current.FindResource("Caption"), FontSize = 11.5, TextWrapping = TextWrapping.NoWrap });
            var line = new DockPanel();
            DockPanel.SetDock(icon, Dock.Left);
            line.Children.Add(icon); line.Children.Add(text);
            var button = new Button { Style = (Style)Application.Current.FindResource("MenuRow"), Content = line, IsEnabled = item.Enabled };
            button.Click += delegate (object sender, RoutedEventArgs e) { var owner = Window.GetWindow(button) as TrayMenu; if (owner != null) owner.Dismiss(); if (item.Run != null) item.Run(); };
            return button;
        }

        // Above and to the left of the cursor (its corner touches the pointer), kept inside the work area of the screen the tray is on.
        void Place()
        {
            var screen = System.Windows.Forms.Screen.FromPoint(cursor).WorkingArea;
            var source = PresentationSource.FromVisual(this);
            double sx = source == null ? 1 : source.CompositionTarget.TransformFromDevice.M11, sy = source == null ? 1 : source.CompositionTarget.TransformFromDevice.M22;
            double x = cursor.X * sx - ActualWidth + 10, y = cursor.Y * sy - ActualHeight + 4;
            Left = Math.Max(screen.Left * sx, Math.Min(x, screen.Right * sx - ActualWidth));
            Top = Math.Max(screen.Top * sy, Math.Min(y, screen.Bottom * sy - ActualHeight));
        }
    }
}
