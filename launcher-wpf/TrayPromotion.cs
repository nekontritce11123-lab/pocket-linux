using System;
using Microsoft.Win32;

// Windows 11 keeps a new tray icon behind the chevron. The panel hides itself into the tray while Windows runs,
// so the icon of this exact Launcher.exe is promoted to the visible area once. A value the user already set is never overridden.
internal static class TrayPromotion
{
    internal static bool TryPromote(string exePath)
    {
        try
        {
            using (RegistryKey root = Registry.CurrentUser.OpenSubKey(@"Control Panel\NotifyIconSettings", true))
                return root != null && Promote(root, exePath);
        }
        catch (Exception) { return false; }
    }

    // True when an entry of this executable exists and is now promoted or was set by the user.
    internal static bool Promote(RegistryKey root, string exePath)
    {
        foreach (string name in root.GetSubKeyNames())
            using (RegistryKey key = root.OpenSubKey(name, true))
            {
                string path = key == null ? null : key.GetValue("ExecutablePath") as string;
                if (path == null || !String.Equals(path, exePath, StringComparison.OrdinalIgnoreCase)) continue;
                if (key.GetValue("IsPromoted") == null) key.SetValue("IsPromoted", 1, RegistryValueKind.DWord);
                return true;
            }
        return false;
    }
}
