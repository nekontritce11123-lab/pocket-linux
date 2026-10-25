using System;

internal static class LauncherAttentionRegression
{
    static void Check(bool value, string message) { if (!value) throw new Exception(message); }

    static int Main()
    {
        Check(AttentionPolicy.Classify(true, "running", "stopped", false, false) == null,
              "An intentional offline session must stay in the tray");
        Check(AttentionPolicy.Classify(true, "running", "stopped", false, true) == "vm-attention",
              "Loss of an expected proxy must still need attention");
        Check(AttentionPolicy.Classify(true, "running", "connection-failed", false) == "vm-attention",
              "A failed proxy must remain visible");
        Check(AttentionPolicy.Classify(true, "stopped", "stopped", false, false) == "vm-attention",
              "Offline guest shutdown must still need attention");
        Check(AttentionPolicy.Classify(true, "failed", "stopped", false, false) == "vm-attention",
              "Offline guest failure must still need attention");
        Check(AttentionPolicy.Classify(true, "unknown", "stopped", false, false) == "state-unknown",
              "Missing guest state must not be hidden by offline mode");
        Check(AttentionPolicy.Classify(false, "running", "stopped", false, false) == "status-unreadable",
              "Unreadable status must still need attention");
        Check(AttentionPolicy.Classify(false, "running", "stopped", true, false) == "outcome-unknown",
              "Unknown operation outcome must take precedence");
        Check(!AttentionPolicy.ShouldReopen(null, 100), "A healthy session never reopens");
        Check(!AttentionPolicy.ShouldReopen("vm-attention", 1) && AttentionPolicy.ShouldReopen("vm-attention", 2),
              "A real failure must reopen after two confirmations");
        Console.WriteLine("PASS Linux attention: 10 checks");
        return 0;
    }
}
