using System;

// When the panel that is hidden in the tray may come back by itself. It has no WPF dependency so a native test
// can run it: the panel used to reopen on the first unreadable poll, which made it vanish and reappear seconds after start.
internal static class AttentionPolicy
{
    internal const int ConfirmedPolls = 2, TransientPolls = 4;

    static readonly string[] Attention = { "failed", "connection-failed", "shutdown-unconfirmed", "control-unavailable-guest-running", "stopped" };

    // Why the user must look at the panel, or null while everything runs.
    internal static string Classify(bool readable, string workState, string gatewayState, bool outcomeUnknown, bool networkExpected = true)
    {
        if (outcomeUnknown) return "outcome-unknown";
        if (!readable) return "status-unreadable";
        // An offline Linux session intentionally has no network process.
        if (Array.IndexOf(Attention, workState) >= 0 || (networkExpected && Array.IndexOf(Attention, gatewayState) >= 0)) return "vm-attention";
        if (workState == "unknown" || (networkExpected && gatewayState == "unknown")) return "state-unknown";
        return null;
    }

    // Polls in a row that must report the same reason before the panel reopens: one unreadable or half-written
    // state file is noise, a stopped or failed machine is not.
    internal static bool ShouldReopen(string reason, int consecutive)
    {
        if (reason == null) return false;
        if (reason == "outcome-unknown") return true;
        return consecutive >= (reason == "vm-attention" ? ConfirmedPolls : TransientPolls);
    }
}
