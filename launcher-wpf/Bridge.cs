// Backend protocol, timeouts and safety rules of the launcher (carried over from the former WinForms panel, now removed).
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

internal static class Bridge
{
    private sealed class PendingReply : Dictionary<string,object>
    {
        internal readonly Task<Dictionary<string,object>> Settled;
        internal PendingReply(Dictionary<string,object> reply,Task<Dictionary<string,object>> settled) : base(reply) { Settled = settled; }
    }

    internal static Task<Dictionary<string,object>> PendingOperation(Dictionary<string,object> reply)
    {
        PendingReply pending = reply as PendingReply;
        return pending == null ? null : pending.Settled;
    }
    internal static string Root
    {
        get { return Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location); }
    }

    internal static string Quote(string value)
    {
        StringBuilder result = new StringBuilder("\"");
        int slashes = 0;
        foreach (char letter in value)
        {
            if (letter == '\\') { slashes++; continue; }
            if (letter == '"') result.Append('\\', slashes * 2 + 1).Append('"');
            else result.Append('\\', slashes).Append(letter);
            slashes = 0;
        }
        return result.Append('\\', slashes * 2).Append('"').ToString();
    }

    internal static Dictionary<string, object> Failure(string message)
    {
        return new Dictionary<string, object> { { "ok", false }, { "message", message } };
    }

    internal static bool Ok(Dictionary<string, object> value)
    {
        return value != null && value.ContainsKey("ok") && value["ok"] is bool && (bool)value["ok"];
    }

    internal static string Message(Dictionary<string, object> value)
    {
        return value != null && value.ContainsKey("message") ? Convert.ToString(value["message"]) : Ok(value) ? "Готово." : "Ответ не получен.";
    }

    internal static Dictionary<string, object> Run(string root, string action, object payload)
    {
        return RunAsync(root, action, payload).GetAwaiter().GetResult();
    }

    internal static int TimeoutMilliseconds(string action)
    {
        switch (action)
        {
            case "start": return 600000;
            case "diagnose": return 300000;
            case "test-profile": return 330000;
            case "stop": return 510000;
            case "repair-gateway":
            case "recover-session": return 180000;
            case "prepare-host": return 210000;
            default: return 30000;
        }
    }

    internal static async Task<Dictionary<string, object>> RunAsync(string root, string action, object payload)
    {
        if (action == "prepare-components" || action == "repair-gateway")
            return await PrepareComponentsAsync(root).ConfigureAwait(false);
        string python = Path.Combine(root, "runtime", "python-3.12.14", "python.exe");
        string backend = Path.Combine(root, "scripts", "portable_app.py");
        if (!File.Exists(python) || !File.Exists(Path.Combine(root, "runtime", "qemu-11.1.0", "qemu-system-x86_64.exe"))
            || !File.Exists(Path.Combine(root, "runtime", "host-files", "HostFiles.exe")) || !File.Exists(Path.Combine(root, "PocketNet.exe")))
        {
            var preparation = await PrepareComponentsAsync(root).ConfigureAwait(false);
            if (!Ok(preparation)) return preparation;
        }
        if (!File.Exists(backend))
            return Failure("Не найдены файлы приложения. Распакуй полный комплект рядом с Launcher.exe.");
        string[] args = { "-X", "utf8", "-I", "-S", "-B", backend, "--root", root, "--action", action };
        ProcessStartInfo info = new ProcessStartInfo(python, String.Join(" ", args.Select(Quote)));
        info.WorkingDirectory = root;
        return await ExecuteProcessAsync(info, TimeoutMilliseconds(action), payload).ConfigureAwait(false);
    }

    static readonly SemaphoreSlim preparationGate = new SemaphoreSlim(1, 1);
    static async Task<Dictionary<string, object>> PrepareComponentsAsync(string root)
    {
        await preparationGate.WaitAsync().ConfigureAwait(false);
        try
        {
            string script = Path.Combine(root, "scripts", "Prepare-Dependencies.ps1");
            if (!File.Exists(script)) return Failure("Не найден переносимый пакет компонентов. Распакуй полный архив.");
            string powershell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
            var info = new ProcessStartInfo(powershell, String.Join(" ", new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script, "-Project", root }.Select(Quote)));
            info.WorkingDirectory = root;
            var reply = await ExecuteProcessAsync(info, 180000, null).ConfigureAwait(false);
            string code = reply.ContainsKey("code") ? Convert.ToString(reply["code"]) : "error";
            reply["message"] = Ok(reply) ? "Переносимые компоненты готовы. Установка в Windows не нужна." :
                code == "runtime_busy" ? "Сначала штатно выключи Linux, затем повтори восстановление компонентов." :
                code == "invalid_package" ? "Пакет компонентов повреждён. Распакуй полный проверенный архив." :
                code == "package_missing" ? "Не найден пакет компонентов. Распакуй полный архив Pocket Linux." :
                "Не удалось распаковать компоненты рядом с лаунчером. Проверь свободное место и доступ к папке.";
            return reply;
        }
        finally { preparationGate.Release(); }
    }

    internal static Dictionary<string, object> Unknown(string message, string code)
    {
        Dictionary<string, object> failure = Failure(message);
        failure["code"] = code;
        failure["outcome_unknown"] = true;
        return failure;
    }

    internal static Task<Dictionary<string, object>> RunProcessAsync(ProcessStartInfo info, int timeoutMilliseconds)
    {
        return ExecuteProcessAsync(info, timeoutMilliseconds, null);
    }

    private static async Task<Dictionary<string, object>> ExecuteProcessAsync(ProcessStartInfo info, int timeoutMilliseconds, object payload)
    {
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardInput = info.RedirectStandardOutput = info.RedirectStandardError = true;
        info.StandardOutputEncoding = info.StandardErrorEncoding = Encoding.UTF8;
        Process process = new Process { StartInfo = info, EnableRaisingEvents = true };
        TaskCompletionSource<bool> exited = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        process.Exited += delegate { exited.TrySetResult(true); };
        try { process.Start(); }
        catch (Exception error)
        {
            process.Dispose();
            if (!(error is System.ComponentModel.Win32Exception) && !(error is InvalidOperationException) && !(error is IOException)) throw;
            Dictionary<string, object> failure = Failure("Не удалось запустить служебный компонент. Проверь доступ к папке и целостность файлов.");
            failure["code"] = "process_start_failed";
            return failure;
        }
        Task<Dictionary<string, object>> response = SettleResponseAsync(ReadResponseAsync(process, exited.Task, payload), exited.Task);
        if (await Task.WhenAny(response, Task.Delay(timeoutMilliseconds)).ConfigureAwait(false) != response)
        {
            // Keep draining pipes until the child exits; timeout never terminates a supervisor or a VM.
            Task cleanup = response.ContinueWith(completed => { var observed = completed.Exception; process.Dispose(); },
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            return new PendingReply(Unknown("Ответ не получен вовремя. Операция может продолжаться. Дождись завершения служебного процесса и повтори диагностику. VM и служебные процессы не останавливались.", "timeout"),response);
        }
        try
        {
            Dictionary<string,object> reply = await response.ConfigureAwait(false);
            string code = reply.ContainsKey("code") ? Convert.ToString(reply["code"]) : "";
            return new[] {"invalid_response","process_failed","transport_error"}.Contains(code) ? new PendingReply(reply,response) : reply;
        }
        finally { process.Dispose(); }
    }

    private static async Task<Dictionary<string,object>> SettleResponseAsync(Task<Dictionary<string,object>> response,Task exited)
    {
        await Task.WhenAll(response,exited).ConfigureAwait(false);
        return await response.ConfigureAwait(false);
    }

    private static async Task<Dictionary<string, object>> ReadResponseAsync(Process process, Task exited, object payload)
    {
        try
        {
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            if (payload != null)
            {
                byte[] body = Encoding.UTF8.GetBytes(new JavaScriptSerializer().Serialize(payload));
                await process.StandardInput.BaseStream.WriteAsync(body, 0, body.Length).ConfigureAwait(false);
                await process.StandardInput.BaseStream.FlushAsync().ConfigureAwait(false);
            }
            process.StandardInput.Close();
            await Task.WhenAll(exited, stdout, stderr).ConfigureAwait(false);
            Dictionary<string, object> result;
            try { result = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(stdout.Result.Trim()); }
            catch (ArgumentException) { result = null; }
            catch (InvalidOperationException) { result = null; }
            if (result == null || !result.ContainsKey("ok") || !(result["ok"] is bool))
                return Unknown("Служебный компонент не вернул корректный ответ. Исход операции не подтверждён. Проверь состояние через диагностику.", "invalid_response");
            if (process.ExitCode != 0 && Ok(result))
                return Unknown("Служебный компонент завершился с ошибкой. Исход операции не подтверждён. Проверь состояние через диагностику.", "process_failed");
            return result;
        }
        catch (Exception error)
        {
            if (!(error is IOException) && !(error is InvalidOperationException) && !(error is ObjectDisposedException)) throw;
            return Unknown("Связь со служебным компонентом прервалась. Исход операции неизвестен. Проверь состояние через диагностику.", "transport_error");
        }
    }

}
