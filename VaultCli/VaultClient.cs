using System.IO.Ports;
using System.Text;

namespace VaultCli;

internal sealed class VaultException : Exception
{
    public int ExitCode { get; }
    public VaultException(int exitCode, string message) : base(message)
        => ExitCode = exitCode;
}

// Serial transport + line protocol for the secrets-vault firmware.
internal sealed class VaultClient : IDisposable
{
    private readonly SerialPort _port;

    private VaultClient(SerialPort port) => _port = port;

    // Opens the given port (or auto-detects), handshakes, returns a client.
    public static VaultClient Connect(string? explicitPort)
    {
        var candidates = explicitPort is not null
            ? new List<string> { explicitPort }
            : PortDetect.FindCandidatePorts();

        if (candidates.Count == 0)
            throw new VaultException(3, "no serial port found (is it plugged in?)");

        foreach (var name in candidates)
        {
            SerialPort? sp = null;
            try
            {
                // DTR true (some USB-CDC stacks gate host->device TX on it),
                // RTS false — asserting RTS drives BOOT/reset on this board and
                // would reboot the ESP, wiping the vault between invocations.
                sp = new SerialPort(name, 115200, Parity.None, 8, StopBits.One)
                {
                    ReadTimeout = 1500,
                    WriteTimeout = 3000,
                    NewLine = "\n",
                    DtrEnable = true,
                    RtsEnable = false,
                };
                sp.Open();
                Thread.Sleep(300);
                sp.DiscardInBuffer();

                var client = new VaultClient(sp);
                if (client.TryPing(6))   // tolerate a boot/enumeration race
                {
                    sp.ReadTimeout = 3000;
                    return client;
                }

                sp.Close();
                sp.Dispose();
            }
            catch (VaultException)
            {
                sp?.Dispose();
            }
            catch (Exception)
            {
                sp?.Dispose();
            }
        }

        throw new VaultException(4,
            explicitPort is not null
                ? $"{explicitPort} did not answer as a secrets-courier"
                : "no secrets-courier responded on any serial port");
    }

    private bool TryPing(int attempts)
    {
        for (int i = 0; i < attempts; i++)
        {
            try
            {
                _port.DiscardInBuffer();
                _port.Write("PING\n");
                var deadline = DateTime.UtcNow.AddMilliseconds(1500);
                while (DateTime.UtcNow < deadline)
                {
                    string line = _port.ReadLine().TrimEnd('\r');
                    if (line.StartsWith("OK PONG vault/", StringComparison.Ordinal))
                        return true;
                }
            }
            catch (TimeoutException) { /* retry */ }
            Thread.Sleep(300);
        }
        return false;
    }

    public sealed record Response(IReadOnlyList<string> DataLines, string Terminal);

    // Sends one command line, reads data lines until OK/ERR terminal line.
    public Response Request(string command)
    {
        try
        {
            _port.DiscardInBuffer();
            _port.Write(command + "\n");

            var data = new List<string>();
            while (true)
            {
                string line = _port.ReadLine().TrimEnd('\r');
                if (line.StartsWith("OK", StringComparison.Ordinal) ||
                    line.StartsWith("ERR", StringComparison.Ordinal))
                    return new Response(data, line);
                data.Add(line);
            }
        }
        catch (TimeoutException)
        {
            throw new VaultException(7, "timeout waiting for device response");
        }
    }

    public void Authenticate(string code)
    {
        var r = Request("AUTH " + code);
        if (r.Terminal.StartsWith("OK AUTHED", StringComparison.Ordinal)) return;
        if (r.Terminal.StartsWith("ERR 409 SEALED", StringComparison.Ordinal))
            throw new VaultException(1,
                "device is SEALED — use 'unseal --code' instead of 'set/seal'");
        if (r.Terminal.StartsWith("ERR 401", StringComparison.Ordinal))
            throw new VaultException(5, "bad code");
        throw new VaultException(1, "auth failed: " + r.Terminal);
    }

    // Wrong code here makes the device DESTROY the payload (self-destruct).
    public void Unseal(string code)
    {
        var r = Request("UNSEAL " + code);
        if (r.Terminal.StartsWith("OK UNSEALED", StringComparison.Ordinal)) return;
        if (r.Terminal.StartsWith("ERR 409 NOTSEALED", StringComparison.Ordinal))
            throw new VaultException(1, "nothing sealed on the device");
        if (r.Terminal.StartsWith("ERR 401", StringComparison.Ordinal))
            throw new VaultException(5,
                "WRONG CODE — payload was destroyed (self-destruct)");
        throw new VaultException(1, "unseal failed: " + r.Terminal);
    }

    public static string B64(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    public static string UnB64(string s) =>
        Encoding.UTF8.GetString(Convert.FromBase64String(s));

    public void Dispose()
    {
        try { if (_port.IsOpen) _port.Close(); } catch { /* ignore */ }
        _port.Dispose();
    }
}
