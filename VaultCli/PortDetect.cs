using System.IO.Ports;

namespace VaultCli;

// Cross-platform serial-port enumeration. We do NOT try to identify the device
// by VID/PID here — the PING handshake in VaultClient is authoritative (only a
// secrets-courier answers "OK PONG vault/..."), so a plain port list is enough
// and keeps this dependency-free (no WMI / no platform lock-in).
internal static class PortDetect
{
    public static List<string> FindCandidatePorts()
    {
        var ports = new List<string>(SerialPort.GetPortNames());

        // GetPortNames is reliable on Windows (COMx). On Linux/macOS it can miss
        // freshly-enumerated CDC devices — add the usual device-node globs.
        if (!OperatingSystem.IsWindows())
        {
            foreach (var pat in new[]
                     {
                         "/dev/ttyACM*", "/dev/ttyUSB*",
                         "/dev/tty.usbmodem*", "/dev/tty.usbserial*",
                         "/dev/cu.usbmodem*", "/dev/cu.usbserial*"
                     })
            {
                var dir = Path.GetDirectoryName(pat)!;
                var glob = Path.GetFileName(pat);
                if (!Directory.Exists(dir)) continue;
                foreach (var f in Directory.EnumerateFiles(dir, glob))
                    if (!ports.Contains(f)) ports.Add(f);
            }
        }

        // Stable order; on Windows sort COM2 < COM10 numerically.
        ports.Sort((a, b) =>
        {
            int na = ExtractNum(a), nb = ExtractNum(b);
            return na != nb ? na.CompareTo(nb)
                            : string.CompareOrdinal(a, b);
        });
        return ports;
    }

    private static int ExtractNum(string s)
    {
        int i = 0, n = 0; bool any = false;
        for (; i < s.Length; i++)
            if (char.IsDigit(s[i])) { n = n * 10 + (s[i] - '0'); any = true; }
            else if (any) break;
        return any ? n : int.MaxValue;
    }
}
