using System.Management;
using System.Text.RegularExpressions;

namespace VaultCli;

// Port detection lifted from CheckESP32/Program.cs (copy-per-tool, repo convention).
internal static class PortDetect
{
    private static readonly string[] KnownVids =
    {
        "VID_10C4", // Silicon Labs (CP210x)
        "VID_1A86", // QinHeng (CH340/CH341)
        "VID_303A", // Espressif (native USB on ESP32-S2/S3/C3/C6/H2)
        "VID_0403"  // FTDI (FT232 on some dev boards)
    };

    private static readonly string[] KnownChips = { "CP210", "CH340" };

    private sealed record PnpDevice(
        string Name, string Caption, string DeviceId, string Manufacturer);

    public static List<string> FindEspPorts()
    {
        var ports = new List<string>();
        foreach (var d in LoadAllPnpDevices())
        {
            var haystack = $"{d.Name} {d.Caption}";

            bool isEsp = KnownChips.Any(c =>
                haystack.Contains(c, StringComparison.OrdinalIgnoreCase));
            if (!isEsp)
                isEsp = KnownVids.Any(v =>
                    d.DeviceId.Contains(v, StringComparison.OrdinalIgnoreCase));
            if (!isEsp) continue;

            var port = ExtractComPort(haystack);
            if (port is not null && !ports.Contains(port))
                ports.Add(port);
        }
        return ports;
    }

    private static List<PnpDevice> LoadAllPnpDevices()
    {
        var list = new List<PnpDevice>();
        using var searcher = new ManagementObjectSearcher(
            "SELECT Name, Caption, DeviceID, Manufacturer FROM Win32_PnPEntity");

        foreach (ManagementObject d in searcher.Get())
        {
            using (d)
            {
                list.Add(new PnpDevice(
                    (d["Name"] as string) ?? string.Empty,
                    (d["Caption"] as string) ?? string.Empty,
                    (d["DeviceID"] as string) ?? string.Empty,
                    (d["Manufacturer"] as string) ?? string.Empty));
            }
        }
        return list;
    }

    private static string? ExtractComPort(string text)
    {
        var match = Regex.Match(text, @"\bCOM\d+\b", RegexOptions.IgnoreCase);
        return match.Success ? match.Value.ToUpperInvariant() : null;
    }
}
