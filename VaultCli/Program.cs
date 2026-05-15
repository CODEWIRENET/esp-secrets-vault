using VaultCli;

// Exit codes: 0 ok · 1 protocol · 2 usage · 3 no port · 4 not a courier
//             5 bad code (UNSEAL with wrong code => payload destroyed) · 7 timeout

try
{
    return Run(args);
}
catch (VaultException ex)
{
    Console.Error.WriteLine("error: " + ex.Message);
    return ex.ExitCode;
}
catch (Exception ex)
{
    Console.Error.WriteLine("error: " + ex.Message);
    return 1;
}

static int Run(string[] args)
{
    if (args.Length == 0) return Usage();

    string cmd = args[0].ToLowerInvariant();
    var rest = args.Skip(1).ToList();

    string? port = TakeOpt(rest, "--port");
    bool json = TakeFlag(rest, "--json");
    string? code = TakeOpt(rest, "--code");
    string? hour = TakeOpt(rest, "--hour");
    string? minutes = TakeOpt(rest, "--minutes");

    switch (cmd)
    {
        case "status":
        {
            using var c = VaultClient.Connect(port);
            var r = c.Request("STATUS");
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            string body = r.Terminal.Substring(3);
            Console.WriteLine(json ? ToJson(body) : body);
            return 0;
        }

        // PC A: stage one item (repeat for more), code is on the device screen.
        case "set":
        {
            if (rest.Count < 2) return Usage("set needs <key> <value>");
            if (code is null) return Usage("set needs --code");
            if (hour is not null && minutes is not null)
                return Usage("--hour and --minutes are mutually exclusive");
            long? ttl = TtlSeconds(hour, minutes);
            string key = rest[0], val = rest[1];

            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            if (ttl is not null)
            {
                var t = c.Request("TTL " + ttl);
                if (!t.Terminal.StartsWith("OK", StringComparison.Ordinal))
                    return Fail(t.Terminal);
            }
            var r = c.Request($"SET {VaultClient.B64(key)} {VaultClient.B64(val)}");
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            Console.WriteLine("staged");
            return 0;
        }

        // PC A: encrypt staged items to flash, hide the code. Unplug & carry.
        case "seal":
        {
            if (code is null) return Usage("seal needs --code");
            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            var r = c.Request("SEAL");
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            Console.WriteLine("sealed — safe to unplug");
            return 0;
        }

        // PC B: decrypt. WRONG CODE DESTROYS THE PAYLOAD.
        case "unseal":
        {
            if (code is null) return Usage("unseal needs --code");
            using var c = VaultClient.Connect(port);
            c.Unseal(code);
            Console.WriteLine("unsealed — use 'get'/'list'");
            return 0;
        }

        // PC B (after unseal) or PC A (while staging) — no code needed here.
        case "get":
        {
            if (rest.Count < 1) return Usage("get needs <key>");
            using var c = VaultClient.Connect(port);
            var r = c.Request("GET " + VaultClient.B64(rest[0]));
            if (r.Terminal.StartsWith("ERR 409", StringComparison.Ordinal))
                return Fail("device is SEALED — run: VaultCli unseal --code <code>", 1);
            if (r.Terminal.StartsWith("ERR 404", StringComparison.Ordinal))
                return Fail("not found", 1);
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            string value = r.DataLines.Count > 0
                ? VaultClient.UnB64(r.DataLines[0]) : "";
            if (json)
                Console.WriteLine($"{{\"key\":{JStr(rest[0])},\"value\":{JStr(value)}}}");
            else
                Console.Out.Write(value);
            return 0;
        }

        case "list":
        {
            using var c = VaultClient.Connect(port);
            var r = c.Request("LIST");
            if (r.Terminal.StartsWith("ERR 409", StringComparison.Ordinal))
                return Fail("device is SEALED — run: VaultCli unseal --code <code>", 1);
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            var keys = r.DataLines.Select(VaultClient.UnB64).ToList();
            if (json)
                Console.WriteLine("[" + string.Join(",", keys.Select(JStr)) + "]");
            else
                foreach (var k in keys) Console.WriteLine(k);
            return 0;
        }

        // Destroy everything (flash + RAM). Only valid before sealing.
        case "wipe":
        {
            if (code is null) return Usage("wipe needs --code");
            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            var r = c.Request("WIPE");
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            Console.WriteLine("wiped");
            return 0;
        }

        // Set the powered-time budget before sealing. 0 = destroy now, -1 = none.
        case "ttl":
        {
            if (code is null) return Usage("ttl needs --code");
            long? secs = TtlSeconds(hour, minutes);
            if (secs is null)
                return Usage("ttl needs --hour N|0|-1 or --minutes N|0|-1 "
                           + "(0 = destroy now, -1 = no expiry)");
            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            var r = c.Request("TTL " + secs);
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            Console.WriteLine(secs == 0 ? "destroyed" : "ok " + r.Terminal[3..]);
            return 0;
        }

        // Toggle display orientation 180° (also: tap the BOOT button).
        case "flip":
        {
            using var c = VaultClient.Connect(port);
            var r = c.Request("FLIP");
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            Console.WriteLine(r.Terminal[3..]);   // "FLIP 0" | "FLIP 1"
            return 0;
        }

        default:
            return Usage($"unknown command '{cmd}'");
    }
}

// null = neither flag. -1 = no expiry (any negative). 0 = destroy now.
// else positive seconds. --hour/--minutes mutually exclusive (checked upstream).
static long? TtlSeconds(string? hour, string? minutes)
{
    if (hour is not null)
    {
        long h = long.Parse(hour);
        return h < 0 ? -1 : h * 3600;
    }
    if (minutes is not null)
    {
        long m = long.Parse(minutes);
        return m < 0 ? -1 : m * 60;
    }
    return null;
}

static string? TakeOpt(List<string> a, string name)
{
    int i = a.IndexOf(name);
    if (i < 0 || i + 1 >= a.Count) return null;
    string v = a[i + 1];
    a.RemoveAt(i + 1);
    a.RemoveAt(i);
    return v;
}

static bool TakeFlag(List<string> a, string name)
{
    int i = a.IndexOf(name);
    if (i < 0) return false;
    a.RemoveAt(i);
    return true;
}

static int Fail(string msg, int code = 1)
{
    Console.Error.WriteLine("device: " + msg);
    return code;
}

static string JStr(string s)
{
    var sb = new System.Text.StringBuilder("\"");
    foreach (char ch in s)
        sb.Append(ch switch
        {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            _ => ch.ToString()
        });
    return sb.Append('"').ToString();
}

static string ToJson(string statusBody)
{
    var sb = new System.Text.StringBuilder("{");
    bool first = true;
    foreach (var tok in statusBody.Split(' ', StringSplitOptions.RemoveEmptyEntries))
    {
        int eq = tok.IndexOf('=');
        if (!first) sb.Append(',');
        if (eq < 0) sb.Append($"\"state\":{JStr(tok)}");
        else sb.Append($"{JStr(tok[..eq])}:{JStr(tok[(eq + 1)..])}");
        first = false;
    }
    return sb.Append('}').ToString();
}

static int Usage(string? err = null)
{
    if (err is not null) Console.Error.WriteLine("usage error: " + err);
    Console.Error.WriteLine(
        """
        VaultCli — secrets-courier (encrypted USB courier)

          # PC A — stage & seal
          VaultCli set  <key> <value> --code NNNNNN [--hour N | --minutes N]
          VaultCli seal               --code NNNNNN
          # unplug, carry the device, remember the code

          # PC B — unseal & read
          VaultCli unseal             --code NNNNNN     (WRONG CODE = DESTROYS payload)
          VaultCli get  <key>
          VaultCli list

          VaultCli status            [--port COMx] [--json]
          VaultCli ttl   --code NNNNNN  --hour N|0|-1 | --minutes N|0|-1
          VaultCli wipe  --code NNNNNN
          VaultCli flip                               (or tap BOOT button)

        TTL is powered-time (only counts while plugged in). N>0 hours/minutes,
        0 = destroy now, -1 = no expiry. Port is auto-detected (PING handshake).

        exit: 0 ok  1 protocol  2 usage  3 no port  4 not a courier
              5 bad code (payload destroyed on wrong unseal)  7 timeout
        """);
    return 2;
}
