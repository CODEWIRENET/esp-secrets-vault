using VaultCli;

// Exit codes: 0 ok · 1 protocol · 2 usage · 3 no port · 4 not vault
//             5 bad code · 6 locked · 7 timeout

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

        case "set":
        {
            if (rest.Count < 2) return Usage("set needs <key> <value>");
            if (code is null) return Usage("set needs --code");
            if (hour is not null && minutes is not null)
                return Usage("--hour and --minutes are mutually exclusive");
            long? ttl = TtlSeconds(hour, minutes);
            if (ttl == 0)
                return Usage("--hour/--minutes 0 with 'set' is contradictory; "
                           + "use 'VaultCli ttl --hour 0' or 'wipe' to close now");
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
            Console.WriteLine("ok");
            return 0;
        }

        case "get":
        {
            if (rest.Count < 1) return Usage("get needs <key>");
            if (code is null) return Usage("get needs --code");
            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            var r = c.Request("GET " + VaultClient.B64(rest[0]));
            if (r.Terminal.StartsWith("ERR 404", StringComparison.Ordinal))
                return Fail("not found", 1);
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            string value = r.DataLines.Count > 0
                ? VaultClient.UnB64(r.DataLines[0]) : "";
            if (json)
                Console.WriteLine(
                    $"{{\"key\":{JStr(rest[0])},\"value\":{JStr(value)}}}");
            else
                Console.Out.Write(value);
            return 0;
        }

        case "list":
        {
            if (code is null) return Usage("list needs --code");
            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            var r = c.Request("LIST");
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            var keys = r.DataLines.Select(VaultClient.UnB64).ToList();
            if (json)
                Console.WriteLine("[" +
                    string.Join(",", keys.Select(JStr)) + "]");
            else
                foreach (var k in keys) Console.WriteLine(k);
            return 0;
        }

        case "del":
        {
            if (rest.Count < 1) return Usage("del needs <key>");
            if (code is null) return Usage("del needs --code");
            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            var r = c.Request("DEL " + VaultClient.B64(rest[0]));
            if (r.Terminal.StartsWith("ERR 404", StringComparison.Ordinal))
                return Fail("not found", 1);
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            Console.WriteLine("ok");
            return 0;
        }

        case "wipe":
        {
            if (code is null) return Usage("wipe needs --code");
            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            var r = c.Request("WIPE");
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            Console.WriteLine("ok");
            return 0;
        }

        case "ttl":
        {
            if (code is null) return Usage("ttl needs --code");
            long? secs = TtlSeconds(hour, minutes);
            if (secs is null)
                return Usage("ttl needs --hour N|0|-1 or --minutes N|0|-1 "
                           + "(0 = close now, -1 = no expiry until power)");
            using var c = VaultClient.Connect(port);
            c.Authenticate(code);
            var r = c.Request("TTL " + secs);
            if (!r.Terminal.StartsWith("OK", StringComparison.Ordinal))
                return Fail(r.Terminal);
            Console.WriteLine(secs == 0 ? "closed" : "ok " + r.Terminal[3..]);
            return 0;
        }

        default:
            return Usage($"unknown command '{cmd}'");
    }
}

// null = neither flag given. -1 = infinite (any negative). 0 = close now.
// else positive seconds. --hour/--minutes are mutually exclusive (checked upstream).
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
        if (eq < 0) { sb.Append($"\"state\":{JStr(tok)}"); }
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
        VaultCli — talk to the secrets-vault ESP32

          VaultCli status [--port COMx] [--json]
          VaultCli set  <key> <value> --code NNNNNN [--hour N | --minutes N] [--port COMx]
          VaultCli get  <key>         --code NNNNNN [--port COMx] [--json]
          VaultCli list               --code NNNNNN [--port COMx] [--json]
          VaultCli del  <key>         --code NNNNNN [--port COMx]
          VaultCli wipe               --code NNNNNN [--port COMx]
          VaultCli ttl                --code NNNNNN  --hour N | --minutes N  [--port COMx]

        TTL: N>0 = lifetime; 0 = close & wipe now; -1 = no expiry until power/new ttl

        exit: 0 ok  1 protocol  2 usage  3 no port  4 not vault  5 bad code  6 locked  7 timeout
        """);
    return 2;
}
