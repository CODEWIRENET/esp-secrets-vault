# esp-secrets-vault

A hardware-gated **ephemeral secrets vault**. An ESP32-C6 shows a random
6-digit pairing code on its screen; a C# CLI (`VaultCli`) uses that code to push
key/value secrets into the device's RAM and later read them back. Intended use:
give an AI agent **time-boxed, human-consented** access to credentials (SMTP
settings, connection strings) without those secrets living in the agent's
config or environment.

```
┌─ human ─┐   set smtp ... --code 123456 --hour 5    ┌──────────────┐
│ VaultCli│ ───────────────────────────────────────► │  ESP32-C6    │
└─────────┘                                           │  RAM-only    │  6-digit
┌─ AI ────┐   get smtp --code 123456                  │  TTL + lock  │  code on
│ VaultCli│ ◄─────────────────────────────────────── │  TFT display │  screen
└─────────┘   value (decoded)                         └──────────────┘
```

## ⚠️ Threat model — read this first

This is a **human-consented, time-boxed, physically-visible convenience
boundary — NOT a cryptographically secure secret store.**

- **Plaintext over USB-serial.** The 6-digit code is the *only* gate. Any local
  process that can open the COM port can speak the protocol. There is no
  transport encryption and no OS ACL beyond default Windows device
  permissions.
- **Brute-force is mitigated, not eliminated.** 6 digits = 10⁶; wrong attempts
  are throttled 1 s each and lock the device (60 s, doubling per 5 fails, cap
  1 h). A determined local attacker with physical USB access is still in scope.
- **No encryption at rest in RAM.** A JTAG/debug attacker with physical access
  could dump SRAM. Ephemerality (RAM-only, wiped on reset/power/TTL) is the
  only protection.
- Use it for *convenience and consent signalling*, not to protect secrets from
  a capable local adversary.

## Hardware

LAFVIN ESP32-C6FH4 + 1.47" 172×320 ST7789 TFT. Pins: `MOSI=6 SCK=7 CS=14
DC=15 RST=21 BL=22`, BOOT `GPIO9`, WS2812 on `RGB_BUILTIN`. Firmware is
**offline** — no WiFi.

## Layout

- `secrets-vault/` — ESP32-C6 firmware (Arduino/C++)
- `VaultCli/` — .NET 8 Windows CLI

## Serial protocol (115200 8N1, newline-delimited, base64 values)

| Request | Auth | Response |
|---|---|---|
| `PING` | no | `OK PONG vault/1 <free>/<max>` |
| `STATUS` | no | `OK <state> entries=… ttl_s=… locked=… …` |
| `AUTH <code>` | — | `OK AUTHED ttl_s=…` / `ERR 401 BADCODE` / `ERR 423 LOCKED <s>` |
| `SET <b64k> <b64v>` | yes | `OK SET` / `ERR 413` / `ERR 507 FULL` |
| `GET <b64k>` | yes | `<b64v>` then `OK` / `ERR 404` |
| `LIST` | yes | keys… then `OK <n>` |
| `DEL <b64k>` | yes | `OK DEL` / `ERR 404` |
| `WIPE` | yes | `OK WIPED` |
| `TTL <sec>` | yes | `OK TTL <sec>` — `0` = close now, `-1` = no expiry |

Auth is bound to the serial session; closing the port (or 120 s idle)
de-authenticates. Caps: 16 entries, 48-byte keys, 512-byte values, RAM only.

## Build & flash

Firmware (needs `arduino-cli` + `esp32:esp32` core, Adafruit ST7789/GFX):

```
arduino-cli compile --fqbn esp32:esp32:esp32c6:CDCOnBoot=cdc,PartitionScheme=no_ota secrets-vault
arduino-cli upload  --fqbn esp32:esp32:esp32c6:CDCOnBoot=cdc,PartitionScheme=no_ota -p COM5 secrets-vault
```

CLI (.NET 8 SDK):

```
dotnet build VaultCli/VaultCli.csproj -c Release
```

## CLI usage

```
VaultCli status [--port COMx] [--json]
VaultCli set  <key> <value> --code NNNNNN [--hour N | --minutes N] [--port COMx]
VaultCli get  <key>         --code NNNNNN [--port COMx] [--json]
VaultCli list               --code NNNNNN [--port COMx] [--json]
VaultCli del  <key>         --code NNNNNN [--port COMx]
VaultCli wipe               --code NNNNNN [--port COMx]
VaultCli ttl                --code NNNNNN  --hour N | --minutes N  [--port COMx]
```

TTL: `N` > 0 = lifetime (hours/minutes); `0` = close & wipe immediately;
`-1` = no expiry until power-off / reset / new TTL. The clock (re)starts every
time TTL is set. Read the 6-digit code **off the device screen** — it is never
sent over serial without a successful `AUTH`.

Exit codes: `0` ok · `1` protocol · `2` usage · `3` no port · `4` not a vault ·
`5` bad code · `6` locked · `7` timeout.

## Known technical debt

`VaultCli/PortDetect.cs` is a **copy** of the WMI port-detection logic from the
separate [CheckESP32](https://github.com/CODEWIRENET/CheckESP32) tool
(deliberate copy-per-tool). A fix there does not propagate here automatically;
keep them in sync manually, or publish CheckESP32 as a NuGet/dotnet-tool and
depend on it.

## License

MIT — see [LICENSE](LICENSE).
