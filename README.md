# esp-secrets-vault

An **encrypted USB secrets courier**. Stage key/value secrets on an ESP32-C6
using a 6-digit code shown on its screen, **seal** them (AES-256-GCM, key
derived from the code — never stored), unplug, walk to another machine, plug in,
and **unseal** with the same code. A wrong code **destroys the payload**.
Designed so a human can hand an AI agent — or another PC — *time-boxed,
physically-carried* access to credentials (SMTP, connection strings) that never
live in any config file, env var, or model context.

## Why

AI agents and cross-machine workflows need *real* credentials, but the usual
options all leak:

- **Env vars / `.env`** — the secret lives wherever the process runs, lands in
  logs, crash dumps, and context windows, and outlives the task.
- **Cloud secret managers** — solve storage, but the holder keeps a long-lived
  token that *is* the keys, and access is invisible to the human in the moment.
- **Paste into the prompt** — now it's in transcripts and model context forever.
- **USB stick** — survives, but a lost stick is plaintext to whoever finds it.

The missing piece is consent that is **physical, scoped, encrypted, and
self-destructing**. `esp-secrets-vault` makes the consent a physical object:
the secret is encrypted at rest with a key derived from a code that exists only
on a screen and in the courier's head; pulling power is a hard revoke; the
budget is a powered-time clock; and one wrong guess wipes it.

It is deliberately **not** an HSM (see threat model). Its value is making
time-boxed, human-carried credential transfer *cheap, visible, and physical*.

## Architecture

```
        PC A (source)                                  PC B (destination)
  ┌───────────────────┐                            ┌────────────────────┐
  │ VaultCli set ...   │  AUTH(code)+SET (RAM)      │ VaultCli unseal    │
  │ VaultCli seal      │ ─────────────────────────► │   --code 482913    │
  └───────────────────┘                            └─────────┬──────────┘
            │                                                 │ correct → AES-GCM
            ▼                                                 │ decrypt to RAM
  ┌─────────────────────────── ESP32-C6 ───────────────────────────┐
  │  STAGING (code on screen)   SEALED (code hidden)   UNSEALED     │
  │  plaintext in RAM      ──►  AES-256-GCM in flash ─► plaintext   │
  │                             key = PBKDF2(code,salt)  in RAM     │
  │                             code NEVER stored                   │
  │                                                                 │
  │  self-destruct (zero RAM + erase flash + new code) on:          │
  │    • wrong unseal code   • powered-TTL = 0   • wipe   • ttl 0    │
  └─────────────────────────────────────────────────────────────────┘
        unplug & carry ──────────────────►  (TTL only counts while powered)
```

## ⚠️ Threat model — read this first

A **human-carried, time-boxed, encrypted convenience boundary — NOT an HSM.**

- **Encrypted at rest.** The sealed blob is AES-256-GCM; the key is
  `PBKDF2-HMAC-SHA256(code, random salt, 20k iters)`. The code is never written
  to the device. A stolen *sealed* device is ciphertext without the code.
- **One wrong guess destroys it.** A failed `unseal` (GCM auth failure) triggers
  active erase: RAM zeroed, NVS blob overwritten + cleared, fresh code. There is
  **no retry** — a typo in the code loses the payload. This is intentional;
  budget for it.
- **Powered-time TTL only.** The board has no RTC, so the lifetime clock counts
  *plugged-in time*, not wall-clock. Carrying it unplugged does not consume
  budget; sitting plugged in does. Expiry → active erase.
- **NVS wear-levelling.** Erase overwrites then clears the blob, but flash
  wear-levelling may leave old *ciphertext* pages physically until GC. It's
  ciphertext without the code, but don't treat a "destroyed" device as
  forensically clean against a determined lab.
- **Staging window.** Before `seal`, staged items are plaintext in RAM and
  readable on that serial session. Seal promptly; unplug if interrupted.
- Not protected against: a JTAG/SRAM attacker with physical access to a
  *powered, unsealed* device.

## Hardware

LAFVIN ESP32-C6FH4 + 1.47" 172×320 ST7789 TFT. Pins: `MOSI=6 SCK=7 CS=14
DC=15 RST=21 BL=22`, BOOT `GPIO9`, WS2812 on `RGB_BUILTIN`. **Offline** — no
WiFi/Bluetooth used.

## Serial protocol (115200 8N1, newline-delimited, base64 values)

| Request | When | Response |
|---|---|---|
| `PING` | any | `OK PONG vault/2 <STATE> <count>` |
| `STATUS` | any | `OK <state> items=… ttl_s=… sealed=… last_read_s=… fails=…` |
| `AUTH <code>` | EMPTY/STAGING | `OK AUTHED ttl_s=…` / `ERR 401 BADCODE` / `ERR 409 SEALED` |
| `SET <b64k> <b64v>` | STAGING | `OK SET` / `ERR 413` / `ERR 507 FULL` |
| `SEAL` | STAGING | `OK SEALED` (encrypts RAM→flash, hides code) |
| `UNSEAL <code>` | SEALED | `OK UNSEALED items=…` / `ERR 401` **(destroys payload)** |
| `GET <b64k>` | STAGING/UNSEALED | `<b64v>` then `OK` / `ERR 404` / `ERR 409` |
| `LIST` | STAGING/UNSEALED | keys… then `OK <n>` |
| `TTL <sec>` | EMPTY/STAGING | `OK TTL <s>` — `0` = destroy now, `-1` = no expiry |
| `WIPE` | not SEALED | `OK WIPED` (destroy everything) |

States: `EMPTY → STAGING → SEALED → UNSEALED` (+ transient `DESTROYED`). Auth is
per serial session. The device port is found by the CLI via the PING handshake
— no driver/VID database, fully cross-platform.

## Build & flash

Firmware (`arduino-cli` + `esp32:esp32` core ≥ 3.3.8, Adafruit ST7789/GFX):

```
arduino-cli compile --fqbn esp32:esp32:esp32c6:CDCOnBoot=cdc,PartitionScheme=no_ota secrets-vault
arduino-cli upload  --fqbn esp32:esp32:esp32c6:CDCOnBoot=cdc,PartitionScheme=no_ota -p <PORT> secrets-vault
```

CLI (.NET 8 SDK — builds/runs on Windows, Linux, macOS):

```
dotnet build VaultCli/VaultCli.csproj -c Release
```

## CLI usage

```
# PC A — stage & seal (code is shown on the device screen)
VaultCli set  smtp "host=mail;user=a;pass=b" --code 482913 --hour 5
VaultCli set  db   "Server=...;Pwd=..."       --code 482913
VaultCli seal                                  --code 482913
# unplug, carry the device, remember 482913

# PC B — unseal & read   (WRONG CODE DESTROYS THE PAYLOAD)
VaultCli unseal --code 482913
VaultCli get smtp
VaultCli list

VaultCli status [--port COMx] [--json]
VaultCli ttl  --code 482913 --minutes 0     # destroy now
VaultCli wipe --code 482913
```

Port is auto-detected (no `--port` needed). TTL is **powered-time**:
`--hour N`/`--minutes N` = budget, `0` = destroy now, `-1` = no expiry.

## Demo

```console
$ VaultCli status
EMPTY items=0 ttl_s=3600 sealed=0 last_read_s=-1 fails=0

$ VaultCli set smtp "host=mail.codewire.net;user=janus;pass=hunter2" --code 482913 --hour 5
staged
$ VaultCli seal --code 482913
sealed — safe to unplug
                                  ── unplug, walk to PC B, plug in ──
$ VaultCli status
SEALED items=0 ttl_s=17981 sealed=1 last_read_s=-1 fails=0

$ VaultCli unseal --code 482913
unsealed — use 'get'/'list'
$ VaultCli get smtp
host=mail.codewire.net;user=janus;pass=hunter2

$ VaultCli unseal --code 999999          # (on a fresh sealed payload)
error: WRONG CODE — payload was destroyed (self-destruct)
```

## Use it from an AI agent

The agent never sees the code — a human types it once at seal time on PC A and
once at unseal time. After `unseal`, the agent just reads:

```bash
# bash — agent fetches a connection string at task time
CONN="$(VaultCli get db || { echo 'vault locked/empty' >&2; exit 1; })"
psql "$CONN" -c '...'
```

```python
# python — typed accessor for an agent tool
import subprocess

def vault_get(key: str) -> str:
    p = subprocess.run(["VaultCli", "get", key],
                        capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip())   # 1=locked/missing, 3=no device
    return p.stdout

smtp = vault_get("smtp")   # secret never touches the agent's config or prompt
```

Exit codes: `0` ok · `1` protocol/locked/not-found · `2` usage · `3` no port ·
`4` not a courier · `5` bad code (payload destroyed) · `7` timeout.

## Layout

- `secrets-vault/` — ESP32-C6 firmware (Arduino/C++)
- `VaultCli/` — .NET 8 cross-platform CLI

## License

MIT — see [LICENSE](LICENSE).
