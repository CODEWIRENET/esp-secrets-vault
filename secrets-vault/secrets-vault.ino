#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>
#include <esp_random.h>
#include "mbedtls/base64.h"

// ---- Hardware (LAFVIN ESP32-C6FH4 + 1.47" 172x320 ST7789), reused from btc-ticker
constexpr int8_t PIN_TFT_MOSI = 6;
constexpr int8_t PIN_TFT_SCLK = 7;
constexpr int8_t PIN_TFT_CS   = 14;
constexpr int8_t PIN_TFT_DC   = 15;
constexpr int8_t PIN_TFT_RST  = 21;
constexpr int8_t PIN_TFT_BL   = 22;
constexpr int    TFT_W        = 172;
constexpr int    TFT_H        = 320;

constexpr uint16_t COL_BG   = 0x0000;
constexpr uint16_t COL_FG   = 0xFFFF;
constexpr uint16_t COL_DIM  = 0x7BEF;
constexpr uint16_t COL_UP   = 0x07E0; // green
constexpr uint16_t COL_DOWN = 0xF800; // red
constexpr uint16_t COL_FLAT = 0xFFE0; // yellow
constexpr uint16_t COL_BLUE = 0x049F;

// ---- Vault config
constexpr int           CODE_DIGITS    = 6;            // one-line change to 4
constexpr int           MAX_ENTRIES    = 16;
constexpr int           MAX_KEY_LEN    = 48;
constexpr int           MAX_VAL_LEN    = 512;
constexpr int           RX_BUF_LEN     = 1400;
constexpr unsigned long DEFAULT_TTL_MS = 3600000UL;    // 1 h
constexpr unsigned long TTL_MIN_S      = 60;
constexpr unsigned long TTL_MAX_S      = 86400;
constexpr unsigned long RENDER_MS      = 500;
constexpr unsigned long IDLE_DEAUTH_MS = 120000UL;     // backstop if CDC close not seen
constexpr unsigned long LED_FLASH_MS   = 130;

enum VaultState : uint8_t { ST_WAITING, ST_ACTIVE, ST_LOCKED, ST_EXPIRED };

struct Entry {
  bool     used;
  uint8_t  keyLen;
  uint16_t valLen;
  char     key[MAX_KEY_LEN];
  uint8_t  val[MAX_VAL_LEN];
};

Adafruit_ST7789 tft(PIN_TFT_CS, PIN_TFT_DC, PIN_TFT_MOSI, PIN_TFT_SCLK, PIN_TFT_RST);

static Entry        g_entries[MAX_ENTRIES];
static char         g_code[CODE_DIGITS + 1];
static VaultState   g_state          = ST_WAITING;
static bool         g_authed         = false;
static unsigned long g_ttlMs         = DEFAULT_TTL_MS;
static unsigned long g_ttlStartMs    = 0;     // 0 = clock not running
static bool          g_ttlInfinite   = false; // true = no expiry until power/new TTL
static int          g_failCount      = 0;
static unsigned long g_lockUntilMs   = 0;
static unsigned long g_lastCmdMs     = 0;
static unsigned long g_lastReadMs    = 0;     // 0 = never
static bool          g_wasConnected  = false;
static char         g_rx[RX_BUF_LEN];
static int          g_rxLen          = 0;
static bool          g_rxOverflow    = false;
static unsigned long g_lastRenderMs  = 0;
static bool          g_screenInit    = false;

// ---- helpers -------------------------------------------------------------

static void sendLine(const char* s) { Serial.print(s); Serial.print('\n'); }

static int countEntries() {
  int n = 0;
  for (auto& e : g_entries) if (e.used) n++;
  return n;
}

static void wipeEntries() {
  for (auto& e : g_entries) { e.used = false; e.keyLen = 0; e.valLen = 0; }
}

static void generateCode() {
  uint32_t mod = 1;
  for (int i = 0; i < CODE_DIGITS; i++) mod *= 10u;
  uint32_t limit = (0xFFFFFFFFu / mod) * mod;       // reject-sample, no modulo bias
  uint32_t r;
  do { r = esp_random(); } while (r >= limit);
  r %= mod;
  snprintf(g_code, sizeof(g_code), "%0*u", CODE_DIGITS, (unsigned)r);
}

static int b64dec(const char* in, size_t inLen, uint8_t* out, size_t cap) {
  size_t olen = 0;
  if (mbedtls_base64_decode(out, cap, &olen, (const unsigned char*)in, inLen) != 0)
    return -1;
  return (int)olen;
}

static bool b64enc(const uint8_t* in, size_t inLen, char* out, size_t cap) {
  size_t olen = 0;
  if (mbedtls_base64_encode((unsigned char*)out, cap, &olen, in, inLen) != 0)
    return false;
  out[olen] = 0;
  return true;
}

static unsigned long ttlRemainingS() {
  if (g_ttlStartMs == 0) return g_ttlMs / 1000;
  unsigned long elapsed = millis() - g_ttlStartMs;
  if (elapsed >= g_ttlMs) return 0;
  return (g_ttlMs - elapsed) / 1000;
}

// -1 = infinite (no expiry), else remaining seconds (idle => configured)
static long ttlReportS() {
  if (g_ttlInfinite) return -1;
  return (long)ttlRemainingS();
}

static unsigned long lockRemainingS() {
  if (g_state != ST_LOCKED) return 0;
  unsigned long now = millis();
  if (now >= g_lockUntilMs) return 0;
  return (g_lockUntilMs - now) / 1000;
}

static const char* stateName(VaultState s) {
  switch (s) {
    case ST_WAITING: return "WAITING";
    case ST_ACTIVE:  return "ACTIVE";
    case ST_LOCKED:  return "LOCKED";
    default:         return "EXPIRED";
  }
}

static void recomputeState() {
  if (g_state == ST_LOCKED && millis() < g_lockUntilMs) return;
  g_state = countEntries() > 0 ? ST_ACTIVE : ST_WAITING;
}

static int findEntry(const uint8_t* key, int keyLen) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (!g_entries[i].used) continue;
    if (g_entries[i].keyLen == keyLen &&
        memcmp(g_entries[i].key, key, keyLen) == 0)
      return i;
  }
  return -1;
}

// ---- LED -----------------------------------------------------------------

static void setLED(uint8_t r, uint8_t g, uint8_t b) {
#if defined(RGB_BUILTIN)
  rgbLedWrite(RGB_BUILTIN, r, g, b);
#else
  (void)r; (void)g; (void)b;
#endif
}

static void updateLed() {
  switch (g_state) {
    case ST_WAITING: setLED(0,  0,  48); break;
    case ST_ACTIVE:  setLED(0,  48, 0);  break;
    case ST_LOCKED:  setLED(64, 0,  0);  break;
    case ST_EXPIRED: setLED(64, 0,  0);  break;
  }
}

static void ledReadFlash() {
  setLED(48, 48, 48);
  delay(LED_FLASH_MS);
  updateLed();
}

// ---- rendering (differential) -------------------------------------------

static void drawCentered(const String& s, int y, uint8_t size, uint16_t color) {
  tft.setTextSize(size);
  tft.setTextColor(color);
  int16_t x1, y1; uint16_t w, h;
  tft.getTextBounds(s.c_str(), 0, 0, &x1, &y1, &w, &h);
  tft.setCursor((TFT_W - (int)w) / 2, y);
  tft.print(s);
}

static void drawBand(const String& s, int y, int bandH, uint8_t size,
                     uint16_t color, String& cache) {
  if (s == cache) return;
  tft.fillRect(0, y - 2, TFT_W, bandH + 4, COL_BG);
  drawCentered(s, y, size, color);
  cache = s;
}

static uint16_t stateColor() {
  switch (g_state) {
    case ST_WAITING: return COL_BLUE;
    case ST_ACTIVE:  return COL_UP;
    default:         return COL_DOWN;
  }
}

static void renderExpired() {
  tft.fillScreen(COL_BG);
  drawCentered("EXPIRED", 130, 4, COL_DOWN);
  drawCentered("wiped", 180, 2, COL_DIM);
  delay(2000);
  g_screenInit = false;
}

static void render() {
  static String cCode, cState, cKeys, cTtl, cRead, cFail;

  if (!g_screenInit) {
    tft.fillScreen(COL_BG);
    drawCentered("SECRETS VAULT", 12, 2, COL_DIM);
    tft.drawFastHLine(8, 34, TFT_W - 16, COL_DIM);
    cCode = cState = cKeys = cTtl = cRead = cFail = "";
    g_screenInit = true;
  }

  drawBand(String(g_code),                       64,  32, 4, COL_FG,        cCode);
  drawBand(stateName(g_state),                   120, 16, 2, stateColor(),  cState);

  char buf[40];
  snprintf(buf, sizeof(buf), "keys: %d/%d", countEntries(), MAX_ENTRIES);
  drawBand(buf, 160, 16, 2, COL_FG, cKeys);

  unsigned long s = (g_state == ST_LOCKED) ? lockRemainingS() : ttlRemainingS();
  unsigned long hh = s / 3600, mm = (s % 3600) / 60, ss = s % 60;
  if (g_state == ST_LOCKED)
    snprintf(buf, sizeof(buf), "locked %02lu:%02lu", mm + hh * 60, ss);
  else if (g_ttlInfinite)
    snprintf(buf, sizeof(buf), "ttl: none");
  else if (g_ttlStartMs == 0)
    snprintf(buf, sizeof(buf), "ttl: %luh (idle)", g_ttlMs / 3600000UL);
  else
    snprintf(buf, sizeof(buf), "ttl %02lu:%02lu:%02lu", hh, mm, ss);
  drawBand(buf, 196, 16, 2, g_state == ST_LOCKED ? COL_DOWN : COL_FLAT, cTtl);

  if (g_lastReadMs == 0)
    snprintf(buf, sizeof(buf), "last read: never");
  else
    snprintf(buf, sizeof(buf), "last read: %lus ago",
             (millis() - g_lastReadMs) / 1000);
  drawBand(buf, 236, 8, 1, COL_DIM, cRead);

  snprintf(buf, sizeof(buf), "auth fails: %d", g_failCount);
  drawBand(buf, 262, 8, 1, g_failCount > 0 ? COL_DOWN : COL_DIM, cFail);
}

// ---- command handling ----------------------------------------------------

static void applyLock() {
  int tier = g_failCount / 5;                       // 1,2,3,...
  unsigned long dur = 60000UL << (tier - 1);        // 60s,120s,240s...
  if (dur > 3600000UL) dur = 3600000UL;
  g_lockUntilMs = millis() + dur;
  g_state = ST_LOCKED;
}

static void cmdAuth(char* arg) {
  if (g_state == ST_LOCKED && millis() < g_lockUntilMs) {
    char r[40];
    snprintf(r, sizeof(r), "ERR 423 LOCKED %lu", lockRemainingS());
    sendLine(r);
    return;
  }
  if (g_state == ST_LOCKED) recomputeState();       // lock elapsed

  if (arg && strcmp(arg, g_code) == 0) {
    g_authed     = true;
    g_failCount  = 0;
    g_lockUntilMs = 0;
    recomputeState();
    char r[48];
    snprintf(r, sizeof(r), "OK AUTHED ttl_s=%ld", ttlReportS());
    sendLine(r);
    return;
  }

  g_failCount++;
  if (g_failCount % 5 == 0) {
    applyLock();
    char r[40];
    snprintf(r, sizeof(r), "ERR 423 LOCKED %lu", lockRemainingS());
    sendLine(r);
    return;
  }
  delay(1000);                                      // throttle attempts 1-4
  sendLine("ERR 401 BADCODE");
}

static void cmdSet(char* k, char* v) {
  if (!k || !v) { sendLine("ERR 400 BADREQ"); return; }
  uint8_t kb[MAX_KEY_LEN]; uint8_t vb[MAX_VAL_LEN];
  int kl = b64dec(k, strlen(k), kb, sizeof(kb));
  int vl = b64dec(v, strlen(v), vb, sizeof(vb));
  if (kl < 0 || vl < 0)            { sendLine("ERR 400 BADB64"); return; }
  if (kl == 0 || kl > MAX_KEY_LEN || vl > MAX_VAL_LEN) {
    sendLine("ERR 413 TOOBIG"); return;
  }
  int idx = findEntry(kb, kl);
  if (idx < 0) {
    for (int i = 0; i < MAX_ENTRIES; i++)
      if (!g_entries[i].used) { idx = i; break; }
  }
  if (idx < 0) { sendLine("ERR 507 FULL"); return; }

  Entry& e = g_entries[idx];
  e.used = true;
  e.keyLen = (uint8_t)kl;
  e.valLen = (uint16_t)vl;
  memcpy(e.key, kb, kl);
  memcpy(e.val, vb, vl);

  if (!g_ttlInfinite && g_ttlStartMs == 0)
    g_ttlStartMs = millis();                        // start clock on first store
  recomputeState();
  sendLine("OK SET");
}

static void cmdGet(char* k) {
  if (!k) { sendLine("ERR 400 BADREQ"); return; }
  uint8_t kb[MAX_KEY_LEN];
  int kl = b64dec(k, strlen(k), kb, sizeof(kb));
  if (kl < 0)  { sendLine("ERR 400 BADB64"); return; }
  int idx = findEntry(kb, kl);
  if (idx < 0) { sendLine("ERR 404 NOTFOUND"); return; }

  static char enc[4 * ((MAX_VAL_LEN + 2) / 3) + 4];
  if (!b64enc(g_entries[idx].val, g_entries[idx].valLen, enc, sizeof(enc))) {
    sendLine("ERR 500 INTERNAL"); return;
  }
  sendLine(enc);
  sendLine("OK");
  g_lastReadMs = millis();
  ledReadFlash();
}

static void cmdList() {
  static char enc[4 * ((MAX_KEY_LEN + 2) / 3) + 4];
  int n = 0;
  for (auto& e : g_entries) {
    if (!e.used) continue;
    if (b64enc((const uint8_t*)e.key, e.keyLen, enc, sizeof(enc))) {
      sendLine(enc);
      n++;
    }
  }
  char r[24];
  snprintf(r, sizeof(r), "OK %d", n);
  sendLine(r);
  g_lastReadMs = millis();
  ledReadFlash();
}

static void cmdDel(char* k) {
  if (!k) { sendLine("ERR 400 BADREQ"); return; }
  uint8_t kb[MAX_KEY_LEN];
  int kl = b64dec(k, strlen(k), kb, sizeof(kb));
  if (kl < 0)  { sendLine("ERR 400 BADB64"); return; }
  int idx = findEntry(kb, kl);
  if (idx < 0) { sendLine("ERR 404 NOTFOUND"); return; }
  g_entries[idx].used = false;
  recomputeState();
  sendLine("OK DEL");
}

static void cmdWipe() {
  wipeEntries();
  generateCode();
  g_ttlStartMs = 0;
  recomputeState();
  g_screenInit = false;
  sendLine("OK WIPED");
}

static void cmdTtl(char* arg) {
  if (!arg) { sendLine("ERR 400 BADTTL"); return; }
  long sec = atol(arg);

  if (sec == 0) {                                   // kill switch: close now
    sendLine("OK TTL 0");
    doExpire();
    return;
  }
  if (sec < 0) {                                    // infinite: until power/new TTL
    g_ttlInfinite = true;
    g_ttlStartMs  = 0;
    sendLine("OK TTL -1");
    return;
  }
  if (sec < (long)TTL_MIN_S || sec > (long)TTL_MAX_S) {
    sendLine("ERR 400 BADTTL"); return;
  }
  g_ttlInfinite = false;
  g_ttlMs       = (unsigned long)sec * 1000UL;
  g_ttlStartMs  = millis();                         // (re)start clock on set
  char r[24];
  snprintf(r, sizeof(r), "OK TTL %ld", sec);
  sendLine(r);
}

static void cmdStatus() {
  long lastRead = g_lastReadMs == 0
                    ? -1
                    : (long)((millis() - g_lastReadMs) / 1000);
  char r[150];
  snprintf(r, sizeof(r),
           "OK %s entries=%d ttl_s=%ld locked=%d lock_s=%lu last_read_s=%ld fails=%d",
           stateName(g_state), countEntries(), ttlReportS(),
           g_state == ST_LOCKED ? 1 : 0, lockRemainingS(), lastRead,
           g_failCount);
  sendLine(r);
}

static void handleLine(char* line) {
  g_lastCmdMs = millis();

  char* sp1 = strchr(line, ' ');
  if (sp1) *sp1 = 0;
  char* a1 = sp1 ? sp1 + 1 : nullptr;
  char* a2 = nullptr;
  if (a1) {
    char* sp2 = strchr(a1, ' ');
    if (sp2) { *sp2 = 0; a2 = sp2 + 1; }
  }

  for (char* p = line; *p; p++) *p = toupper(*p);

  if (strcmp(line, "PING") == 0) {
    char r[40];
    snprintf(r, sizeof(r), "OK PONG vault/1 %d/%d",
             MAX_ENTRIES - countEntries(), MAX_ENTRIES);
    sendLine(r);
    return;
  }
  if (strcmp(line, "STATUS") == 0) { cmdStatus(); return; }
  if (strcmp(line, "AUTH")   == 0) { cmdAuth(a1);  return; }

  // everything below requires an authed session
  if (!g_authed) { sendLine("ERR 401 NOAUTH"); return; }

  if      (strcmp(line, "SET")  == 0) cmdSet(a1, a2);
  else if (strcmp(line, "GET")  == 0) cmdGet(a1);
  else if (strcmp(line, "LIST") == 0) cmdList();
  else if (strcmp(line, "DEL")  == 0) cmdDel(a1);
  else if (strcmp(line, "WIPE") == 0) cmdWipe();
  else if (strcmp(line, "TTL")  == 0) cmdTtl(a1);
  else                                sendLine("ERR 400 BADREQ");
}

static void pumpSerial() {
  while (Serial.available() > 0) {
    int c = Serial.read();
    if (c < 0) break;
    if (c == '\r') continue;
    if (c == '\n') {
      if (g_rxOverflow) {
        sendLine("ERR 413 TOOBIG");
        g_rxOverflow = false;
      } else {
        g_rx[g_rxLen] = 0;
        if (g_rxLen > 0) handleLine(g_rx);
      }
      g_rxLen = 0;
      continue;
    }
    if (g_rxLen >= RX_BUF_LEN - 1) { g_rxOverflow = true; continue; }
    g_rx[g_rxLen++] = (char)c;
  }
}

static void trackConnection() {
  bool conn = (bool)Serial;
  if (g_wasConnected && !conn) {            // CDC closed -> drop session
    g_authed = false;
  }
  g_wasConnected = conn;
}

static void doExpire() {
  wipeEntries();
  g_state = ST_EXPIRED;
  updateLed();
  renderExpired();
  generateCode();
  g_ttlStartMs  = 0;
  g_ttlInfinite = false;
  g_ttlMs       = DEFAULT_TTL_MS;
  g_authed      = false;
  g_failCount   = 0;
  g_lockUntilMs = 0;
  g_state       = ST_WAITING;
}

static void tickTtl() {
  if (g_ttlInfinite || g_ttlStartMs == 0) return;
  if (millis() - g_ttlStartMs < g_ttlMs) return;
  doExpire();
}

// ---- arduino entrypoints -------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println();
  Serial.println(F("secrets-vault boot"));

  pinMode(PIN_TFT_BL, OUTPUT);
  digitalWrite(PIN_TFT_BL, HIGH);

  tft.init(TFT_W, TFT_H);
  tft.setRotation(0);
  tft.fillScreen(COL_BG);

  wipeEntries();
  g_ttlMs = DEFAULT_TTL_MS;
  generateCode();
  g_state = ST_WAITING;

  render();
  updateLed();
  Serial.println(F("ready"));
}

void loop() {
  unsigned long now = millis();

  trackConnection();
  pumpSerial();
  tickTtl();

  if (g_authed && g_lastCmdMs != 0 && now - g_lastCmdMs > IDLE_DEAUTH_MS)
    g_authed = false;

  if (g_state == ST_LOCKED && now >= g_lockUntilMs) {
    recomputeState();
    updateLed();
  }

  if (now - g_lastRenderMs >= RENDER_MS) {
    render();
    updateLed();
    g_lastRenderMs = now;
  }
  delay(5);
}
