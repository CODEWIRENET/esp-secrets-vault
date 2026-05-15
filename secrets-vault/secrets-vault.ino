#include <Arduino.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7789.h>
#include <Preferences.h>
#include <esp_random.h>
#include "mbedtls/base64.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

// ---- Hardware (LAFVIN ESP32-C6FH4 + 1.47" 172x320 ST7789)
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
constexpr uint16_t COL_SEAL = 0xFCA0; // amber (sealed)

// ---- Vault config
constexpr int           CODE_DIGITS  = 6;            // one-line change to 4
constexpr int           MAX_ENTRIES  = 16;
constexpr int           MAX_KEY_LEN  = 48;
constexpr int           MAX_VAL_LEN  = 512;
constexpr int           RX_BUF_LEN   = 1400;
constexpr unsigned long DEFAULT_TTL_MS  = 3600000UL; // 1 h powered-time
constexpr long          TTL_MIN_S    = 60;
constexpr long          TTL_MAX_S    = 86400;
constexpr unsigned long RENDER_MS    = 500;
constexpr unsigned long TTL_PERSIST_MS = 15000;      // re-persist remaining every 15 s
constexpr unsigned long IDLE_DEAUTH_MS = 120000UL;
constexpr unsigned long LED_FLASH_MS = 130;
constexpr uint32_t      PBKDF2_ITERS = 20000;
constexpr int           SALT_LEN     = 16;
constexpr int           IV_LEN       = 12;
constexpr int           TAG_LEN      = 16;
constexpr int           KEY_LEN      = 32;            // AES-256
constexpr uint32_t      BLOB_MAGIC   = 0x53565432;    // 'SVT2'

// EMPTY: no payload, code shown, accept staging.
// STAGING: authed, building payload in RAM, code shown.
// SEALED: ciphertext in flash, code hidden, needs UNSEAL.
// UNSEALED: decrypted payload in RAM (readable).
// DESTROYED: transient — wrong code / expiry wiped everything.
enum VaultState : uint8_t { ST_EMPTY, ST_STAGING, ST_SEALED, ST_UNSEALED, ST_DESTROYED };

struct Entry {
  bool     used;
  uint8_t  keyLen;
  uint16_t valLen;
  char     key[MAX_KEY_LEN];
  uint8_t  val[MAX_VAL_LEN];
};

#pragma pack(push, 1)
struct BlobHeader {
  uint32_t magic;
  uint8_t  version;
  uint8_t  salt[SALT_LEN];
  uint8_t  iv[IV_LEN];
  uint8_t  tag[TAG_LEN];
  uint32_t ttlRemainingMs;   // powered-time budget left at seal
  uint16_t ctLen;            // ciphertext length
};
#pragma pack(pop)

Adafruit_ST7789 tft(PIN_TFT_CS, PIN_TFT_DC, PIN_TFT_MOSI, PIN_TFT_SCLK, PIN_TFT_RST);
Preferences      prefs;

static Entry         g_entries[MAX_ENTRIES];
static char          g_code[CODE_DIGITS + 1];
static VaultState    g_state         = ST_EMPTY;
static bool          g_authed        = false;        // staging auth
static unsigned long g_ttlBudgetMs   = DEFAULT_TTL_MS;// configured budget
static unsigned long g_ttlRemainMs   = DEFAULT_TTL_MS;// counts down while powered
static bool          g_ttlInfinite   = false;
static unsigned long g_lastTickMs    = 0;
static unsigned long g_lastPersistMs = 0;
static unsigned long g_lastCmdMs     = 0;
static unsigned long g_lastReadMs    = 0;
static int           g_failCount     = 0;
static bool          g_wasConnected  = false;
static char          g_rx[RX_BUF_LEN];
static int           g_rxLen         = 0;
static bool          g_rxOverflow    = false;
static unsigned long g_lastRenderMs  = 0;
static bool          g_screenInit    = false;

static uint8_t  g_plain[1 + MAX_ENTRIES * (1 + 2 + MAX_KEY_LEN + MAX_VAL_LEN)];
static uint8_t  g_cipher[sizeof(g_plain)];

// ---- helpers -------------------------------------------------------------

static void sendLine(const char* s) { Serial.print(s); Serial.print('\n'); }

static int countEntries() {
  int n = 0;
  for (auto& e : g_entries) if (e.used) n++;
  return n;
}

static void zeroEntries() {
  for (auto& e : g_entries) {
    memset(e.key, 0, MAX_KEY_LEN);
    memset(e.val, 0, MAX_VAL_LEN);
    e.used = false; e.keyLen = 0; e.valLen = 0;
  }
}

static void generateCode() {
  uint32_t mod = 1;
  for (int i = 0; i < CODE_DIGITS; i++) mod *= 10u;
  uint32_t limit = (0xFFFFFFFFu / mod) * mod;
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

static int findEntry(const uint8_t* key, int keyLen) {
  for (int i = 0; i < MAX_ENTRIES; i++) {
    if (!g_entries[i].used) continue;
    if (g_entries[i].keyLen == keyLen &&
        memcmp(g_entries[i].key, key, keyLen) == 0)
      return i;
  }
  return -1;
}

// ---- crypto + persistence ------------------------------------------------

static bool deriveKey(const char* code, const uint8_t* salt, uint8_t out[KEY_LEN]) {
  return mbedtls_pkcs5_pbkdf2_hmac_ext(
           MBEDTLS_MD_SHA256,
           (const unsigned char*)code, strlen(code),
           salt, SALT_LEN, PBKDF2_ITERS, KEY_LEN, out) == 0;
}

static int serializeRam(uint8_t* buf) {
  int n = 0;
  uint8_t cnt = 0;
  int p = 1;
  for (auto& e : g_entries) {
    if (!e.used) continue;
    buf[p++] = e.keyLen;
    buf[p++] = (uint8_t)(e.valLen & 0xFF);
    buf[p++] = (uint8_t)(e.valLen >> 8);
    memcpy(buf + p, e.key, e.keyLen); p += e.keyLen;
    memcpy(buf + p, e.val, e.valLen); p += e.valLen;
    cnt++;
  }
  buf[0] = cnt;
  n = p;
  return n;
}

static bool deserializeRam(const uint8_t* buf, int len) {
  zeroEntries();
  if (len < 1) return false;
  uint8_t cnt = buf[0];
  int p = 1;
  for (int i = 0; i < cnt && i < MAX_ENTRIES; i++) {
    if (p + 3 > len) return false;
    uint8_t kl = buf[p++];
    uint16_t vl = buf[p] | (buf[p + 1] << 8); p += 2;
    if (kl > MAX_KEY_LEN || vl > MAX_VAL_LEN) return false;
    if (p + kl + vl > len) return false;
    Entry& e = g_entries[i];
    e.used = true; e.keyLen = kl; e.valLen = vl;
    memcpy(e.key, buf + p, kl); p += kl;
    memcpy(e.val, buf + p, vl); p += vl;
  }
  return true;
}

// Overwrite NVS blob with zeros, then erase the namespace (active destroy).
static void eraseFlash() {
  size_t existing = 0;
  prefs.begin("vault", false);
  existing = prefs.getBytesLength("blob");
  if (existing > 0) {
    static uint8_t zb[sizeof(g_cipher) + sizeof(BlobHeader)];
    memset(zb, 0, sizeof(zb));
    prefs.putBytes("blob", zb, existing > sizeof(zb) ? sizeof(zb) : existing);
  }
  prefs.remove("blob");
  prefs.clear();
  prefs.end();
}

static bool sealToFlash() {
  int plen = serializeRam(g_plain);
  if (plen <= 1) return false;

  BlobHeader h;
  h.magic   = BLOB_MAGIC;
  h.version = 2;
  esp_fill_random(h.salt, SALT_LEN);
  esp_fill_random(h.iv, IV_LEN);
  h.ttlRemainingMs = g_ttlInfinite ? 0xFFFFFFFFu : (uint32_t)g_ttlRemainMs;
  h.ctLen = (uint16_t)plen;

  uint8_t key[KEY_LEN];
  if (!deriveKey(g_code, h.salt, key)) return false;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, KEY_LEN * 8) == 0
         && mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plen,
              h.iv, IV_LEN, (const unsigned char*)&h.magic, 5 /* AAD: magic+ver */,
              g_plain, g_cipher, TAG_LEN, h.tag) == 0;
  mbedtls_gcm_free(&gcm);
  memset(key, 0, KEY_LEN);
  if (!ok) return false;

  static uint8_t out[sizeof(BlobHeader) + sizeof(g_cipher)];
  memcpy(out, &h, sizeof(h));
  memcpy(out + sizeof(h), g_cipher, plen);

  prefs.begin("vault", false);
  size_t w = prefs.putBytes("blob", out, sizeof(h) + plen);
  prefs.end();
  memset(g_plain, 0, sizeof(g_plain));
  memset(g_cipher, 0, sizeof(g_cipher));
  return w == sizeof(h) + plen;
}

static bool flashHasBlob() {
  prefs.begin("vault", true);
  size_t l = prefs.getBytesLength("blob");
  prefs.end();
  return l >= sizeof(BlobHeader) + 2;
}

// Loads header (for TTL/status) without the code. Returns false if absent/bad.
static bool loadHeader(BlobHeader& h) {
  prefs.begin("vault", true);
  size_t l = prefs.getBytesLength("blob");
  bool ok = false;
  if (l >= sizeof(BlobHeader)) {
    prefs.getBytes("blob", &h, sizeof(h));
    ok = (h.magic == BLOB_MAGIC);
  }
  prefs.end();
  return ok;
}

// Try to decrypt with code. true => loaded into RAM. false => wrong/tampered.
static bool unsealWithCode(const char* code) {
  static uint8_t in[sizeof(BlobHeader) + sizeof(g_cipher)];
  prefs.begin("vault", true);
  size_t l = prefs.getBytesLength("blob");
  if (l < sizeof(BlobHeader) || l > sizeof(in)) { prefs.end(); return false; }
  prefs.getBytes("blob", in, l);
  prefs.end();

  BlobHeader h;
  memcpy(&h, in, sizeof(h));
  if (h.magic != BLOB_MAGIC) return false;
  if (h.ctLen > sizeof(g_cipher) || sizeof(h) + h.ctLen > l) return false;

  uint8_t key[KEY_LEN];
  if (!deriveKey(code, h.salt, key)) return false;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int rc = -1;
  if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, KEY_LEN * 8) == 0) {
    rc = mbedtls_gcm_auth_decrypt(&gcm, h.ctLen, h.iv, IV_LEN,
           (const unsigned char*)&h.magic, 5, h.tag, TAG_LEN,
           in + sizeof(h), g_plain);
  }
  mbedtls_gcm_free(&gcm);
  memset(key, 0, KEY_LEN);
  if (rc != 0) { memset(g_plain, 0, sizeof(g_plain)); return false; }

  bool ok = deserializeRam(g_plain, h.ctLen);
  memset(g_plain, 0, sizeof(g_plain));
  if (!ok) return false;

  g_ttlInfinite = (h.ttlRemainingMs == 0xFFFFFFFFu);
  g_ttlRemainMs = g_ttlInfinite ? DEFAULT_TTL_MS : h.ttlRemainingMs;
  return true;
}

static void persistTtl() {
  if (g_state != ST_SEALED && g_state != ST_UNSEALED) return;
  if (g_ttlInfinite) return;
  prefs.begin("vault", false);
  size_t l = prefs.getBytesLength("blob");
  if (l >= sizeof(BlobHeader)) {
    static uint8_t buf[sizeof(BlobHeader) + sizeof(g_cipher)];
    prefs.getBytes("blob", buf, l);
    BlobHeader* h = (BlobHeader*)buf;
    if (h->magic == BLOB_MAGIC) {
      h->ttlRemainingMs = (uint32_t)g_ttlRemainMs;
      prefs.putBytes("blob", buf, l);
    }
  }
  prefs.end();
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
    case ST_EMPTY:     setLED(0,  0,  48); break;
    case ST_STAGING:   setLED(0,  32, 32); break;
    case ST_SEALED:    setLED(40, 20, 0);  break;
    case ST_UNSEALED:  setLED(0,  48, 0);  break;
    case ST_DESTROYED: setLED(64, 0,  0);  break;
  }
}

static void ledReadFlash() {
  setLED(48, 48, 48);
  delay(LED_FLASH_MS);
  updateLed();
}

// ---- rendering -----------------------------------------------------------

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

static const char* stateName() {
  switch (g_state) {
    case ST_EMPTY:     return "READY";
    case ST_STAGING:   return "STAGING";
    case ST_SEALED:    return "SEALED";
    case ST_UNSEALED:  return "UNSEALED";
    default:           return "DESTROYED";
  }
}

static uint16_t stateColor() {
  switch (g_state) {
    case ST_EMPTY:    return COL_BLUE;
    case ST_STAGING:  return COL_FLAT;
    case ST_SEALED:   return COL_SEAL;
    case ST_UNSEALED: return COL_UP;
    default:          return COL_DOWN;
  }
}

static unsigned long ttlRemainS() {
  return g_ttlInfinite ? 0 : g_ttlRemainMs / 1000;
}

static void render() {
  static String cTitle, cCode, cState, cInfo, cTtl, cHint;

  if (!g_screenInit) {
    tft.fillScreen(COL_BG);
    cTitle = cCode = cState = cInfo = cTtl = cHint = "";
    g_screenInit = true;
  }

  drawBand("SECRETS COURIER", 12, 16, 2, COL_DIM, cTitle);
  tft.drawFastHLine(8, 34, TFT_W - 16, COL_DIM);

  // Code only visible while not yet sealed.
  bool showCode = (g_state == ST_EMPTY || g_state == ST_STAGING);
  drawBand(showCode ? String(g_code) : String("------"),
           60, 32, 4, showCode ? COL_FG : COL_DIM, cCode);

  drawBand(stateName(), 116, 16, 2, stateColor(), cState);

  char buf[40];
  snprintf(buf, sizeof(buf), "items: %d", countEntries());
  drawBand(buf, 156, 16, 2, COL_FG, cInfo);

  if (g_ttlInfinite)
    snprintf(buf, sizeof(buf), "ttl: none");
  else {
    unsigned long s = ttlRemainS();
    snprintf(buf, sizeof(buf), "ttl %02lu:%02lu:%02lu",
             s / 3600, (s % 3600) / 60, s % 60);
  }
  drawBand(buf, 192, 16, 2, COL_FLAT, cTtl);

  const char* hint;
  switch (g_state) {
    case ST_EMPTY:     hint = "AUTH on host to stage"; break;
    case ST_STAGING:   hint = "SET items, then SEAL";  break;
    case ST_SEALED:    hint = "UNSEAL on host w/ code"; break;
    case ST_UNSEALED:  hint = "reading enabled";       break;
    default:           hint = "payload destroyed";     break;
  }
  drawBand(hint, 240, 8, 1, COL_DIM, cHint);

  snprintf(buf, sizeof(buf), "fails: %d  powered-time", g_failCount);
  static String cFoot;
  drawBand(buf, 268, 8, 1, g_failCount ? COL_DOWN : COL_DIM, cFoot);
}

// ---- commands ------------------------------------------------------------

static void selfDestruct(const char* reason) {
  Serial.printf("DESTROY: %s\n", reason);
  zeroEntries();
  eraseFlash();
  g_state = ST_DESTROYED;
  g_authed = false;
  memset(g_plain, 0, sizeof(g_plain));
  memset(g_cipher, 0, sizeof(g_cipher));
  updateLed();
  g_screenInit = false;
  render();
  delay(1500);
  generateCode();
  g_ttlBudgetMs = DEFAULT_TTL_MS;
  g_ttlRemainMs = DEFAULT_TTL_MS;
  g_ttlInfinite = false;
  g_state = ST_EMPTY;
  g_screenInit = false;
}

static void cmdAuth(char* arg) {
  if (g_state == ST_SEALED)    { sendLine("ERR 409 SEALED use UNSEAL"); return; }
  if (g_state == ST_DESTROYED) { sendLine("ERR 409 BUSY"); return; }
  if (g_state == ST_UNSEALED)  { sendLine("OK AUTHED"); return; } // already open at dest
  // EMPTY or STAGING: the code is on-screen — require it every time.
  if (arg && strcmp(arg, g_code) == 0) {
    g_authed = true;
    if (g_state == ST_EMPTY) g_state = ST_STAGING;
    char r[48];
    snprintf(r, sizeof(r), "OK AUTHED ttl_s=%lu", g_ttlInfinite ? 0 : ttlRemainS());
    sendLine(r);
    return;
  }
  g_failCount++;
  delay(1000);
  sendLine("ERR 401 BADCODE");
}

static void cmdUnseal(char* arg) {
  if (g_state != ST_SEALED) { sendLine("ERR 409 NOTSEALED"); return; }
  if (!arg) { sendLine("ERR 400 BADREQ"); return; }
  if (unsealWithCode(arg)) {
    g_state  = ST_UNSEALED;
    g_authed = true;
    g_lastTickMs = millis();
    char r[48];
    snprintf(r, sizeof(r), "OK UNSEALED items=%d ttl_s=%lu",
             countEntries(), g_ttlInfinite ? 0 : ttlRemainS());
    sendLine(r);
    updateLed();
    g_screenInit = false;
    return;
  }
  g_failCount++;
  sendLine("ERR 401 BADCODE destroyed");
  selfDestruct("wrong unseal code");
}

static void cmdSet(char* k, char* v) {
  if (g_state != ST_STAGING) { sendLine("ERR 409 NOTSTAGING"); return; }
  if (!k || !v) { sendLine("ERR 400 BADREQ"); return; }
  uint8_t kb[MAX_KEY_LEN]; uint8_t vb[MAX_VAL_LEN];
  int kl = b64dec(k, strlen(k), kb, sizeof(kb));
  int vl = b64dec(v, strlen(v), vb, sizeof(vb));
  if (kl < 0 || vl < 0) { sendLine("ERR 400 BADB64"); return; }
  if (kl == 0 || kl > MAX_KEY_LEN || vl > MAX_VAL_LEN) { sendLine("ERR 413 TOOBIG"); return; }
  int idx = findEntry(kb, kl);
  if (idx < 0)
    for (int i = 0; i < MAX_ENTRIES; i++) if (!g_entries[i].used) { idx = i; break; }
  if (idx < 0) { sendLine("ERR 507 FULL"); return; }
  Entry& e = g_entries[idx];
  memset(e.key, 0, MAX_KEY_LEN);
  memset(e.val, 0, MAX_VAL_LEN);
  e.used = true; e.keyLen = (uint8_t)kl; e.valLen = (uint16_t)vl;
  memcpy(e.key, kb, kl);
  memcpy(e.val, vb, vl);
  memset(vb, 0, sizeof(vb));
  sendLine("OK SET");
}

static void cmdGet(char* k) {
  if (g_state != ST_UNSEALED && g_state != ST_STAGING) { sendLine("ERR 409 LOCKED"); return; }
  if (!k) { sendLine("ERR 400 BADREQ"); return; }
  uint8_t kb[MAX_KEY_LEN];
  int kl = b64dec(k, strlen(k), kb, sizeof(kb));
  if (kl < 0) { sendLine("ERR 400 BADB64"); return; }
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
  if (g_state != ST_UNSEALED && g_state != ST_STAGING) { sendLine("ERR 409 LOCKED"); return; }
  static char enc[4 * ((MAX_KEY_LEN + 2) / 3) + 4];
  int n = 0;
  for (auto& e : g_entries) {
    if (!e.used) continue;
    if (b64enc((const uint8_t*)e.key, e.keyLen, enc, sizeof(enc))) { sendLine(enc); n++; }
  }
  char r[24]; snprintf(r, sizeof(r), "OK %d", n);
  sendLine(r);
  g_lastReadMs = millis();
  ledReadFlash();
}

static void cmdSeal() {
  if (g_state != ST_STAGING) { sendLine("ERR 409 NOTSTAGING"); return; }
  if (countEntries() == 0)   { sendLine("ERR 400 EMPTY"); return; }
  if (!sealToFlash())        { sendLine("ERR 500 SEALFAIL"); return; }
  zeroEntries();
  g_state  = ST_SEALED;
  g_authed = false;
  g_lastTickMs = millis();
  sendLine("OK SEALED");
  updateLed();
  g_screenInit = false;
}

static void cmdTtl(char* arg) {
  if (g_state != ST_STAGING && g_state != ST_EMPTY) {
    sendLine("ERR 409 SET BEFORE SEAL"); return;
  }
  if (!arg) { sendLine("ERR 400 BADTTL"); return; }
  long sec = atol(arg);
  if (sec == 0) { sendLine("OK TTL 0"); selfDestruct("ttl 0"); return; }
  if (sec < 0)  { g_ttlInfinite = true; sendLine("OK TTL -1"); return; }
  if (sec < TTL_MIN_S || sec > TTL_MAX_S) { sendLine("ERR 400 BADTTL"); return; }
  g_ttlInfinite = false;
  g_ttlBudgetMs = (unsigned long)sec * 1000UL;
  g_ttlRemainMs = g_ttlBudgetMs;
  char r[24]; snprintf(r, sizeof(r), "OK TTL %ld", sec);
  sendLine(r);
}

static void cmdWipe() {
  if (g_state == ST_SEALED) { sendLine("ERR 409 SEALED unseal-or-wrongcode"); return; }
  sendLine("OK WIPED");
  selfDestruct("explicit wipe");
}

static void cmdStatus() {
  long lastRead = g_lastReadMs == 0 ? -1 : (long)((millis() - g_lastReadMs) / 1000);
  char r[150];
  snprintf(r, sizeof(r),
    "OK %s items=%d ttl_s=%ld sealed=%d last_read_s=%ld fails=%d",
    stateName(), countEntries(),
    g_ttlInfinite ? -1L : (long)ttlRemainS(),
    g_state == ST_SEALED ? 1 : 0, lastRead, g_failCount);
  sendLine(r);
}

static void handleLine(char* line) {
  g_lastCmdMs = millis();
  char* sp1 = strchr(line, ' ');
  if (sp1) *sp1 = 0;
  char* a1 = sp1 ? sp1 + 1 : nullptr;
  char* a2 = nullptr;
  if (a1) { char* sp2 = strchr(a1, ' '); if (sp2) { *sp2 = 0; a2 = sp2 + 1; } }
  for (char* p = line; *p; p++) *p = toupper(*p);

  if (strcmp(line, "PING") == 0) {
    char r[48];
    snprintf(r, sizeof(r), "OK PONG vault/2 %s %d", stateName(), countEntries());
    sendLine(r);
    return;
  }
  if (strcmp(line, "STATUS") == 0) { cmdStatus(); return; }
  if (strcmp(line, "AUTH")   == 0) { cmdAuth(a1);   return; }
  if (strcmp(line, "UNSEAL") == 0) { cmdUnseal(a1); return; }

  if (strcmp(line, "SET")  == 0) { if (!g_authed) { sendLine("ERR 401 NOAUTH"); return; } cmdSet(a1, a2); return; }
  if (strcmp(line, "GET")  == 0) { cmdGet(a1);  return; }
  if (strcmp(line, "LIST") == 0) { cmdList();   return; }
  if (strcmp(line, "SEAL") == 0) { if (!g_authed) { sendLine("ERR 401 NOAUTH"); return; } cmdSeal(); return; }
  if (strcmp(line, "TTL")  == 0) { if (!g_authed && g_state != ST_EMPTY) { sendLine("ERR 401 NOAUTH"); return; } cmdTtl(a1); return; }
  if (strcmp(line, "WIPE") == 0) { if (!g_authed && g_state != ST_UNSEALED) { sendLine("ERR 401 NOAUTH"); return; } cmdWipe(); return; }
  sendLine("ERR 400 BADREQ");
}

static void pumpSerial() {
  while (Serial.available() > 0) {
    int c = Serial.read();
    if (c < 0) break;
    if (c == '\r') continue;
    if (c == '\n') {
      if (g_rxOverflow) { sendLine("ERR 413 TOOBIG"); g_rxOverflow = false; }
      else { g_rx[g_rxLen] = 0; if (g_rxLen > 0) handleLine(g_rx); }
      g_rxLen = 0;
      continue;
    }
    if (g_rxLen >= RX_BUF_LEN - 1) { g_rxOverflow = true; continue; }
    g_rx[g_rxLen++] = (char)c;
  }
}

static void trackConnection() {
  bool conn = (bool)Serial;
  if (g_wasConnected && !conn && g_state == ST_STAGING) {
    g_authed = false;            // closing during staging drops auth
  }
  g_wasConnected = conn;
}

static void tickTtl() {
  unsigned long now = millis();
  if (g_state != ST_SEALED && g_state != ST_UNSEALED) { g_lastTickMs = now; return; }
  if (g_ttlInfinite) { g_lastTickMs = now; return; }
  unsigned long dt = now - g_lastTickMs;
  g_lastTickMs = now;
  if (dt > g_ttlRemainMs) g_ttlRemainMs = 0;
  else g_ttlRemainMs -= dt;
  if (g_ttlRemainMs == 0) { selfDestruct("ttl expired (powered-time)"); return; }
  if (now - g_lastPersistMs >= TTL_PERSIST_MS) {
    persistTtl();
    g_lastPersistMs = now;
  }
}

// ---- entrypoints ---------------------------------------------------------

void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println();
  Serial.println(F("secrets-courier boot"));

  pinMode(PIN_TFT_BL, OUTPUT);
  digitalWrite(PIN_TFT_BL, HIGH);
  tft.init(TFT_W, TFT_H);
  tft.setRotation(0);
  tft.fillScreen(COL_BG);

  zeroEntries();
  generateCode();

  if (flashHasBlob()) {
    BlobHeader h;
    if (loadHeader(h)) {
      g_state = ST_SEALED;
      g_ttlInfinite = (h.ttlRemainingMs == 0xFFFFFFFFu);
      g_ttlRemainMs = g_ttlInfinite ? DEFAULT_TTL_MS : h.ttlRemainingMs;
      Serial.println(F("sealed payload found in flash"));
    } else {
      eraseFlash();          // corrupt/foreign blob → destroy
      g_state = ST_EMPTY;
    }
  } else {
    g_state = ST_EMPTY;
  }

  g_lastTickMs = millis();
  render();
  updateLed();
  Serial.println(F("ready"));
}

void loop() {
  unsigned long now = millis();
  trackConnection();
  pumpSerial();
  tickTtl();

  if (g_authed && g_state == ST_STAGING &&
      g_lastCmdMs != 0 && now - g_lastCmdMs > IDLE_DEAUTH_MS)
    g_authed = false;

  if (now - g_lastRenderMs >= RENDER_MS) {
    render();
    updateLed();
    g_lastRenderMs = now;
  }
  delay(5);
}
