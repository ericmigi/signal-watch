// Fieldwatch detection core. See Fieldwatch.h for attribution.
#include "Fieldwatch.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace fw {

namespace {

constexpr uint8_t AD_UUID16_PARTIAL = 0x02;
constexpr uint8_t AD_UUID16_COMPLETE = 0x03;
constexpr uint8_t AD_UUID128_PARTIAL = 0x06;
constexpr uint8_t AD_UUID128_COMPLETE = 0x07;
constexpr uint8_t AD_NAME_SHORT = 0x08;
constexpr uint8_t AD_NAME_COMPLETE = 0x09;
constexpr uint8_t AD_SERVICE_DATA16 = 0x16;
constexpr uint8_t AD_MFG = 0xFF;

uint16_t le16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
int32_t le32(const uint8_t* p) {
  return static_cast<int32_t>(static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
                              (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24));
}

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

int hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// True when `data` starts with the bytes spelled by `hex` (up to `hexLen` chars).
bool startsWithHex(const uint8_t* data, size_t len, const char* hex, size_t hexLen) {
  if (hexLen % 2 != 0 || hexLen / 2 > len) return false;
  for (size_t i = 0; i < hexLen / 2; i++) {
    const int hi = hexNibble(hex[2 * i]), lo = hexNibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0 || data[i] != static_cast<uint8_t>((hi << 4) | lo)) return false;
  }
  return true;
}

bool containsBytes(const uint8_t* data, size_t len, const char* hex, size_t hexLen) {
  if (hexLen == 0 || hexLen / 2 > len) return false;
  for (size_t i = 0; i + hexLen / 2 <= len; i++) {
    if (startsWithHex(data + i, len - i, hex, hexLen)) return true;
  }
  return false;
}

uint16_t parseHex16(const char* hex) {
  uint16_t v = 0;
  for (int i = 0; i < 4; i++) v = static_cast<uint16_t>((v << 4) | static_cast<uint16_t>(hexNibble(hex[i]) & 0xF));
  return v;
}

uint32_t fnv1a(const char* s) {
  uint32_t h = 2166136261u;
  for (; *s; s++) {
    h ^= static_cast<uint8_t>(*s);
    h *= 16777619u;
  }
  return h ? h : 1;
}

void copyAscii(char* out, size_t outLen, const uint8_t* src, size_t srcLen) {
  size_t n = std::min(srcLen, outLen - 1);
  size_t w = 0;
  for (size_t i = 0; i < n; i++) {
    const uint8_t c = src[i];
    if (c == 0) break;
    out[w++] = (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '?';
  }
  while (w > 0 && out[w - 1] == ' ') w--;
  out[w] = '\0';
}

int medianOf(int8_t* values, int count) {
  std::sort(values, values + count);
  return values[count / 2];
}

}  // namespace

// ---------------------------------------------------------------------------
// AdView
// ---------------------------------------------------------------------------

template <typename Fn>
void AdView::each(Fn&& fn) const {
  size_t i = 0;
  while (i + 1 < n) {
    const uint8_t len = p[i];
    if (len == 0 || i + 1 + len > n) return;
    if (fn(p[i + 1], p + i + 2, static_cast<uint8_t>(len - 1))) return;
    i += 1 + len;
  }
}

template <typename Fn>
void AdView::eachServiceData16(Fn&& fn) const {
  each([&](uint8_t type, const uint8_t* d, uint8_t len) {
    if (type == AD_SERVICE_DATA16 && len >= 2) {
      return fn(le16(d), Bytes{d + 2, static_cast<uint8_t>(len - 2)});
    }
    return false;
  });
}

template <typename Fn>
void AdView::eachMfg(Fn&& fn) const {
  each([&](uint8_t type, const uint8_t* d, uint8_t len) {
    if (type == AD_MFG && len >= 2) return fn(le16(d), Bytes{d + 2, static_cast<uint8_t>(len - 2)});
    return false;
  });
}

bool AdView::mfg(uint16_t company, Bytes& out) const {
  bool found = false;
  eachMfg([&](uint16_t id, Bytes b) {
    if (id != company) return false;
    out = b;
    found = true;
    return true;
  });
  return found;
}

bool AdView::anyMfg(uint16_t& company, Bytes& out) const {
  bool found = false;
  eachMfg([&](uint16_t id, Bytes b) {
    company = id;
    out = b;
    found = true;
    return true;
  });
  return found;
}

bool AdView::serviceData16(uint16_t uuid, Bytes& out) const {
  bool found = false;
  eachServiceData16([&](uint16_t id, Bytes b) {
    if (id != uuid) return false;
    out = b;
    found = true;
    return true;
  });
  return found;
}

bool AdView::hasUuid16(uint16_t uuid) const {
  bool found = false;
  each([&](uint8_t type, const uint8_t* d, uint8_t len) {
    if (type == AD_UUID16_PARTIAL || type == AD_UUID16_COMPLETE) {
      for (uint8_t i = 0; i + 1 < len; i += 2) {
        if (le16(d + i) == uuid) return found = true;
      }
    } else if (type == AD_SERVICE_DATA16 && len >= 2 && le16(d) == uuid) {
      return found = true;
    }
    return false;
  });
  return found;
}

bool AdView::hasUuid128(const char* hex32) const {
  uint8_t want[16];
  for (int i = 0; i < 16; i++) {
    const int hi = hexNibble(hex32[2 * i]), lo = hexNibble(hex32[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    want[15 - i] = static_cast<uint8_t>((hi << 4) | lo);  // AD stores UUIDs little-endian
  }
  bool found = false;
  each([&](uint8_t type, const uint8_t* d, uint8_t len) {
    if (type != AD_UUID128_PARTIAL && type != AD_UUID128_COMPLETE) return false;
    for (uint8_t i = 0; i + 16 <= len; i += 16) {
      if (memcmp(d + i, want, 16) == 0) return found = true;
    }
    return false;
  });
  return found;
}

void AdView::name(char* out, size_t outLen) const {
  out[0] = '\0';
  each([&](uint8_t type, const uint8_t* d, uint8_t len) {
    if (type != AD_NAME_COMPLETE && type != AD_NAME_SHORT) return false;
    copyAscii(out, outLen, d, len);
    return type == AD_NAME_COMPLETE;
  });
}

// ---------------------------------------------------------------------------
// Wi-Fi beacons
// ---------------------------------------------------------------------------

namespace {

constexpr size_t MAC_HEADER = 24;
constexpr size_t FIXED_PARAMS = 12;  // timestamp, interval, capability

// Calls fn(id, data, len) for each information element; stops when fn returns true.
template <typename Fn>
void eachIe(const uint8_t* frame, size_t len, Fn&& fn) {
  size_t i = MAC_HEADER + FIXED_PARAMS;
  while (i + 2 <= len) {
    const uint8_t id = frame[i], ieLen = frame[i + 1];
    if (i + 2 + ieLen > len) return;
    if (fn(id, frame + i + 2, ieLen)) return;
    i += 2 + ieLen;
  }
}

bool isBeaconFrame(const uint8_t* frame, size_t len) {
  if (len < MAC_HEADER + FIXED_PARAMS) return false;
  const uint8_t fc = frame[0];
  const uint8_t type = (fc >> 2) & 0x3, subtype = (fc >> 4) & 0xF;
  return type == 0 && (subtype == 8 || subtype == 5);
}

// AKM suite selectors from an RSN or WPA element (`at` = pairwise count offset).
// `legacy` marks WPA2-era suites; next to SAE they mean WPA2/WPA3 transition mode.
struct Akms {
  bool enterprise = false, personal = false, strong = false, legacy = false;
};
Akms readAkms(const uint8_t* d, size_t len, size_t at) {
  Akms a;
  if (at + 2 > len) return a;
  at += 2 + 4u * le16(d + at);
  if (at + 2 > len) return a;
  const uint16_t count = le16(d + at);
  at += 2;
  for (uint16_t k = 0; k < count && at + 4 <= len; k++, at += 4) {
    const uint8_t t = d[at + 3];
    if (t == 1 || t == 3 || t == 5 || t == 11 || t == 12 || t == 13) a.enterprise = true;
    if (t == 2 || t == 4 || t == 6 || t == 8 || t == 9 || t == 24 || t == 25) a.personal = true;
    if (t == 8 || t == 9 || t == 11 || t == 12 || t == 13 || t == 18 || t == 24 || t == 25) a.strong = true;
    if (t >= 1 && t <= 6) a.legacy = true;
  }
  return a;
}

}  // namespace

bool parseBeacon(const uint8_t* frame, size_t len, Beacon& out) {
  if (!isBeaconFrame(frame, len)) return false;
  out = Beacon{};
  memcpy(out.bssid, frame + 16, 6);
  const uint16_t capability = le16(frame + MAC_HEADER + 10);
  bool rsn = false, wpa = false, rsnStrong = false, rsnLegacy = false, sawSsid = false;
  eachIe(frame, len, [&](uint8_t id, const uint8_t* d, uint8_t ieLen) {
    if (id == 0 && !sawSsid) {
      sawSsid = true;
      const size_t n = std::min<size_t>(ieLen, 32);
      bool allZero = true;
      for (size_t i = 0; i < n; i++) allZero = allZero && d[i] == 0;
      out.hidden = n == 0 || allZero;
      if (!out.hidden) copyAscii(out.ssid, sizeof(out.ssid), d, n);
    } else if (id == 48 && ieLen >= 8) {  // RSN: version, group cipher, then suites
      rsn = true;
      const Akms a = readAkms(d, ieLen, 6);
      out.enterprise = out.enterprise || a.enterprise;
      out.personal = out.personal || a.personal;
      rsnStrong = rsnStrong || a.strong;
      rsnLegacy = rsnLegacy || a.legacy;
    } else if (id == 221 && ieLen >= 4) {
      if (d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01) {  // WPA: OUI, type, version, group
        wpa = true;
        const Akms a = readAkms(d, ieLen, 10);
        out.enterprise = out.enterprise || a.enterprise;
        out.personal = out.personal || a.personal;
      } else if (d[0] == 0xFA && d[1] == 0x0B && d[2] == 0xBC && d[3] == 0x0D) {  // ASTM Remote ID
        out.remoteId = Bytes{d + 4, static_cast<uint8_t>(ieLen - 4)};
      }
    }
    return false;
  });
  if (rsn) {
    out.security = (rsnStrong && !rsnLegacy) ? SEC_WPA3 : SEC_WPA2;
  } else if (wpa) {
    out.security = SEC_WPA;
  } else if (capability & 0x0010) {
    out.security = SEC_WEP;
  } else {
    out.security = SEC_OPEN;
  }
  return true;
}

bool beaconHasVendorIe(const uint8_t* frame, size_t len, const uint8_t oui[3]) {
  if (!isBeaconFrame(frame, len)) return false;
  bool found = false;
  eachIe(frame, len, [&](uint8_t id, const uint8_t* d, uint8_t ieLen) {
    if (id == 221 && ieLen >= 3 && memcmp(d, oui, 3) == 0) found = true;
    return found;
  });
  return found;
}

// ---------------------------------------------------------------------------
// Pairing flood
// ---------------------------------------------------------------------------

namespace {
const uint8_t kLoveSpouse[] = {0x6D, 0xB6, 0x43, 0xCE, 0x97, 0xFE, 0x42, 0x7C};
const uint8_t kEasyBuds[] = {0x42, 0x09, 0x81, 0x02, 0x14, 0x15, 0x03, 0x21, 0x01, 0x09};
const uint8_t kEasyWatch[] = {0x01, 0x00, 0x02, 0x00, 0x01, 0x01, 0xFF, 0x00, 0x00, 0x43};

bool startsWith(Bytes b, const uint8_t* prefix, size_t n) { return b.len >= n && memcmp(b.data, prefix, n) == 0; }

// Apple Continuity TLVs. Find My (0x12) and Nearby Info (0x10) are not popups;
// a 0x07 after Find My belongs to that advert.
uint8_t appleBits(Bytes b) {
  uint8_t bits = 0;
  bool sawFindMy = false;
  for (size_t i = 0; i + 2 <= b.len;) {
    const uint8_t type = b.data[i], len = b.data[i + 1];
    if (len == 0 || i + 2 + len > b.len) break;
    if (type == 0x07 && !sawFindMy) bits |= FAM_APPLE_PROX;
    if (type == 0x0F) bits |= FAM_APPLE_ACTION;
    if (type == 0x12) sawFindMy = true;
    i += 2 + len;
  }
  return bits;
}
}  // namespace

uint8_t floodFamilies(const AdView& ad) {
  uint8_t bits = 0;
  ad.eachMfg([&](uint16_t id, Bytes b) {
    if (id == 0x004C) bits |= appleBits(b);
    if (id == 0x0006 && b.len >= 3 && b.data[0] == 0x03 && b.data[1] <= 0x02 && b.data[2] == 0x80)
      bits |= FAM_SWIFT_PAIR;
    if (id == 0x0075 && (startsWith(b, kEasyBuds, sizeof(kEasyBuds)) || startsWith(b, kEasyWatch, sizeof(kEasyWatch))))
      bits |= FAM_EASY_SETUP;
    if (id == 0x00FF && startsWith(b, kLoveSpouse, sizeof(kLoveSpouse))) bits |= FAM_LOVESPOUSE;
    return false;
  });
  Bytes fp;
  if (ad.serviceData16(0xFE2C, fp) && fp.len == 3) bits |= FAM_FAST_PAIR;  // 3-byte model ID = pairing mode
  return bits;
}

void floodFamilyNames(uint8_t families, char* out, size_t outLen) {
  static const char* const names[] = {"Apple pairing", "Apple Nearby Action", "Fast Pair",
                                      "Swift Pair",    "Samsung Easy Setup",  "LoveSpouse"};
  out[0] = '\0';
  for (int i = 0; i < 6; i++) {
    if (!(families & (1 << i))) continue;
    const size_t used = strlen(out);
    snprintf(out + used, outLen - used, "%s%s", used ? ", " : "", names[i]);
  }
}

void PairingFlood::reset() {
  head = count = 0;
  episode = false;
  popups = names = median = 0;
  fams = 0;
}

void PairingFlood::evict(uint32_t now) {
  while (count > 0 && now - window[head].at > WINDOW_MS) {
    head = (head + 1) % CAP;
    count--;
  }
}

bool PairingFlood::consider(const uint8_t mac[6], bool randomAddr, int8_t rssi, const AdView& ad, uint32_t now) {
  const uint8_t families = floodFamilies(ad);
  bool popup = families != 0;
  if (!popup) {
    char name[2];
    ad.name(name, sizeof(name));
    if (name[0] == '\0' || !randomAddr) return false;  // a stable named device stays out
  }
  evict(now);
  for (int i = 0; i < count; i++) {
    if (memcmp(window[(head + i) % CAP].mac, mac, 6) == 0) return false;  // not brand-new
  }
  if (count == CAP) {
    head = (head + 1) % CAP;
    count--;
  }
  Hit& h = window[(head + count) % CAP];
  memcpy(h.mac, mac, 6);
  h.at = now;
  h.rssi = rssi;
  h.popup = popup;
  h.families = families;
  count++;
  return publish();
}

void PairingFlood::tick(uint32_t now) {
  if (count == 0 && !episode) return;
  evict(now);
  publish();
}

bool PairingFlood::publish() {
  // One "band" per kind: hits within RSSI_BAND_DB of the median loudness, so a
  // spread-out crowd does not count as one burst.
  auto band = [&](bool popup, int& medianOut, uint8_t& famOut) {
    int8_t values[CAP];
    int total = 0, measured = 0;
    for (int i = 0; i < count; i++) {
      const Hit& h = window[(head + i) % CAP];
      if (h.popup != popup) continue;
      total++;
      if (h.rssi < 0 && h.rssi > -127) values[measured++] = h.rssi;
    }
    famOut = 0;
    if (total == 0) return 0;
    if (measured * 2 <= total) {
      for (int i = 0; i < count; i++) {
        const Hit& h = window[(head + i) % CAP];
        if (h.popup == popup) famOut |= h.families;
      }
      return total;
    }
    const int med = medianOf(values, measured);
    medianOut = med;
    int kept = 0;
    for (int i = 0; i < count; i++) {
      const Hit& h = window[(head + i) % CAP];
      if (h.popup != popup || !(h.rssi < 0 && h.rssi > -127)) continue;
      if (std::abs(h.rssi - med) <= RSSI_BAND_DB) {
        kept++;
        famOut |= h.families;
      }
    }
    return kept;
  };
  int popMedian = 0, nameMedian = 0;
  uint8_t popFams = 0, nameFams = 0;
  popups = band(true, popMedian, popFams);
  names = band(false, nameMedian, nameFams);
  const bool popupHot = popups >= POPUP_MIN;
  const bool nameHot = names >= NAME_MIN;
  if (!popupHot && !nameHot) {
    episode = false;
    return false;
  }
  fams = popupHot ? popFams : 0;
  median = popupHot ? popMedian : nameMedian;
  const bool starting = !episode;
  episode = true;
  return starting;
}

// ---------------------------------------------------------------------------
// Beacon flood
// ---------------------------------------------------------------------------

void BeaconFlood::reset() {
  memset(seen, 0, sizeof(seen));
  seenCount = 0;
  primed = false;
  freshCount = count = median = 0;
  channel = 0;
}

void BeaconFlood::beginSweep() { freshCount = 0; }

bool BeaconFlood::remember(uint32_t hash) {
  uint32_t slot = hash & (SEEN_CAP - 1);
  for (int probe = 0; probe < SEEN_CAP; probe++, slot = (slot + 1) & (SEEN_CAP - 1)) {
    if (seen[slot] == hash) return false;
    if (seen[slot] == 0) {
      seen[slot] = hash;
      seenCount++;
      return true;
    }
  }
  return false;
}

void BeaconFlood::beacon(const char* ssid, uint8_t ch, int8_t rssi) {
  if (!ssid || !ssid[0]) return;
  const uint32_t h = fnv1a(ssid);
  if (!remember(h) || !primed) return;
  if (freshCount < SWEEP_CAP) fresh[freshCount++] = Fresh{h, ch, rssi};
}

bool BeaconFlood::endSweep() {
  count = 0;
  bool flood = false;
  if (primed) {
    // Largest single-channel group of brand-new names within RSSI_BAND_DB of its median.
    for (int i = 0; i < freshCount; i++) {
      const uint8_t ch = fresh[i].channel;
      bool done = false;
      for (int j = 0; j < i; j++) done = done || fresh[j].channel == ch;
      if (done) continue;
      int8_t values[SWEEP_CAP];
      int n = 0;
      for (int j = 0; j < freshCount; j++)
        if (fresh[j].channel == ch) values[n++] = fresh[j].rssi;
      const int med = medianOf(values, n);
      int kept = 0;
      for (int j = 0; j < n; j++) kept += std::abs(values[j] - med) <= RSSI_BAND_DB;
      if (kept > count) {
        count = kept;
        channel = ch;
        median = med;
      }
    }
    // ponytail: no "gone on the next sweep" check or guest/extender suffix folding
    // (WifiBeaconFlood.kt does both); add them if busy venues false-alarm.
    flood = count >= MIN_NAMES;
  }
  primed = true;
  if (seenCount > SEEN_CAP * 3 / 4) {  // relearn instead of probing a full table
    memset(seen, 0, sizeof(seen));
    seenCount = 0;
    primed = false;
  }
  freshCount = 0;
  return flood;
}

// ---------------------------------------------------------------------------
// Remote ID
// ---------------------------------------------------------------------------

namespace {
constexpr size_t RID_MSG = 25;

bool validCoord(int32_t lat, int32_t lon) {
  return lat >= -900000000 && lat <= 900000000 && lon >= -1800000000 && lon <= 1800000000;
}

void parseRidMessage(const uint8_t* m, RemoteId& out) {
  switch (m[0] >> 4) {
    case 0: {  // Basic ID
      char id[21];
      copyAscii(id, sizeof(id), m + 2, 20);
      if (id[0]) memcpy(out.uasId, id, sizeof(id));
      break;
    }
    case 1: {  // Location
      const uint8_t flags = m[1];
      out.status = flags >> 4;
      const uint8_t sh = m[3];
      if (sh != 255) {
        const float mps = (flags & 1) ? sh * 0.75f + 63.75f : sh * 0.25f;
        out.speedCm = static_cast<uint16_t>(mps * 100.0f);
      }
      const int32_t lat = le32(m + 5), lon = le32(m + 9);
      if ((lat != 0 || lon != 0) && validCoord(lat, lon)) {
        out.lat = lat;
        out.lon = lon;
        out.hasLocation = true;
      }
      out.altM = static_cast<int16_t>(le16(m + 15) / 2 - 1000);
      break;
    }
    case 3:  // Self ID
      out.selfKind = m[1];
      copyAscii(out.selfId, sizeof(out.selfId), m + 2, 23);
      break;
    case 4: {  // System (operator position)
      const int32_t lat = le32(m + 2), lon = le32(m + 6);
      if ((lat != 0 || lon != 0) && validCoord(lat, lon)) {
        out.opLat = lat;
        out.opLon = lon;
        out.hasOperator = true;
      }
      break;
    }
    default:
      break;
  }
}

// Single 25-byte messages, or a message pack (type nibble 0xF).
bool parseRidFrom(const uint8_t* b, size_t len, size_t start, RemoteId& out) {
  if (start >= len) return false;
  int parsed = 0;
  if ((b[start] >> 4) == 0xF && start + 3 <= len) {
    const size_t size = std::max<size_t>(b[start + 1], RID_MSG);
    const uint8_t count = b[start + 2];
    size_t i = start + 3;
    for (uint8_t k = 0; k < count && i + RID_MSG <= len; k++, i += size) {
      parseRidMessage(b + i, out);
      parsed++;
    }
  } else {
    for (size_t i = start; i + RID_MSG <= len; i += RID_MSG) {
      parseRidMessage(b + i, out);
      parsed++;
    }
  }
  return parsed > 0;
}
}  // namespace

bool parseRemoteIdBle(const uint8_t* data, size_t len, RemoteId& out) {
  if (!data || len == 0) return false;
  // [0x0D app code][counter][message], or bare messages.
  const size_t start = (len >= 2 + RID_MSG && data[0] == 0x0D) ? 2 : 0;
  return parseRidFrom(data, len, start, out);
}

bool parseRemoteIdWifi(const uint8_t* data, size_t len, RemoteId& out) {
  if (!data || len == 0) return false;
  // ASTM [counter][messages]. Some senders use the BLE shape [0x0D][counter][messages];
  // take that only when a message pack starts at offset 2 and not at 1, so a
  // counter that happens to be 0x0D does not shift the parse.
  const bool bleShaped = len >= 3 + RID_MSG && data[0] == 0x0D && (data[1] >> 4) != 0xF && (data[2] >> 4) == 0xF;
  const size_t start = bleShaped ? 2 : 1;
  return parseRidFrom(data, len, start, out);
}

uint32_t distanceM(int32_t lat1, int32_t lon1, int32_t lat2, int32_t lon2) {
  constexpr double kDeg = 3.14159265358979323846 / 180.0 / 1e7;
  const double p1 = lat1 * kDeg, p2 = lat2 * kDeg;
  const double dp = (static_cast<double>(lat2) - lat1) * kDeg, dl = (static_cast<double>(lon2) - lon1) * kDeg;
  double a = std::sin(dp / 2) * std::sin(dp / 2) + std::cos(p1) * std::cos(p2) * std::sin(dl / 2) * std::sin(dl / 2);
  a = std::min(1.0, std::max(0.0, a));
  return static_cast<uint32_t>(6371000.0 * 2 * std::atan2(std::sqrt(a), std::sqrt(1 - a)));
}

void DroneTable::reset() {
  n = 0;
  newHead = newCount = 0;
  idHead = idCount = 0;
  swarmOpen = false;
  lastNewId = 0;
  swarmIds = 0;
}

bool DroneTable::rememberId(const char* id) {
  const uint32_t h = fnv1a(id);
  for (int i = 0; i < idCount; i++)
    if (knownIds[i] == h) return false;
  knownIds[idHead] = h;
  idHead = (idHead + 1) % ID_CAP;
  if (idCount < ID_CAP) idCount++;
  return true;
}

uint8_t DroneTable::observe(const uint8_t mac[6], const RemoteId& rid, int8_t rssi, bool wifi, uint32_t now) {
  uint8_t events = NONE;
  if (swarmOpen && now - lastNewId >= SWARM_QUIET_MS) swarmOpen = false;
  for (int i = 0; i < n;) {  // drop drones gone for STALE_MS
    if (now - drones[i].lastSeen > STALE_MS) {
      drones[i] = drones[--n];
    } else {
      i++;
    }
  }

  // Same UAS ID (BLE and Wi-Fi, or a new address) is one drone; else key by address.
  auto keyed = [&](const Drone& d) { return memcmp(d.keys[0], mac, 6) == 0 || memcmp(d.keys[1], mac, 6) == 0; };
  int idx = -1;
  for (int i = 0; i < n && idx < 0; i++) {
    if (rid.uasId[0] && strcmp(drones[i].rid.uasId, rid.uasId) == 0) idx = i;
  }
  for (int i = 0; i < n && idx < 0; i++) {
    if (keyed(drones[i]) && (!rid.uasId[0] || !drones[i].rid.uasId[0])) idx = i;
  }
  if (idx < 0) {
    if (n == CAP) {  // evict the stalest
      int oldest = 0;
      for (int i = 1; i < n; i++)
        if (drones[i].lastSeen < drones[oldest].lastSeen) oldest = i;
      drones[oldest] = drones[--n];
    }
    idx = n++;
    drones[idx] = Drone{};
    drones[idx].firstSeen = now;
    events |= NEW_DRONE;
  }
  if (rid.uasId[0]) {  // a blank-ID entry on this address is the same drone: fold it away
    for (int i = 0; i < n; i++) {
      if (i == idx || drones[i].rid.uasId[0] || !keyed(drones[i])) continue;
      drones[i] = drones[--n];
      if (idx == n) idx = i;
      break;
    }
  }
  Drone& d = drones[idx];
  memcpy(d.keys[wifi ? 1 : 0], mac, 6);
  // Merge: fields present in this advert overwrite.
  if (rid.uasId[0]) memcpy(d.rid.uasId, rid.uasId, sizeof(rid.uasId));
  if (rid.hasLocation) {
    d.rid.hasLocation = true;
    d.rid.lat = rid.lat;
    d.rid.lon = rid.lon;
    d.rid.altM = rid.altM;
    d.rid.speedCm = rid.speedCm;
    d.rid.status = rid.status;
  }
  if (rid.hasOperator) {
    d.rid.hasOperator = true;
    d.rid.opLat = rid.opLat;
    d.rid.opLon = rid.opLon;
  }
  if (rid.selfId[0] || rid.selfKind) {
    memcpy(d.rid.selfId, rid.selfId, sizeof(rid.selfId));
    d.rid.selfKind = rid.selfKind;
  }
  d.rssi = rssi;
  d.wifi = wifi;
  d.lastSeen = now;

  // Emergency follows the merged state, so one-message BLE adverts do not toggle it.
  const bool emergencyNow = d.rid.emergency();
  if (emergencyNow && !d.emergencyLatched) events |= EMERGENCY;
  d.emergencyLatched = emergencyNow;

  // Swarm: distinct new UAS IDs inside the window. A blank ID stays out.
  if (rid.uasId[0] && rememberId(rid.uasId)) {
    newTimes[newHead] = now;
    newHead = (newHead + 1) % CAP;
    if (newCount < CAP) newCount++;
    lastNewId = now;
    int recent = 0;
    for (int i = 0; i < newCount; i++) recent += now - newTimes[i] <= SWARM_WINDOW_MS;
    if (recent >= SWARM_MIN && !swarmOpen) {
      swarmOpen = true;
      swarmIds = recent;
      events |= SWARM;
    } else if (swarmOpen) {
      swarmIds = std::max(swarmIds, recent);
    }
  }
  return events;
}

// ---------------------------------------------------------------------------
// Trackers
// ---------------------------------------------------------------------------

TrackerState trackerState(const AdView& ad, const uint8_t mac[6], uint8_t key[8], TrackerFamily& family) {
  family = TF_NONE;
  memset(key, 0, 8);
  memcpy(key, mac, 6);
  Bytes b;
  // Samsung SmartTag FD5A: state in the low bits of the first byte; privacy ID is the stable key.
  if (ad.serviceData16(0xFD5A, b) && b.len >= 13 && (b.data[0] & 0xF8) == 0x10) {
    family = TF_SMARTTAG;
    memcpy(key, b.data + 4, 8);
    const uint8_t state = b.data[0] & 0x07;
    if (state >= 1 && state <= 3) return TRACKER_SEPARATED;
    if (state >= 4 && state <= 6) return TRACKER_NEAR;
    return TRACKER_NONE;
  }
  bool near = false, separated = false;
  if (ad.serviceData16(0xFCB2, b) && b.len >= 2) {  // DULT
    family = TF_DULT;
    ((b.data[1] & 0x01) ? near : separated) = true;
  }
  if (ad.serviceData16(0xFEAA, b) && b.len >= 1 && (b.data[0] == 0x40 || b.data[0] == 0x41)) {  // Find Hub
    family = TF_FIND_HUB;
    ((b.data[0] == 0x41) ? separated : near) = true;
  }
  if (ad.mfg(0x004C, b)) {
    // Find My long form with the "owner seen recently" bit clear is separated.
    // Any other Continuity TLV means an Apple phone or computer: skip.
    bool phone = false, appleNear = false, appleSep = false;
    for (size_t i = 0; i + 2 <= b.len;) {
      const uint8_t type = b.data[i], len = b.data[i + 1];
      if (len == 0 || i + 2 + len > b.len) break;
      if (type != 0x12) {
        phone = true;
      } else if (len == 0x02 || (len == 0x19 && (b.data[i + 2] & 0x04))) {
        appleNear = true;
      } else if (len == 0x19) {
        appleSep = true;
      }
      i += 2 + len;
    }
    if (!phone && (appleNear || appleSep)) {
      family = TF_APPLE;
      near = near || appleNear;
      separated = separated || appleSep;
    }
  }
  if (near) return TRACKER_NEAR;
  return separated ? TRACKER_SEPARATED : TRACKER_NONE;
}

const char* trackerFamilyName(TrackerFamily f) {
  switch (f) {
    case TF_APPLE: return "Find My tag";
    case TF_SMARTTAG: return "SmartTag";
    case TF_DULT: return "Tracker (DULT)";
    case TF_FIND_HUB: return "Find Hub tag";
    default: return "Tracker";
  }
}

int TrackerWatch::observe(const AdView& ad, const uint8_t mac[6], int8_t rssi, uint32_t now) {
  uint8_t key[8];
  TrackerFamily family;
  const TrackerState state = trackerState(ad, mac, key, family);
  if (state == TRACKER_NONE) return -1;
  int idx = -1;
  for (int i = 0; i < n; i++)
    if (memcmp(eps[i].key, key, 8) == 0) idx = i;
  if (state == TRACKER_NEAR) {  // back with its owner: the episode ends
    if (idx >= 0) eps[idx] = eps[--n];
    return -1;
  }
  if (idx < 0) {
    if (n == CAP) {
      int oldest = 0;
      for (int i = 1; i < n; i++)
        if (eps[i].lastHeard < eps[oldest].lastHeard) oldest = i;
      eps[oldest] = eps[--n];
    }
    idx = n++;
    eps[idx] = Episode{};
    memcpy(eps[idx].key, key, 8);
    eps[idx].startedAt = now;
  }
  Episode& e = eps[idx];
  memcpy(e.mac, mac, 6);
  e.family = family;
  e.rssi = rssi;
  e.lastHeard = now;
  // ponytail: time only. Fieldwatch also needs 3 GPS places 100 m apart; this device has no GPS.
  if (!e.raised && now - e.startedAt >= FOLLOW_MS) {
    e.raised = true;
    return idx;
  }
  return -1;
}

void TrackerWatch::tick(uint32_t now) {
  for (int i = 0; i < n;) {
    if (now - eps[i].lastHeard > GAP_MS) {
      eps[i] = eps[--n];
    } else {
      i++;
    }
  }
}

// ---------------------------------------------------------------------------
// Trusted networks
// ---------------------------------------------------------------------------

namespace {
bool trustable(const char* ssid) {
  if (!ssid || !ssid[0] || strlen(ssid) > 32) return false;
  for (const char* c = ssid; *c; c++)
    if (*c == '\t' || *c == '\n' || *c == '\r') return false;
  return true;
}
}  // namespace

TrustedNets::Net* TrustedNets::find(const char* ssid) {
  for (int i = 0; i < n; i++)
    if (strcmp(nets[i].ssid, ssid) == 0) return &nets[i];
  return nullptr;
}

const TrustedNets::Net* TrustedNets::find(const char* ssid) const {
  for (int i = 0; i < n; i++)
    if (strcmp(nets[i].ssid, ssid) == 0) return &nets[i];
  return nullptr;
}

bool TrustedNets::trust(const char* ssid) {
  if (!trustable(ssid) || find(ssid)) return find(ssid) != nullptr;
  if (n == NET_CAP) return false;
  nets[n] = Net{};
  strncpy(nets[n].ssid, ssid, 32);
  n++;
  return true;
}

void TrustedNets::untrust(const char* ssid) {
  for (int i = 0; i < n; i++) {
    if (strcmp(nets[i].ssid, ssid) == 0) {
      nets[i] = nets[--n];
      return;
    }
  }
}

bool TrustedNets::isTrusted(const char* ssid) const { return find(ssid) != nullptr; }

uint8_t TrustedNets::check(const Beacon& b) {
  if (b.hidden) return OK;
  Net* net = find(b.ssid);
  if (!net) return OK;
  bool known = false;
  for (int i = 0; i < net->apCount; i++) known = known || memcmp(net->aps[i].bssid, b.bssid, 6) == 0;

  auto learn = [&]() {
    if (net->apCount == AP_CAP) return;
    Ap& ap = net->aps[net->apCount++];
    memcpy(ap.bssid, b.bssid, 6);
    ap.security = b.security;
    ap.enterprise = b.enterprise;
    ap.personal = b.personal;
  };
  if (net->apCount == 0 && !known) {  // first AP after trusting: the baseline
    learn();
    learnedNew = true;
    return OK;
  }

  uint8_t reasons = OK;
  uint8_t baseMin = 255;
  bool baseOpen = false, allEnterprise = true, anyPersonal = false, sameVendor = false;
  for (int i = 0; i < net->apCount; i++) {
    const Ap& ap = net->aps[i];
    baseMin = std::min(baseMin, ap.security);
    baseOpen = baseOpen || ap.security <= SEC_WEP;
    allEnterprise = allEnterprise && ap.enterprise && !ap.personal;
    anyPersonal = anyPersonal || ap.personal;
    sameVendor = sameVendor || memcmp(ap.bssid, b.bssid, 3) == 0;
  }
  if (b.security <= SEC_WEP && !baseOpen) {
    reasons |= b.security == SEC_OPEN ? OPEN : WEAKER;
  } else if (b.security < baseMin) {
    reasons |= WEAKER;
  } else if (allEnterprise && b.personal && !anyPersonal) {
    reasons |= WEAKER;
  }
  // A new access point from a maker this name never used. Randomized BSSIDs carry no maker.
  // A known BSSID keeps its maker; only a downgrade (a replayed address running open) warns.
  if (!known && !sameVendor && !isRandomizedMac(b.bssid)) reasons |= UNKNOWN_VENDOR;
  // Another AP of the same mesh. A randomized BSSID carries no maker to vouch for it, so it is not learned.
  if (reasons == OK && !known && !isRandomizedMac(b.bssid)) {
    learn();
    learnedNew = true;
  }
  return reasons;
}

size_t TrustedNets::serialize(char* out, size_t outLen) const {
  size_t used = 0;
  out[0] = '\0';
  for (int i = 0; i < n; i++) {
    const Net& net = nets[i];
    for (int k = 0; k < std::max<int>(net.apCount, 1); k++) {
      int w;
      if (net.apCount == 0) {
        w = snprintf(out + used, outLen - used, "%s\t\t0\t0\n", net.ssid);
      } else {
        const Ap& ap = net.aps[k];
        w = snprintf(out + used, outLen - used, "%s\t%02X%02X%02X%02X%02X%02X\t%u\t%u\n", net.ssid, ap.bssid[0],
                     ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5], ap.security,
                     (ap.enterprise ? 1u : 0u) | (ap.personal ? 2u : 0u));
      }
      if (w < 0 || used + static_cast<size_t>(w) >= outLen) {  // never save a partial list
        out[0] = '\0';
        return 0;
      }
      used += static_cast<size_t>(w);
    }
  }
  return used;
}

void TrustedNets::deserialize(const char* text) {
  n = 0;
  while (text && *text) {
    const char* end = strchr(text, '\n');
    const size_t lineLen = end ? static_cast<size_t>(end - text) : strlen(text);
    char line[80];
    const size_t copy = std::min(lineLen, sizeof(line) - 1);
    memcpy(line, text, copy);
    line[copy] = '\0';
    text = end ? end + 1 : text + lineLen;

    char* tab1 = strchr(line, '\t');
    if (!tab1) continue;
    *tab1 = '\0';
    char* tab2 = strchr(tab1 + 1, '\t');
    if (!tab2) continue;
    *tab2 = '\0';
    char* tab3 = strchr(tab2 + 1, '\t');
    if (!tab3) continue;
    *tab3 = '\0';
    if (!trust(line)) continue;
    const char* hex = tab1 + 1;
    if (strlen(hex) != 12) continue;
    Net* net = find(line);
    if (net->apCount == AP_CAP) continue;
    Ap ap{};
    bool ok = true;
    for (int b = 0; b < 6; b++) {
      const int hi = hexNibble(hex[2 * b]), lo = hexNibble(hex[2 * b + 1]);
      ok = ok && hi >= 0 && lo >= 0;
      ap.bssid[b] = static_cast<uint8_t>((hi << 4) | lo);
    }
    if (!ok) continue;
    ap.security = static_cast<uint8_t>(std::min(atoi(tab2 + 1), 4));
    const int flags = atoi(tab3 + 1);
    ap.enterprise = flags & 1;
    ap.personal = flags & 2;
    net->aps[net->apCount++] = ap;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

bool isRandomizedMac(const uint8_t mac[6]) { return (mac[0] & 0x02) != 0; }

bool containsNoCase(const char* text, const char* needle) {
  if (!needle[0]) return true;
  for (; *text; text++) {
    const char* a = text;
    const char* b = needle;
    while (*a && *b && lower(*a) == lower(*b)) {
      a++;
      b++;
    }
    if (!*b) return true;
  }
  return false;
}

bool globMatch(const char* pattern, const char* text) {
  const char* star = nullptr;
  const char* resume = nullptr;
  while (*text) {
    if (*pattern == '*') {
      star = pattern++;
      resume = text;
    } else if (*pattern && (*pattern == '?' || lower(*pattern) == lower(*text))) {
      pattern++;
      text++;
    } else if (star) {
      pattern = star + 1;
      text = ++resume;
    } else {
      return false;
    }
  }
  while (*pattern == '*') pattern++;
  return *pattern == '\0';
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

namespace {
enum class RuleKind : uint8_t { OUI, VIE, NAME, GLOB, UUID, MFG, MFGDATA, SVCDATA };
enum class RuleRadio : uint8_t { ANY, BLE, WIFI };
struct CatalogRule {
  RuleKind kind;
  RuleRadio radio;
  uint16_t id;
  const char* text;
};
constexpr uint8_t kFleetMatchAny = 1;
constexpr uint8_t kFleetAlert = 2;
struct CatalogFleet {
  const char* name;
  uint16_t first;
  uint16_t count;
  uint8_t flags;
  uint8_t cls;
};

#include "FieldwatchCatalog.inc"

constexpr int kFleetCount = static_cast<int>(sizeof(kFleets) / sizeof(kFleets[0]));

// Fleet index for a 24-bit OUI, or -1.
int ouiFleet(const uint8_t mac[6], bool wifi) {
  const uint32_t key = (static_cast<uint32_t>(mac[0]) << 16) | (mac[1] << 8) | mac[2];
  const uint32_t* end = kOuis + sizeof(kOuis) / sizeof(kOuis[0]);
  const uint32_t* it = std::lower_bound(kOuis, end, key << 8);
  if (it == end || (*it >> 8) != key) return -1;
  if ((*it & 0x80) && !wifi) return -1;
  return kOuiFleets[*it & 0x7F];
}

bool macPrefix(const uint8_t mac[6], const char* hex) {
  return startsWithHex(mac, 6, hex, strlen(hex));
}

Match makeMatch(int fleet) {
  Match m;
  m.fleet = fleet;
  m.name = kFleets[fleet].name;
  m.className = kClassNames[kFleets[fleet].cls];
  m.alert = kFleets[fleet].flags & kFleetAlert;
  return m;
}

template <typename RuleHit>
Match firstFleet(int ouiHit, RuleHit&& hit, bool wifi) {
  for (int f = 0; f < kFleetCount; f++) {
    const CatalogFleet& fleet = kFleets[f];
    const bool any = fleet.flags & kFleetMatchAny;
    if (any && f == ouiHit) return makeMatch(f);
    int applicable = 0, hits = 0;
    for (int r = fleet.first; r < fleet.first + fleet.count; r++) {
      const CatalogRule& rule = kRules[r];
      if (rule.radio == (wifi ? RuleRadio::BLE : RuleRadio::WIFI)) continue;
      applicable++;
      if (hit(rule)) {
        hits++;
        if (any) return makeMatch(f);
      } else if (!any) {
        break;
      }
    }
    if (!any && applicable > 0 && hits == applicable) return makeMatch(f);
  }
  return Match{};
}
}  // namespace

int catalogSize() { return kFleetCount; }

const char* catalogName(int fleet) { return fleet >= 0 && fleet < kFleetCount ? kFleets[fleet].name : ""; }

Match matchBle(const AdView& ad, const uint8_t mac[6], bool randomAddr, const char* name) {
  // Random BLE addresses carry no maker prefix, whatever their top bits say.
  const int ouiHit = randomAddr ? -1 : ouiFleet(mac, false);
  return firstFleet(
      ouiHit,
      [&](const CatalogRule& rule) {
        switch (rule.kind) {
          case RuleKind::OUI:
            return macPrefix(mac, rule.text);
          case RuleKind::NAME:
            return name[0] && containsNoCase(name, rule.text);
          case RuleKind::GLOB:
            return name[0] && globMatch(rule.text, name);
          case RuleKind::UUID:
            return strlen(rule.text) == 4 ? ad.hasUuid16(parseHex16(rule.text))
                                          : strlen(rule.text) == 32 && ad.hasUuid128(rule.text);
          case RuleKind::MFG: {
            Bytes b;
            return ad.mfg(rule.id, b);
          }
          case RuleKind::MFGDATA: {
            bool hit = false;
            const size_t hexLen = strlen(rule.text);
            ad.eachMfg([&](uint16_t id, Bytes b) {
              hit = (rule.id == 0 || id == rule.id) && startsWithHex(b.data, b.len, rule.text, hexLen);
              return hit;
            });
            return hit;
          }
          case RuleKind::SVCDATA: {
            const char* colon = strchr(rule.text, ':');
            const char* prefix = colon ? colon + 1 : "";
            const size_t prefixLen = strlen(prefix);
            if (colon == rule.text) {  // any service data containing these bytes
              bool hit = false;
              ad.eachServiceData16([&](uint16_t, Bytes b) {
                hit = containsBytes(b.data, b.len, prefix, prefixLen);
                return hit;
              });
              return hit;
            }
            Bytes b;
            return ad.serviceData16(parseHex16(rule.text), b) && startsWithHex(b.data, b.len, prefix, prefixLen);
          }
          case RuleKind::VIE:
            return false;
        }
        return false;
      },
      false);
}

Match matchWifi(const uint8_t* frame, size_t len, const Beacon& b) {
  const int ouiHit = ouiFleet(b.bssid, true);
  return firstFleet(
      ouiHit,
      [&](const CatalogRule& rule) {
        switch (rule.kind) {
          case RuleKind::OUI:
            return macPrefix(b.bssid, rule.text);
          case RuleKind::NAME:
            return b.ssid[0] && containsNoCase(b.ssid, rule.text);
          case RuleKind::GLOB:
            return b.ssid[0] && globMatch(rule.text, b.ssid);
          case RuleKind::VIE: {
            uint8_t oui[3];
            if (strlen(rule.text) != 6) return false;
            for (int i = 0; i < 3; i++)
              oui[i] = static_cast<uint8_t>((hexNibble(rule.text[2 * i]) << 4) | hexNibble(rule.text[2 * i + 1]));
            return beaconHasVendorIe(frame, len, oui);
          }
          default:
            return false;  // BLE-only rule kinds
        }
      },
      true);
}

}  // namespace fw
