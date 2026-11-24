// Fieldwatch detection core: receive-only Wi-Fi and BLE observer rules.
//
// Detection rules, thresholds and the signature catalog follow Fieldwatch by
// Off Grid Pete LLC (https://github.com/OffGridPete/Fieldwatch, MIT License).
// No Arduino, radio or heap dependencies, so the host tests in test/fieldwatch
// exercise this exact code. Every table is fixed size: floods must not exhaust
// memory.
#pragma once

#include <cstddef>
#include <cstdint>

namespace fw {

// ---------------------------------------------------------------------------
// BLE advertising payload (AD structures)
// ---------------------------------------------------------------------------

struct Bytes {
  const uint8_t* data = nullptr;
  uint8_t len = 0;
};

// View over one advertising payload (advertising data + scan response).
class AdView {
 public:
  AdView(const uint8_t* payload, size_t len) : p(payload), n(len) {}
  // Manufacturer data for `company`, excluding the 2-byte company ID.
  bool mfg(uint16_t company, Bytes& out) const;
  // First manufacturer record of any company.
  bool anyMfg(uint16_t& company, Bytes& out) const;
  // Service data for a 16-bit UUID, excluding the UUID.
  bool serviceData16(uint16_t uuid, Bytes& out) const;
  // 16-bit UUID in a service list or as service data.
  bool hasUuid16(uint16_t uuid) const;
  // 128-bit UUID (32 uppercase hex chars, canonical big-endian text order).
  bool hasUuid128(const char* hex32) const;
  // Local name, NUL-terminated into `out` (empty when none).
  void name(char* out, size_t outLen) const;
  // Calls fn(uuid16, data) for each 16-bit service data record.
  template <typename Fn>
  void eachServiceData16(Fn&& fn) const;
  template <typename Fn>
  void eachMfg(Fn&& fn) const;

 private:
  template <typename Fn>
  void each(Fn&& fn) const;  // fn(type, data, len)
  const uint8_t* p;
  size_t n;
};

// ---------------------------------------------------------------------------
// Wi-Fi management frames
// ---------------------------------------------------------------------------

enum SecurityRank : uint8_t { SEC_OPEN = 0, SEC_WEP = 1, SEC_WPA = 2, SEC_WPA2 = 3, SEC_WPA3 = 4 };

struct Beacon {
  uint8_t bssid[6]{};
  char ssid[33]{};
  bool hidden = false;
  uint8_t security = SEC_OPEN;
  bool enterprise = false;
  bool personal = false;
  Bytes remoteId;  // vendor IE FA:0B:BC type 0x0D payload after the type byte
};

// Parses a beacon or probe response (full 802.11 frame). False for other frames.
bool parseBeacon(const uint8_t* frame, size_t len, Beacon& out);

// Vendor IE OUIs carried by a beacon, for catalog matching.
bool beaconHasVendorIe(const uint8_t* frame, size_t len, const uint8_t oui[3]);

// ---------------------------------------------------------------------------
// Bluetooth pairing flood (PairingFlood.kt)
// ---------------------------------------------------------------------------

enum FloodFamily : uint8_t {
  FAM_APPLE_PROX = 1,
  FAM_APPLE_ACTION = 2,
  FAM_FAST_PAIR = 4,
  FAM_SWIFT_PAIR = 8,
  FAM_EASY_SETUP = 16,
  FAM_LOVESPOUSE = 32,
};

// Pairing-popup families in one advert (0 when none).
uint8_t floodFamilies(const AdView& ad);
void floodFamilyNames(uint8_t families, char* out, size_t outLen);

class PairingFlood {
 public:
  static constexpr uint32_t WINDOW_MS = 10000;
  static constexpr int POPUP_MIN = 10;
  static constexpr int NAME_MIN = 15;
  static constexpr int RSSI_BAND_DB = 12;
  static constexpr int CAP = 96;

  // Every advert. Repeat addresses inside the window are ignored.
  // Returns true when a new flood episode starts.
  bool consider(const uint8_t mac[6], bool randomAddr, int8_t rssi, const AdView& ad, uint32_t now);
  // Ends the episode once the window empties. Call regularly.
  void tick(uint32_t now);
  bool active() const { return episode; }
  int popupCount() const { return popups; }
  int nameCount() const { return names; }
  int medianRssi() const { return median; }
  uint8_t families() const { return fams; }
  void reset();

 private:
  struct Hit {
    uint8_t mac[6];
    uint32_t at;
    int8_t rssi;
    bool popup;
    uint8_t families;
  };
  Hit window[CAP]{};
  int head = 0, count = 0;
  bool episode = false;
  int popups = 0, names = 0, median = 0;
  uint8_t fams = 0;

  void evict(uint32_t now);
  bool publish();
};

// ---------------------------------------------------------------------------
// Wi-Fi beacon flood (WifiBeaconFlood.kt). One sweep = one pass over all channels.
// ---------------------------------------------------------------------------

class BeaconFlood {
 public:
  static constexpr int MIN_NAMES = 15;
  static constexpr int RSSI_BAND_DB = 6;
  static constexpr int SEEN_CAP = 1024;  // power of two
  static constexpr int SWEEP_CAP = 96;

  void beginSweep();
  void beacon(const char* ssid, uint8_t channel, int8_t rssi);
  // Returns true when this sweep is a flood (largest channel group).
  bool endSweep();
  int lastCount() const { return count; }
  uint8_t lastChannel() const { return channel; }
  int lastMedian() const { return median; }
  void reset();

 private:
  uint32_t seen[SEEN_CAP]{};  // FNV-1a hashes, 0 = empty
  int seenCount = 0;
  bool primed = false;  // the first sweep only learns
  struct Fresh {
    uint32_t hash;
    uint8_t channel;
    int8_t rssi;
  };
  Fresh fresh[SWEEP_CAP]{};
  int freshCount = 0;
  int count = 0, median = 0;
  uint8_t channel = 0;
  bool remember(uint32_t hash);  // true when the name was not seen before
};

// ---------------------------------------------------------------------------
// Remote ID (ASTM F3411 / OpenDroneID, OpenDroneId.kt)
// ---------------------------------------------------------------------------

struct RemoteId {
  char uasId[21]{};
  bool hasLocation = false;
  int32_t lat = 0, lon = 0;  // degrees * 1e7
  int16_t altM = 0;
  uint16_t speedCm = 0;  // cm/s
  uint8_t status = 0;    // 3 = emergency
  bool hasOperator = false;
  int32_t opLat = 0, opLon = 0;
  char selfId[24]{};
  uint8_t selfKind = 0;  // 1 = emergency description
  bool emergency() const { return status == 3 || selfKind == 1; }
};

// BLE service data for 0xFFFA (after the UUID). Fields seen are merged into `out`.
bool parseRemoteIdBle(const uint8_t* data, size_t len, RemoteId& out);
// Wi-Fi vendor IE payload after OUI FA:0B:BC and type 0x0D.
bool parseRemoteIdWifi(const uint8_t* data, size_t len, RemoteId& out);
// Great-circle distance in metres between two 1e7-degree points.
uint32_t distanceM(int32_t lat1, int32_t lon1, int32_t lat2, int32_t lon2);

struct Drone {
  uint8_t keys[2][6];  // last BLE and Wi-Fi address
  RemoteId rid;
  int8_t rssi;
  bool wifi;
  uint32_t firstSeen, lastSeen;
  bool emergencyLatched;
};

class DroneTable {
 public:
  static constexpr int CAP = 16;
  static constexpr uint32_t SWARM_WINDOW_MS = 30000;
  static constexpr int SWARM_MIN = 5;
  static constexpr uint32_t SWARM_QUIET_MS = 120000;
  static constexpr uint32_t STALE_MS = 300000;

  enum Event : uint8_t { NONE = 0, NEW_DRONE = 1, EMERGENCY = 2, SWARM = 4 };
  // `mac` keys the drone while its UAS ID is unknown. Returns Event bits.
  uint8_t observe(const uint8_t mac[6], const RemoteId& rid, int8_t rssi, bool wifi, uint32_t now);
  int count() const { return n; }
  const Drone& at(int i) const { return drones[i]; }
  int swarmCount() const { return swarmIds; }
  // While a swarm is open, single new drones stay quiet: the swarm warning covers them.
  bool swarming() const { return swarmOpen; }
  void reset();

 private:
  static constexpr int ID_CAP = 32;
  Drone drones[CAP]{};
  int n = 0;
  uint32_t knownIds[ID_CAP]{};  // hashes of UAS IDs already counted for the swarm
  int idHead = 0, idCount = 0;
  bool rememberId(const char* id);
  uint32_t newTimes[CAP]{};  // first-seen times of distinct UAS IDs, ring
  int newHead = 0, newCount = 0;
  bool swarmOpen = false;
  uint32_t lastNewId = 0;
  int swarmIds = 0;
};

// ---------------------------------------------------------------------------
// Trackers separated from their owner (TrackerWatch.kt, SmartTag.kt)
// ---------------------------------------------------------------------------

enum TrackerState : uint8_t { TRACKER_NONE, TRACKER_NEAR, TRACKER_SEPARATED };
enum TrackerFamily : uint8_t { TF_NONE, TF_APPLE, TF_SMARTTAG, TF_DULT, TF_FIND_HUB };

// Reads the owner-separated flag. `key` gets a stable identity: the SmartTag
// privacy ID when present, else the address.
TrackerState trackerState(const AdView& ad, const uint8_t mac[6], uint8_t key[8], TrackerFamily& family);
const char* trackerFamilyName(TrackerFamily f);

class TrackerWatch {
 public:
  static constexpr int CAP = 24;
  static constexpr uint32_t FOLLOW_MS = 30UL * 60000;
  static constexpr uint32_t GAP_MS = 20UL * 60000;

  struct Episode {
    uint8_t key[8];
    uint8_t mac[6];
    TrackerFamily family;
    int8_t rssi;
    uint32_t startedAt, lastHeard;
    bool raised;
  };
  // Returns the episode index when a "tag following you" warning is due, else -1.
  int observe(const AdView& ad, const uint8_t mac[6], int8_t rssi, uint32_t now);
  void tick(uint32_t now);
  int count() const { return n; }
  const Episode& at(int i) const { return eps[i]; }
  void reset() { n = 0; }

 private:
  Episode eps[CAP]{};
  int n = 0;
};

// ---------------------------------------------------------------------------
// Trusted networks (TrustedNetwork.kt): evil twin and downgrade warnings
// ---------------------------------------------------------------------------

class TrustedNets {
 public:
  static constexpr int NET_CAP = 8;
  static constexpr int AP_CAP = 8;
  enum Reason : uint8_t { OK = 0, OPEN = 1, WEAKER = 2, UNKNOWN_VENDOR = 4 };

  struct Ap {
    uint8_t bssid[6];
    uint8_t security;
    bool enterprise, personal;
  };
  struct Net {
    char ssid[33];
    Ap aps[AP_CAP];
    uint8_t apCount;
  };

  // Learns every AP heard on `ssid` from now on (first sighting per BSSID).
  bool trust(const char* ssid);
  void untrust(const char* ssid);
  bool isTrusted(const char* ssid) const;
  // Learn mode adds this AP when the name was just trusted. Returns Reason bits.
  uint8_t check(const Beacon& b);
  // True once since the last call when check() learned a new AP (time to save).
  bool takeLearned() {
    const bool l = learnedNew;
    learnedNew = false;
    return l;
  }
  int count() const { return n; }
  const Net& at(int i) const { return nets[i]; }
  // Text form for SD persistence: one "ssid\tbssid\tsec\tflags" line per AP.
  // Returns 0 when `out` cannot hold every line; SERIAL_MAX always fits.
  static constexpr size_t SERIAL_MAX = NET_CAP * AP_CAP * 56 + 1;
  size_t serialize(char* out, size_t outLen) const;
  void deserialize(const char* text);

 private:
  Net nets[NET_CAP]{};
  int n = 0;
  bool learnedNew = false;
  Net* find(const char* ssid);
  const Net* find(const char* ssid) const;
};

// ---------------------------------------------------------------------------
// Signature catalog (DefaultCatalog.kt)
// ---------------------------------------------------------------------------

struct Match {
  int fleet = -1;
  const char* name = nullptr;
  const char* className = nullptr;
  bool alert = false;
};

Match matchBle(const AdView& ad, const uint8_t mac[6], bool randomAddr, const char* name);
Match matchWifi(const uint8_t* frame, size_t len, const Beacon& b);
int catalogSize();
const char* catalogName(int fleet);

// Case-insensitive helpers shared by the catalog.
bool globMatch(const char* pattern, const char* text);
bool containsNoCase(const char* text, const char* needle);
bool isRandomizedMac(const uint8_t mac[6]);  // locally administered bit

}  // namespace fw
