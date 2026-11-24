#pragma once
// Fieldwatch: receive-only Wi-Fi and BLE observer with a signature library,
// flood, Remote ID, tracker and trusted-network warnings. Detection rules follow
// Fieldwatch by Off Grid Pete LLC (https://github.com/OffGridPete/Fieldwatch, MIT).
#include <Fieldwatch.h>

#include <cstdint>
#include <memory>

#include "FieldwatchRadio.h"
#include "activities/Activity.h"
#include "util/ButtonNavigator.h"

class FieldwatchActivity final : public Activity {
 public:
  explicit FieldwatchActivity(GfxRenderer& renderer, MappedInputManager& mappedInput)
      : Activity("Fieldwatch", renderer, mappedInput) {}
  void onEnter() override;
  void onExit() override;
  void loop() override;
  void render(RenderLock&&) override;
  bool preventAutoSleep() override { return running; }
  bool skipLoopDelay() override { return running; }

 private:
  enum Tab : uint8_t { TAB_LIVE, TAB_ALERTS, TAB_DRONES, TAB_NETS, TAB_COUNT };

  struct Device {
    uint8_t mac[6];
    bool wifi;
    char name[33];  // BLE name or SSID
    int8_t rssi;
    int16_t fleet;  // catalog index, or FLEET_UNCHECKED / FLEET_NONE
    uint8_t channel;
    uint8_t security;
    bool enterprise, personal;
    bool alerted;
    bool separated;  // tracker away from its owner
    uint32_t firstSeen, lastSeen;
  };
  static constexpr int DEVICE_CAP = 64;
  static constexpr int16_t FLEET_UNCHECKED = -1;
  static constexpr int16_t FLEET_NONE = -2;  // matched once, nothing found

  // De-duplication that survives eviction from the device table. Alerts get their
  // own ring so a crowd of ordinary matches cannot push them out.
  enum OnceKind : uint8_t { ONCE_BLE_HIT, ONCE_WIFI_HIT, ONCE_TRUSTED };
  struct OnceRing {
    static constexpr int CAP = 64;
    uint32_t keys[CAP]{};
    int head = 0, count = 0;
    bool first(const uint8_t mac[6], uint8_t kind);
  };
  OnceRing hitsLogged;
  OnceRing alertsRaised;

  struct Alert {
    uint32_t at;
    char title[40];
    char detail[72];
  };
  static constexpr int ALERT_CAP = 24;

  std::unique_ptr<FieldwatchRadio> radio;
  fw::PairingFlood pairing;
  fw::BeaconFlood beaconFlood;
  fw::DroneTable drones;
  fw::TrackerWatch trackers;
  fw::TrustedNets trusted;

  Device devices[DEVICE_CAP]{};
  int deviceCount = 0;
  Alert alerts[ALERT_CAP]{};  // newest at index 0
  int alertCount = 0;
  int unseenAlerts = 0;
  bool showAlert = false;

  bool running = false;
  bool allocFailed = false;
  Tab tab = TAB_LIVE;
  int selector = 0;
  uint32_t startedAt = 0;
  uint32_t lastRender = 0;
  uint32_t lastSweep = 0;
  uint32_t lastBeaconFlood = 0;  // last beacon-flood alert
  uint32_t floodSeenAt = 0;      // last sweep judged a flood
  uint32_t popupQuietUntil = 0;
  static constexpr uint32_t POPUP_QUIET_MS = 10000;
  bool wifiPhase = false;  // copied from the radio in loop(); render never touches the radio
  uint8_t channel = 0;
  char selectedSsid[33]{};  // Networks row drawn as selected (written by render, read under the lock)
  bool trustedDirty = false;
  uint32_t lastTrustedSave = 0;
  char logPath[48]{};
  char logBuf[1024]{};  // CSV lines batched into one SD write
  size_t logLen = 0;
  uint32_t lastFlush = 0;
  static constexpr uint32_t LOG_FLUSH_MS = 5000;
  ButtonNavigator buttonNavigator;

  void start();
  void stop();
  void drain();
  void onBle(const FwBleFrame& f, uint32_t now);
  void onWifi(const FwWifiFrame& f, uint32_t now);
  Device* find(const uint8_t mac[6], bool wifi);
  Device& upsert(const uint8_t mac[6], bool wifi, uint32_t now);
  bool onRemoteId(const uint8_t mac[6], const fw::RemoteId& rid, int8_t rssi, bool wifi, uint32_t now);
  void handleInput();
  void raise(const char* title, const char* detail);
  void logLine(const char* kind, const char* text);
  void flushLog();
  void loadTrusted();
  void saveTrusted();
  void toggleTrust(const char* ssid);

  int listSize() const;
  int sortedDevices(int* out) const;
  int networks(int* out) const;  // device index of the strongest AP per SSID
  void renderIdle();
  void renderAlert();
  void renderList(int top, int bottom);
};
