#include "FieldwatchActivity.h"

#include <Arduino.h>
#include <HalStorage.h>
#include <Logging.h>
#include <Memory.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>

#include "MappedInputManager.h"
#include "components/UITheme.h"
#include "fontIds.h"

namespace {
constexpr const char* DIR = "/biscuit/signalwatch";
constexpr const char* TRUSTED_PATH = "/biscuit/signalwatch/trusted.txt";
constexpr uint32_t RENDER_MS = 2000;
constexpr uint32_t BEACON_FLOOD_REPEAT_MS = 60000;
constexpr const char* TAB_NAMES[] = {"Live", "Alerts", "Drones", "Networks"};

void formatMac(char* out, size_t len, const uint8_t* m) {
  snprintf(out, len, "%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void formatAge(char* out, size_t len, uint32_t ms) {
  const uint32_t s = ms / 1000;
  if (s < 60) {
    snprintf(out, len, "%lus", static_cast<unsigned long>(s));
  } else if (s < 3600) {
    snprintf(out, len, "%lum", static_cast<unsigned long>(s / 60));
  } else {
    snprintf(out, len, "%luh", static_cast<unsigned long>(s / 3600));
  }
}

const char* securityName(uint8_t s) {
  static const char* const names[] = {"open", "WEP", "WPA", "WPA2", "WPA3"};
  return s <= fw::SEC_WPA3 ? names[s] : "?";
}

// Integer formatting: no %f (and its stack use) on the render task.
void formatCoord(char* out, size_t len, int32_t lat, int32_t lon) {
  const auto part = [](int32_t v, char* o, size_t n) {
    const uint32_t a = static_cast<uint32_t>(v < 0 ? -static_cast<int64_t>(v) : v);
    snprintf(o, n, "%s%lu.%05lu", v < 0 ? "-" : "", static_cast<unsigned long>(a / 10000000),
             static_cast<unsigned long>((a % 10000000) / 100));
  };
  char a[16], b[16];
  part(lat, a, sizeof(a));
  part(lon, b, sizeof(b));
  snprintf(out, len, "%s, %s", a, b);
}
}  // namespace

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

void FieldwatchActivity::onEnter() {
  Activity::onEnter();
  running = false;
  allocFailed = false;
  showAlert = false;
  tab = TAB_LIVE;
  selector = 0;
  loadTrusted();
  requestUpdate();
}

void FieldwatchActivity::onExit() {
  Activity::onExit();
  if (running) stop();
}

void FieldwatchActivity::start() {
  // ~13 KB of frame rings, held only while scanning.
  radio = makeUniqueNoThrow<FieldwatchRadio>();
  if (!radio) {
    allocFailed = true;
    requestUpdate();
    return;
  }
  allocFailed = false;
  pairing.reset();
  beaconFlood.reset();
  drones.reset();
  trackers.reset();
  deviceCount = 0;
  alertCount = 0;
  unseenAlerts = 0;
  selector = 0;
  hitsLogged = OnceRing{};
  alertsRaised = OnceRing{};
  logLen = 0;
  popupQuietUntil = 0;
  lastFlush = millis();
  lastSweep = 0;
  lastBeaconFlood = 0;
  floodSeenAt = 0;

  Storage.mkdir(DIR);
  logPath[0] = '\0';
  for (int n = 1; n < 1000; n++) {
    char path[sizeof(logPath)];
    snprintf(path, sizeof(path), "%s/session%03d.csv", DIR, n);
    if (!Storage.exists(path)) {
      memcpy(logPath, path, sizeof(path));
      break;
    }
  }
  if (logPath[0]) {
    HalFile f = Storage.open(logPath, O_WRITE | O_CREAT | O_APPEND);
    if (f) {
      f.println("seconds,kind,detail");
      f.close();
    }
  }

  startedAt = millis();
  lastRender = startedAt;
  radio->start();
  running = true;
  requestUpdate();
}

void FieldwatchActivity::stop() {
  if (radio) radio->stop();
  char summary[96];
  snprintf(summary, sizeof(summary), "%d radios, %d alerts, %d drones", deviceCount, alertCount, drones.count());
  logLine("end", summary);
  flushLog();
  saveTrusted();
  radio.reset();
  running = false;
  showAlert = false;
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------

bool FieldwatchActivity::OnceRing::first(const uint8_t mac[6], uint8_t kind) {
  uint32_t h = 2166136261u;
  for (int i = 0; i < 6; i++) h = (h ^ mac[i]) * 16777619u;
  h = (h ^ kind) * 16777619u;
  for (int i = 0; i < count; i++)
    if (keys[i] == h) return false;
  keys[head] = h;
  head = (head + 1) % CAP;
  if (count < CAP) count++;
  return true;
}

FieldwatchActivity::Device* FieldwatchActivity::find(const uint8_t mac[6], bool wifi) {
  for (int i = 0; i < deviceCount; i++) {
    if (devices[i].wifi == wifi && memcmp(devices[i].mac, mac, 6) == 0) return &devices[i];
  }
  return nullptr;
}

FieldwatchActivity::Device& FieldwatchActivity::upsert(const uint8_t mac[6], bool wifi, uint32_t now) {
  if (Device* d = find(mac, wifi)) return *d;
  int idx = deviceCount;
  if (deviceCount == DEVICE_CAP) {  // replace the radio heard longest ago
    idx = 0;
    for (int i = 1; i < deviceCount; i++)
      if (devices[i].lastSeen < devices[idx].lastSeen) idx = i;
  } else {
    deviceCount++;
  }
  Device& d = devices[idx];
  d = Device{};
  memcpy(d.mac, mac, 6);
  d.wifi = wifi;
  d.fleet = FLEET_UNCHECKED;
  d.firstSeen = now;
  return d;
}

bool FieldwatchActivity::onRemoteId(const uint8_t mac[6], const fw::RemoteId& rid, int8_t rssi, bool wifi,
                                    uint32_t now) {
  const uint8_t ev = drones.observe(mac, rid, rssi, wifi, now);
  if ((ev & fw::DroneTable::NEW_DRONE) && !drones.swarming()) {
    raise("Drone (Remote ID)", rid.uasId[0] ? rid.uasId : (wifi ? "WiFi Remote ID" : "Bluetooth Remote ID"));
  }
  if (ev & fw::DroneTable::EMERGENCY) raise("Drone emergency", rid.selfId[0] ? rid.selfId : rid.uasId);
  if (ev & fw::DroneTable::SWARM) {
    char detail[72];
    snprintf(detail, sizeof(detail), "%d new Remote ID drones in %lus", drones.swarmCount(),
             static_cast<unsigned long>(fw::DroneTable::SWARM_WINDOW_MS / 1000));
    raise("Drone swarm", detail);
  }
  return true;
}

void FieldwatchActivity::onBle(const FwBleFrame& f, uint32_t now) {
  const fw::AdView ad(f.data, f.len);
  if (pairing.consider(f.mac, f.randomAddr, f.rssi, ad, now)) {
    char fams[96], detail[72];
    fw::floodFamilyNames(pairing.families(), fams, sizeof(fams));
    snprintf(detail, sizeof(detail), "%d new pairing radios at %d dBm. %s",
             std::max(pairing.popupCount(), pairing.nameCount()), pairing.medianRssi(),
             fams[0] ? fams : "Named random addresses");
    raise("Bluetooth flood", detail);
  }

  // Drones and trackers are checked even during a flood, so a flood cannot hide them.
  fw::Bytes ridData;
  bool isDrone = false;
  if (ad.serviceData16(0xFFFA, ridData)) {
    fw::RemoteId rid;
    if (fw::parseRemoteIdBle(ridData.data, ridData.len, rid)) isDrone = onRemoteId(f.mac, rid, f.rssi, false, now);
  }
  const int follow = trackers.observe(ad, f.mac, f.rssi, now);
  if (follow >= 0) {
    char detail[72];
    snprintf(detail, sizeof(detail), "%s away from its owner, with you for 30+ min",
             fw::trackerFamilyName(trackers.at(follow).family));
    raise("Tracker with you", detail);
  }

  Device* existing = find(f.mac, false);
  if (!existing && pairing.active() && !isDrone) return;  // keep flood addresses out of the table
  Device& d = existing ? *existing : upsert(f.mac, false, now);
  d.rssi = f.rssi;
  d.lastSeen = now;
  d.alerted = d.alerted || isDrone;  // drones sort to the top of Live
  uint8_t key[8];
  fw::TrackerFamily family;
  d.separated = fw::trackerState(ad, f.mac, key, family) == fw::TRACKER_SEPARATED;
  char name[33];
  ad.name(name, sizeof(name));
  if (name[0] && strcmp(name, d.name) != 0) {
    memcpy(d.name, name, sizeof(name));
    if (d.fleet == FLEET_NONE) d.fleet = FLEET_UNCHECKED;  // a name can match where the address did not
  }

  if (d.fleet != FLEET_UNCHECKED) return;
  const fw::Match m = fw::matchBle(ad, f.mac, f.randomAddr, d.name);
  d.fleet = m.fleet >= 0 ? static_cast<int16_t>(m.fleet) : FLEET_NONE;
  if (m.fleet < 0 || !hitsLogged.first(f.mac, ONCE_BLE_HIT)) return;
  char line[96], mac[18];
  formatMac(mac, sizeof(mac), f.mac);
  snprintf(line, sizeof(line), "BLE %s %s %d", m.name, mac, f.rssi);
  logLine("hit", line);
  if (m.alert && !isDrone && alertsRaised.first(f.mac, ONCE_BLE_HIT)) {
    d.alerted = true;
    raise(m.name, m.className);
  }
}

void FieldwatchActivity::onWifi(const FwWifiFrame& f, uint32_t now) {
  fw::Beacon b;
  if (!fw::parseBeacon(f.data, f.len, b)) return;
  beaconFlood.beacon(b.ssid, f.channel, f.rssi);

  bool isDrone = false;
  if (b.remoteId.len) {
    fw::RemoteId rid;
    if (fw::parseRemoteIdWifi(b.remoteId.data, b.remoteId.len, rid)) isDrone = onRemoteId(b.bssid, rid, f.rssi, true, now);
  }

  const uint8_t reasons = trusted.check(b);
  if (trusted.takeLearned()) trustedDirty = true;
  if (reasons && alertsRaised.first(b.bssid, ONCE_TRUSTED)) {
    char detail[72], mac[18], why[48] = "";
    formatMac(mac, sizeof(mac), b.bssid);
    if (reasons & fw::TrustedNets::OPEN) strcat(why, "open");
    if (reasons & fw::TrustedNets::WEAKER) strcat(why, why[0] ? ", weaker security" : "weaker security");
    if (reasons & fw::TrustedNets::UNKNOWN_VENDOR) strcat(why, why[0] ? ", unknown maker" : "unknown maker");
    snprintf(detail, sizeof(detail), "%s: %s", mac, why);
    char title[40];
    snprintf(title, sizeof(title), "Trusted: %.28s", b.ssid);
    raise(title, detail);
  }

  Device* existing = find(b.bssid, true);
  // During a beacon flood, new fake access points stay out of the table.
  const bool flooding = floodSeenAt != 0 && now - floodSeenAt < BEACON_FLOOD_REPEAT_MS;
  if (!existing && flooding && !isDrone && !reasons) return;
  Device& d = existing ? *existing : upsert(b.bssid, true, now);
  d.rssi = f.rssi;
  d.channel = f.channel;
  d.lastSeen = now;
  d.security = b.security;
  d.enterprise = b.enterprise;
  d.personal = b.personal;
  d.alerted = d.alerted || isDrone || reasons;
  memcpy(d.name, b.ssid, sizeof(b.ssid));

  if (d.fleet != FLEET_UNCHECKED) return;
  const fw::Match m = fw::matchWifi(f.data, f.len, b);
  d.fleet = m.fleet >= 0 ? static_cast<int16_t>(m.fleet) : FLEET_NONE;
  if (m.fleet < 0 || !hitsLogged.first(b.bssid, ONCE_WIFI_HIT)) return;
  char line[96], mac[18];
  formatMac(mac, sizeof(mac), b.bssid);
  snprintf(line, sizeof(line), "WiFi %s %s '%s' %d", m.name, mac, b.ssid, f.rssi);
  logLine("hit", line);
  if (m.alert && !isDrone && alertsRaised.first(b.bssid, ONCE_WIFI_HIT)) {
    d.alerted = true;
    raise(m.name, b.ssid[0] ? b.ssid : m.className);
  }
}

void FieldwatchActivity::drain() {
  const uint32_t now = millis();
  FwBleFrame ble;
  for (int i = 0; i < FieldwatchRadio::BLE_RING && radio->popBle(ble); i++) onBle(ble, now);
  FwWifiFrame& wifi = radio->scratch;  // 520 bytes: lives in the radio, off the stack
  for (int i = 0; i < FieldwatchRadio::WIFI_RING && radio->popWifi(wifi); i++) {
    if (wifi.sweep != lastSweep) {  // a sweep finished: judge it
      const bool flood = beaconFlood.endSweep();
      if (flood) floodSeenAt = now ? now : 1;  // keeps fake APs out while the flood lasts
      if (flood && (lastBeaconFlood == 0 || now - lastBeaconFlood > BEACON_FLOOD_REPEAT_MS)) {
        lastBeaconFlood = now ? now : 1;
        char detail[72];
        snprintf(detail, sizeof(detail), "%d new network names on channel %u at %d dBm", beaconFlood.lastCount(),
                 beaconFlood.lastChannel(), beaconFlood.lastMedian());
        raise("WiFi beacon flood", detail);
      }
      beaconFlood.beginSweep();
      lastSweep = wifi.sweep;
    }
    onWifi(wifi, now);
  }
  pairing.tick(now);
  trackers.tick(now);
}

// ---------------------------------------------------------------------------
// Alerts, log, trusted list
// ---------------------------------------------------------------------------

void FieldwatchActivity::raise(const char* title, const char* detail) {
  if (alertCount < ALERT_CAP) alertCount++;
  memmove(&alerts[1], &alerts[0], sizeof(Alert) * (alertCount - 1));
  Alert& a = alerts[0];
  const uint32_t now = millis();
  a.at = now - startedAt;
  snprintf(a.title, sizeof(a.title), "%s", title);
  snprintf(a.detail, sizeof(a.detail), "%s", detail ? detail : "");
  unseenAlerts++;
  // After a dismissal, further alerts only go to the Alerts tab for a while,
  // so a stream of alerts cannot keep the pop-up open.
  if (now >= popupQuietUntil) showAlert = true;
  char line[120];
  snprintf(line, sizeof(line), "%s: %s", a.title, a.detail);
  logLine("alert", line);
  LOG_INF("FW", "ALERT %s", line);
  requestUpdate();
}

void FieldwatchActivity::logLine(const char* kind, const char* text) {
  if (!logPath[0]) return;
  char detail[128];
  size_t w = 0;
  for (const char* c = text; *c && w + 1 < sizeof(detail); c++) detail[w++] = (*c == '"') ? '\'' : *c;
  detail[w] = '\0';
  const size_t room = sizeof(logBuf) - logLen;
  const int n = snprintf(logBuf + logLen, room, "%lu,%s,\"%s\"\n",
                         static_cast<unsigned long>((millis() - startedAt) / 1000), kind, detail);
  if (n > 0 && static_cast<size_t>(n) < room) {
    logLen += static_cast<size_t>(n);
  } else {
    logBuf[logLen] = '\0';  // full: this line is dropped; the next flush makes room
  }
}

void FieldwatchActivity::flushLog() {
  if (logLen == 0 || !logPath[0]) return;
  HalFile f = Storage.open(logPath, O_WRITE | O_CREAT | O_APPEND);
  if (f) {
    f.write(reinterpret_cast<const uint8_t*>(logBuf), logLen);
    f.close();
  }
  logLen = 0;
  lastFlush = millis();
}

void FieldwatchActivity::loadTrusted() {
  auto text = makeUniqueNoThrow<char[]>(fw::TrustedNets::SERIAL_MAX);
  if (!text) return;
  const size_t n = Storage.readFileToBuffer(TRUSTED_PATH, text.get(), fw::TrustedNets::SERIAL_MAX);
  text[std::min(n, fw::TrustedNets::SERIAL_MAX - 1)] = '\0';
  trusted.deserialize(n ? text.get() : "");
}

void FieldwatchActivity::saveTrusted() {
  auto text = makeUniqueNoThrow<char[]>(fw::TrustedNets::SERIAL_MAX);
  if (!text) return;
  const size_t n = trusted.serialize(text.get(), fw::TrustedNets::SERIAL_MAX);
  if (n == 0 && trusted.count() > 0) return;  // never replace the file with a partial list
  Storage.mkdir(DIR);
  if (Storage.writeFile(TRUSTED_PATH, String(text.get()))) trustedDirty = false;
}

void FieldwatchActivity::toggleTrust(const char* ssid) {
  if (!ssid[0]) return;
  if (trusted.isTrusted(ssid)) {
    trusted.untrust(ssid);
  } else if (trusted.trust(ssid)) {
    // The strongest AP heard right now on this name is the baseline.
    const Device* best = nullptr;
    for (int i = 0; i < deviceCount; i++) {
      const Device& d = devices[i];
      if (d.wifi && strcmp(d.name, ssid) == 0 && (!best || d.rssi > best->rssi)) best = &d;
    }
    if (best) {
      fw::Beacon b;
      memcpy(b.bssid, best->mac, 6);
      memcpy(b.ssid, best->name, sizeof(b.ssid));
      b.security = best->security;
      b.enterprise = best->enterprise;
      b.personal = best->personal;
      trusted.check(b);
      trusted.takeLearned();
    }
  }
  saveTrusted();
}

// ---------------------------------------------------------------------------
// Loop
// ---------------------------------------------------------------------------

void FieldwatchActivity::loop() {
  using Button = MappedInputManager::Button;
  if (!running) {
    if (mappedInput.wasReleased(Button::Confirm)) start();
    if (mappedInput.wasReleased(Button::Back)) finish();
    return;
  }

  radio->loop();  // channel hopping stays on time: outside the render lock
  wifiPhase = radio->phase() == FieldwatchRadio::Phase::Wifi;
  channel = radio->channel();
  const uint32_t now = millis();

  if (mappedInput.wasReleased(Button::Back)) {
    // stop() frees the radio; render never touches it, and Back always stops,
    // even with an alert open.
    {
      RenderLock lock(*this);
      stop();
    }
    requestUpdate();
    return;
  }

  {
    // The render task reads the tables. Skip draining while it draws; the rings buffer frames.
    RenderLock lock(RenderLock::Mode::Try);
    if (lock.ownsLock()) drain();
  }
  // A button edge lasts one update, so input waits for the lock instead of being dropped.
  const bool buttonActivity = mappedInput.wasReleased(Button::Confirm) || mappedInput.wasReleased(Button::Left) ||
                              mappedInput.wasReleased(Button::Right) || mappedInput.isPressed(Button::Up) ||
                              mappedInput.isPressed(Button::Down) || mappedInput.wasReleased(Button::Up) ||
                              mappedInput.wasReleased(Button::Down);
  if (buttonActivity) {
    RenderLock lock(*this);
    if (showAlert) {
      if (mappedInput.wasReleased(Button::Confirm)) {
        showAlert = false;
        popupQuietUntil = now + POPUP_QUIET_MS;
        requestUpdate();
      }
    } else {
      handleInput();
    }
  }
  if (trustedDirty && now - lastTrustedSave >= LOG_FLUSH_MS) {  // retries a failed save at most every 5 s
    lastTrustedSave = now;
    saveTrusted();
  }
  if (logLen > sizeof(logBuf) / 2 || (logLen && now - lastFlush >= LOG_FLUSH_MS)) flushLog();

  if (now - lastRender >= RENDER_MS) {
    lastRender = now;
    requestUpdate();
  }
}

void FieldwatchActivity::handleInput() {
  using Button = MappedInputManager::Button;
  if (mappedInput.wasReleased(Button::Right) || mappedInput.wasReleased(Button::Left)) {
    const int step = mappedInput.wasReleased(Button::Right) ? 1 : TAB_COUNT - 1;
    tab = static_cast<Tab>((tab + step) % TAB_COUNT);
    selector = 0;
    if (tab == TAB_ALERTS) unseenAlerts = 0;
    requestUpdate();
  }
  buttonNavigator.onPressAndContinuous({Button::Down}, [&] {
    const int size = listSize();
    if (size > 0) selector = (selector + 1) % size;
    requestUpdate();
  });
  buttonNavigator.onPressAndContinuous({Button::Up}, [&] {
    const int size = listSize();
    if (size > 0) selector = (selector + size - 1) % size;
    requestUpdate();
  });
  if (tab == TAB_NETS && mappedInput.wasReleased(Button::Confirm)) {
    toggleTrust(selectedSsid);  // the row drawn as selected, not a re-sorted position
    requestUpdate();
  }
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

int FieldwatchActivity::sortedDevices(int* out) const {
  for (int i = 0; i < deviceCount; i++) out[i] = i;
  // Alerting signatures first, then any signature, then by loudness.
  std::sort(out, out + deviceCount, [this](int a, int b) {
    const Device& x = devices[a];
    const Device& y = devices[b];
    const int rx = (x.alerted ? 2 : 0) + (x.fleet >= 0 || x.separated ? 1 : 0);
    const int ry = (y.alerted ? 2 : 0) + (y.fleet >= 0 || y.separated ? 1 : 0);
    if (rx != ry) return rx > ry;
    return x.rssi > y.rssi;
  });
  return deviceCount;
}

int FieldwatchActivity::networks(int* out) const {
  int n = 0;
  for (int i = 0; i < deviceCount; i++) {
    const Device& d = devices[i];
    if (!d.wifi || !d.name[0]) continue;
    int same = -1;
    for (int k = 0; k < n; k++)
      if (strcmp(devices[out[k]].name, d.name) == 0) same = k;
    if (same < 0) {
      out[n++] = i;
    } else if (d.rssi > devices[out[same]].rssi) {
      out[same] = i;
    }
  }
  std::sort(out, out + n, [this](int a, int b) { return strcmp(devices[a].name, devices[b].name) < 0; });
  return n;
}

int FieldwatchActivity::listSize() const {
  int tmp[DEVICE_CAP];
  switch (tab) {
    case TAB_LIVE: return deviceCount;
    case TAB_ALERTS: return alertCount;
    case TAB_DRONES: return drones.count();
    case TAB_NETS: return networks(tmp);
    default: return 0;
  }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

void FieldwatchActivity::render(RenderLock&&) {
  renderer.clearScreen();
  if (!running) {
    renderIdle();
  } else if (showAlert && alertCount > 0) {
    renderAlert();
  } else {
    const auto& metrics = UITheme::getInstance().getMetrics();
    const int pageWidth = renderer.getScreenWidth();
    const int pageHeight = renderer.getScreenHeight();
    char status[32];
    if (wifiPhase) {
      snprintf(status, sizeof(status), "WiFi ch %u", channel);
    } else {
      snprintf(status, sizeof(status), "Bluetooth");
    }
    GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Signal Watch", status);
    int y = metrics.topPadding + metrics.headerHeight;
    char alertTab[16];
    snprintf(alertTab, sizeof(alertTab), unseenAlerts ? "Alerts %d" : "Alerts", unseenAlerts);
    const std::vector<TabInfo> tabs = {{TAB_NAMES[0], tab == TAB_LIVE},
                                       {alertTab, tab == TAB_ALERTS},
                                       {TAB_NAMES[2], tab == TAB_DRONES},
                                       {TAB_NAMES[3], tab == TAB_NETS}};
    GUI.drawTabBar(renderer, Rect{0, y, pageWidth, metrics.tabBarHeight}, tabs, true);
    y += metrics.tabBarHeight;
    renderList(y, pageHeight - metrics.buttonHintsHeight);
    const char* confirm = "";
    selectedSsid[0] = '\0';
    if (tab == TAB_NETS) {
      int nets[DEVICE_CAP];
      const int n = networks(nets);
      if (n > 0) {
        memcpy(selectedSsid, devices[nets[std::min(selector, n - 1)]].name, sizeof(selectedSsid));
        confirm = trusted.isTrusted(selectedSsid) ? "Untrust" : "Trust";
      }
    }
    const auto labels = mappedInput.mapLabels("Stop", confirm, "< Tab", "Tab >");
    GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
    GUI.drawSideButtonHints(renderer, "Up", "Down");
  }
  renderer.displayBuffer();
}

void FieldwatchActivity::renderIdle() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int pageWidth = renderer.getScreenWidth();
  const int pageHeight = renderer.getScreenHeight();
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Signal Watch");
  const int mid = (metrics.topPadding + metrics.headerHeight + pageHeight - metrics.buttonHintsHeight) / 2;
  char line[96];
  renderer.drawCenteredText(UI_10_FONT_ID, mid - 90, "Receive-only WiFi and Bluetooth observer.", true,
                            EpdFontFamily::BOLD);
  snprintf(line, sizeof(line), "%d signatures. Floods, drones, trackers,", fw::catalogSize());
  renderer.drawCenteredText(UI_10_FONT_ID, mid - 60, line);
  renderer.drawCenteredText(UI_10_FONT_ID, mid - 36, "evil twins of trusted networks.");
  renderer.drawCenteredText(SMALL_FONT_ID, mid - 4, "Pattern matches are hints, not identity.");
  renderer.drawCenteredText(SMALL_FONT_ID, mid + 18, "Based on Fieldwatch by Off Grid Pete (MIT).");
  if (allocFailed) {
    renderer.drawCenteredText(UI_10_FONT_ID, mid + 56, "Not enough memory to start.", true, EpdFontFamily::BOLD);
  } else if (logPath[0]) {
    snprintf(line, sizeof(line), "%d radios, %d alerts. Log: %s", deviceCount, alertCount, logPath);
    renderer.drawCenteredText(SMALL_FONT_ID, mid + 56,
                              renderer.truncatedText(SMALL_FONT_ID, line, pageWidth - 2 * metrics.contentSidePadding).c_str());
  } else {
    snprintf(line, sizeof(line), "%d trusted networks", trusted.count());
    renderer.drawCenteredText(SMALL_FONT_ID, mid + 56, line);
  }
  const auto labels = mappedInput.mapLabels("Back", "Start", "", "");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
}

void FieldwatchActivity::renderAlert() {
  const auto& metrics = UITheme::getInstance().getMetrics();
  const int pageWidth = renderer.getScreenWidth();
  const int pageHeight = renderer.getScreenHeight();
  const Alert& a = alerts[0];
  GUI.drawHeader(renderer, Rect{0, metrics.topPadding, pageWidth, metrics.headerHeight}, "Signal Watch", "Alert");
  const int mid = pageHeight / 2;
  renderer.fillRect(0, mid - 80, pageWidth, 56, true);
  renderer.drawCenteredText(UI_12_FONT_ID, mid - 66, a.title, false, EpdFontFamily::BOLD);
  renderer.drawCenteredText(UI_10_FONT_ID, mid,
                            renderer.truncatedText(UI_10_FONT_ID, a.detail, pageWidth - 2 * metrics.contentSidePadding).c_str());
  char when[32], age[12];
  formatAge(age, sizeof(age), a.at);
  snprintf(when, sizeof(when), "At %s into the session", age);
  renderer.drawCenteredText(SMALL_FONT_ID, mid + 30, when);
  renderer.drawCenteredText(SMALL_FONT_ID, mid + 56, "A pattern match. Look with your eyes.");
  const auto labels = mappedInput.mapLabels("Stop", "OK", "", "");
  GUI.drawButtonHints(renderer, labels.btn1, labels.btn2, labels.btn3, labels.btn4);
}

void FieldwatchActivity::renderList(int top, int bottom) {
  const int pageWidth = renderer.getScreenWidth();
  const Rect rect{0, top, pageWidth, bottom - top};
  const uint32_t now = millis();
  int order[DEVICE_CAP];

  switch (tab) {
    case TAB_LIVE: {
      const int n = sortedDevices(order);
      if (n == 0) {
        renderer.drawCenteredText(UI_10_FONT_ID, top + 60, "Listening...");
        return;
      }
      GUI.drawList(
          renderer, rect, n, std::min(selector, n - 1),
          [&](int i) -> std::string {
            const Device& d = devices[order[i]];
            char line[64], mac[18];
            formatMac(mac, sizeof(mac), d.mac);
            snprintf(line, sizeof(line), "%s%s", d.alerted ? "! " : "", d.name[0] ? d.name : mac);
            return line;
          },
          [&](int i) -> std::string {
            const Device& d = devices[order[i]];
            char line[96], age[12];
            formatAge(age, sizeof(age), now - d.lastSeen);
            if (d.wifi) {
              snprintf(line, sizeof(line), "WiFi ch%u %s %ddBm %s", d.channel, securityName(d.security), d.rssi, age);
            } else {
              snprintf(line, sizeof(line), "BLE %ddBm %s%s", d.rssi, age, d.separated ? " separated tag" : "");
            }
            return line;
          },
          nullptr,
          [&](int i) -> std::string {
            const Device& d = devices[order[i]];
            return d.fleet >= 0 ? fw::catalogName(d.fleet) : "";
          });
      break;
    }
    case TAB_ALERTS: {
      if (alertCount == 0) {
        renderer.drawCenteredText(UI_10_FONT_ID, top + 60, "No alerts.");
        return;
      }
      GUI.drawList(
          renderer, rect, alertCount, std::min(selector, alertCount - 1),
          [&](int i) -> std::string { return alerts[i].title; },
          [&](int i) -> std::string {
            char line[96], age[12];
            formatAge(age, sizeof(age), alerts[i].at);
            snprintf(line, sizeof(line), "%s - %s", age, alerts[i].detail);
            return line;
          });
      break;
    }
    case TAB_DRONES: {
      const int n = drones.count();
      if (n == 0) {
        renderer.drawCenteredText(UI_10_FONT_ID, top + 60, "No Remote ID drones heard.");
        return;
      }
      GUI.drawList(
          renderer, rect, n, std::min(selector, n - 1),
          [&](int i) -> std::string {
            const fw::Drone& d = drones.at(i);
            char line[64];
            snprintf(line, sizeof(line), "%s%s", d.rid.emergency() ? "EMERGENCY " : "",
                     d.rid.uasId[0] ? d.rid.uasId : "(no ID yet)");
            return line;
          },
          [&](int i) -> std::string {
            const fw::Drone& d = drones.at(i);
            char line[128], pos[40] = "no position";
            if (d.rid.hasLocation) formatCoord(pos, sizeof(pos), d.rid.lat, d.rid.lon);
            if (d.rid.hasLocation && d.rid.hasOperator) {
              snprintf(line, sizeof(line), "%s %dm %u.%um/s, pilot %lum away", pos, d.rid.altM, d.rid.speedCm / 100,
                       (d.rid.speedCm % 100) / 10, static_cast<unsigned long>(fw::distanceM(d.rid.lat, d.rid.lon, d.rid.opLat, d.rid.opLon)));
            } else {
              snprintf(line, sizeof(line), "%s %s %ddBm", pos, d.wifi ? "WiFi" : "BLE", d.rssi);
            }
            return line;
          });
      break;
    }
    case TAB_NETS: {
      const int n = networks(order);
      if (n == 0) {
        renderer.drawCenteredText(UI_10_FONT_ID, top + 60, "No named WiFi networks heard yet.");
        return;
      }
      GUI.drawList(
          renderer, rect, n, std::min(selector, n - 1),
          [&](int i) -> std::string {
            const Device& d = devices[order[i]];
            char line[48];
            snprintf(line, sizeof(line), "%s%s", trusted.isTrusted(d.name) ? "[trusted] " : "", d.name);
            return line;
          },
          [&](int i) -> std::string {
            const Device& d = devices[order[i]];
            char line[64], mac[18];
            formatMac(mac, sizeof(mac), d.mac);
            snprintf(line, sizeof(line), "%s %s ch%u %ddBm", mac, securityName(d.security), d.channel, d.rssi);
            return line;
          });
      break;
    }
    default:
      break;
  }
}
