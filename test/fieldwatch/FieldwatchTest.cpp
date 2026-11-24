#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "Fieldwatch.h"

using Buf = std::vector<uint8_t>;

namespace {

Buf hex(const std::string& h) {
  Buf out;
  for (size_t i = 0; i + 1 < h.size(); i += 2) out.push_back(static_cast<uint8_t>(std::stoi(h.substr(i, 2), nullptr, 16)));
  return out;
}

void ad(Buf& p, uint8_t type, const Buf& data) {
  p.push_back(static_cast<uint8_t>(data.size() + 1));
  p.push_back(type);
  p.insert(p.end(), data.begin(), data.end());
}

Buf mfg(uint16_t company, const Buf& data) {
  Buf b{static_cast<uint8_t>(company & 0xFF), static_cast<uint8_t>(company >> 8)};
  b.insert(b.end(), data.begin(), data.end());
  return b;
}

Buf svc(uint16_t uuid, const Buf& data) { return mfg(uuid, data); }

struct Mac {
  uint8_t b[6];
};
Mac mac(uint8_t last, uint8_t first = 0xC2) { return Mac{{first, 0x11, 0x22, 0x33, 0x44, last}}; }

// 802.11 beacon: header, fixed params, then IEs.
Buf beacon(const std::string& ssid, const uint8_t bssid[6], bool privacy, const Buf& extraIes = {}) {
  Buf f(24 + 12, 0);
  f[0] = 0x80;
  memcpy(&f[10], bssid, 6);
  memcpy(&f[16], bssid, 6);
  f[24 + 10] = privacy ? 0x11 : 0x01;
  f.push_back(0);
  f.push_back(static_cast<uint8_t>(ssid.size()));
  f.insert(f.end(), ssid.begin(), ssid.end());
  f.insert(f.end(), extraIes.begin(), extraIes.end());
  return f;
}

Buf rsnIe(const std::vector<uint8_t>& akms) {
  Buf d{0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, static_cast<uint8_t>(akms.size()), 0x00};
  for (uint8_t a : akms) {
    d.insert(d.end(), {0x00, 0x0F, 0xAC, a});
  }
  Buf ie{48, static_cast<uint8_t>(d.size())};
  ie.insert(ie.end(), d.begin(), d.end());
  return ie;
}

// Real DJI pack (FA:0B:BC type 0x0D payload) from Fieldwatch's OpenDroneIdTest.
const char* kDjiPack =
    "D9F2190302123135383146335954444A3144303033315A353330000000"
    "1220820A00864228110CFF80CF0000F508B2083A022E310A00"
    "420176E42711B5FF81CF010000000000000005088B02900E00";

Buf locationMsg(uint8_t status, int32_t lat, int32_t lon) {
  Buf m(25, 0);
  m[0] = 0x12;
  m[1] = static_cast<uint8_t>(status << 4);
  m[3] = 40;  // 10 m/s
  memcpy(&m[5], &lat, 4);
  memcpy(&m[9], &lon, 4);
  return m;
}

Buf basicIdMsg(const std::string& id) {
  Buf m(25, 0);
  m[0] = 0x02;
  m[1] = 0x12;
  memcpy(&m[2], id.data(), std::min<size_t>(id.size(), 20));
  return m;
}

Buf bleRid(const Buf& msg) {
  Buf d{0x0D, 0x01};
  d.insert(d.end(), msg.begin(), msg.end());
  return d;
}

}  // namespace

// ---------------------------------------------------------------------------

TEST(FieldwatchRemoteId, DjiWifiPack) {
  Buf b = hex(kDjiPack);
  fw::RemoteId r;
  ASSERT_TRUE(fw::parseRemoteIdWifi(b.data(), b.size(), r));
  EXPECT_STREQ("1581F3YTDJ1D0031Z530", r.uasId);
  EXPECT_EQ(287851142, r.lat);
  EXPECT_EQ(-813629684, r.lon);
  EXPECT_EQ(250, r.speedCm);
  ASSERT_TRUE(r.hasOperator);
  EXPECT_EQ(287827062, r.opLat);
  EXPECT_EQ(-813563979, r.opLon);
}

TEST(FieldwatchRemoteId, TruncatedInputIsSafe) {
  Buf b = hex(kDjiPack);
  for (size_t n = 0; n <= b.size(); n++) {
    fw::RemoteId r;
    fw::parseRemoteIdWifi(b.data(), n, r);
    fw::parseRemoteIdBle(b.data(), n, r);
  }
  Buf garbage(200, 0xFF);  // pack header claiming 255 messages
  fw::RemoteId r;
  fw::parseRemoteIdBle(garbage.data(), garbage.size(), r);
  SUCCEED();
}

TEST(FieldwatchRemoteId, BleLocationAndEmergency) {
  Buf d = bleRid(locationMsg(3, 400000000, -740000000));
  fw::RemoteId r;
  ASSERT_TRUE(fw::parseRemoteIdBle(d.data(), d.size(), r));
  EXPECT_EQ(400000000, r.lat);
  EXPECT_EQ(1000, r.speedCm);
  EXPECT_TRUE(r.emergency());
}

TEST(FieldwatchRemoteId, Distance) {
  EXPECT_NEAR(1112, static_cast<int>(fw::distanceM(400000000, -740000000, 400100000, -740000000)), 2);
}

TEST(FieldwatchDrones, SwarmFiresOnceAndRearmsAfterQuiet) {
  fw::DroneTable t;
  uint32_t now = 1000;
  int swarms = 0;
  for (int i = 0; i < 7; i++) {
    Buf d = bleRid(basicIdMsg("ID" + std::to_string(i)));
    fw::RemoteId r;
    fw::parseRemoteIdBle(d.data(), d.size(), r);
    Mac m = mac(static_cast<uint8_t>(i));
    swarms += (t.observe(m.b, r, -60, false, now += 2000) & fw::DroneTable::SWARM) != 0;
  }
  EXPECT_EQ(1, swarms);
  now += fw::DroneTable::SWARM_QUIET_MS + 1;
  for (int i = 10; i < 15; i++) {
    Buf d = bleRid(basicIdMsg("ID" + std::to_string(i)));
    fw::RemoteId r;
    fw::parseRemoteIdBle(d.data(), d.size(), r);
    Mac m = mac(static_cast<uint8_t>(i));
    swarms += (t.observe(m.b, r, -60, false, now += 1000) & fw::DroneTable::SWARM) != 0;
  }
  EXPECT_EQ(2, swarms);
}

TEST(FieldwatchDrones, SameIdOnTwoRadiosIsOneDrone) {
  fw::DroneTable t;
  fw::RemoteId r;
  strcpy(r.uasId, "ABC");
  Mac a = mac(1), b = mac(2);
  t.observe(a.b, r, -50, false, 10);
  t.observe(b.b, r, -50, true, 20);
  EXPECT_EQ(1, t.count());
}

TEST(FieldwatchDrones, EmergencyRisingEdgeOnly) {
  fw::DroneTable t;
  Mac m = mac(1);
  fw::RemoteId e;
  e.hasLocation = true;
  e.status = 3;
  EXPECT_TRUE(t.observe(m.b, e, -50, false, 10) & fw::DroneTable::EMERGENCY);
  EXPECT_FALSE(t.observe(m.b, e, -50, false, 20) & fw::DroneTable::EMERGENCY);
  fw::RemoteId ok;
  ok.hasLocation = true;
  t.observe(m.b, ok, -50, false, 30);
  EXPECT_TRUE(t.observe(m.b, e, -50, false, 40) & fw::DroneTable::EMERGENCY);
}

// ---------------------------------------------------------------------------

TEST(FieldwatchFlood, AppleProximityBurstStartsOneEpisode) {
  fw::PairingFlood f;
  Buf p;
  ad(p, 0xFF, mfg(0x004C, hex("07050120020F00")));
  fw::AdView v(p.data(), p.size());
  int starts = 0;
  for (int i = 0; i < 20; i++) {
    Mac m = mac(static_cast<uint8_t>(i));
    starts += f.consider(m.b, true, static_cast<int8_t>(-60 - (i % 5)), v, 1000 + i * 100);
  }
  EXPECT_EQ(1, starts);
  EXPECT_TRUE(f.active());
  EXPECT_EQ(fw::FAM_APPLE_PROX, f.families());
  f.tick(1000 + 20 * 100 + fw::PairingFlood::WINDOW_MS + 1);
  EXPECT_FALSE(f.active());
}

TEST(FieldwatchFlood, NineIsQuietAndRepeatsDoNotCount) {
  fw::PairingFlood f;
  Buf p;
  ad(p, 0xFF, mfg(0x004C, hex("07050120020F00")));
  fw::AdView v(p.data(), p.size());
  for (int i = 0; i < 9; i++) {
    Mac m = mac(static_cast<uint8_t>(i));
    EXPECT_FALSE(f.consider(m.b, true, -60, v, 1000 + i));
  }
  Mac again = mac(0);
  for (int i = 0; i < 5; i++) EXPECT_FALSE(f.consider(again.b, true, -60, v, 2000 + i));
  EXPECT_FALSE(f.active());
}

TEST(FieldwatchFlood, SpreadLoudnessIsACrowd) {
  fw::PairingFlood f;
  Buf p;
  ad(p, 0xFF, mfg(0x004C, hex("07050120020F00")));
  fw::AdView v(p.data(), p.size());
  for (int i = 0; i < 12; i++) {
    Mac m = mac(static_cast<uint8_t>(i));
    f.consider(m.b, true, static_cast<int8_t>(-40 - i * 5), v, 1000 + i);
  }
  EXPECT_FALSE(f.active());
}

TEST(FieldwatchFlood, FindMyIsNotAPopup) {
  Buf p;
  ad(p, 0xFF, mfg(0x004C, hex("1202000007020000")));  // Find My, then a 0x07 inside it
  fw::AdView v(p.data(), p.size());
  EXPECT_EQ(0, fw::floodFamilies(v));
}

TEST(FieldwatchFlood, FamiliesAndNames) {
  Buf swift, fast, love;
  ad(swift, 0xFF, mfg(0x0006, hex("030080")));
  ad(fast, 0x16, svc(0xFE2C, hex("CD8256")));
  ad(love, 0xFF, mfg(0x00FF, hex("6DB643CE97FE427C01")));
  EXPECT_EQ(fw::FAM_SWIFT_PAIR, fw::floodFamilies(fw::AdView(swift.data(), swift.size())));
  EXPECT_EQ(fw::FAM_FAST_PAIR, fw::floodFamilies(fw::AdView(fast.data(), fast.size())));
  EXPECT_EQ(fw::FAM_LOVESPOUSE, fw::floodFamilies(fw::AdView(love.data(), love.size())));
  char names[96];
  fw::floodFamilyNames(fw::FAM_FAST_PAIR | fw::FAM_SWIFT_PAIR, names, sizeof(names));
  EXPECT_STREQ("Fast Pair, Swift Pair", names);
}

TEST(FieldwatchFlood, RandomNamedBurst) {
  fw::PairingFlood f;
  Buf p;
  ad(p, 0x09, Buf{'x', 'y'});
  fw::AdView v(p.data(), p.size());
  Mac pub = mac(1, 0x00);
  EXPECT_FALSE(f.consider(pub.b, false, -60, v, 1));  // stable address stays out
  bool started = false;
  for (int i = 0; i < 15; i++) {
    Mac m = mac(static_cast<uint8_t>(i));
    started = f.consider(m.b, true, -60, v, 10 + i) || started;
  }
  EXPECT_TRUE(started);
}

TEST(FieldwatchFlood, MalformedAdvertIsSafe) {
  Buf p{0x1F, 0xFF, 0x4C, 0x00, 0x07};  // length runs past the end
  fw::AdView v(p.data(), p.size());
  EXPECT_EQ(0, fw::floodFamilies(v));
  char name[8];
  v.name(name, sizeof(name));
  EXPECT_STREQ("", name);
}

// ---------------------------------------------------------------------------

TEST(FieldwatchBeaconFlood, FirstSweepLearnsSecondDetects) {
  fw::BeaconFlood f;
  f.beginSweep();
  for (int i = 0; i < 30; i++) f.beacon(("home" + std::to_string(i)).c_str(), 6, -60);
  EXPECT_FALSE(f.endSweep());
  f.beginSweep();
  for (int i = 0; i < 15; i++) f.beacon(("FREE WIFI " + std::to_string(i)).c_str(), 11, static_cast<int8_t>(-50 - i % 3));
  EXPECT_TRUE(f.endSweep());
  EXPECT_EQ(11, f.lastChannel());
}

TEST(FieldwatchBeaconFlood, FourteenOrSpreadChannelsIsQuiet) {
  fw::BeaconFlood f;
  f.beginSweep();
  f.endSweep();
  f.beginSweep();
  for (int i = 0; i < 14; i++) f.beacon(("a" + std::to_string(i)).c_str(), 1, -50);
  EXPECT_FALSE(f.endSweep());
  f.beginSweep();
  for (int i = 0; i < 30; i++) f.beacon(("b" + std::to_string(i)).c_str(), static_cast<uint8_t>(1 + i % 3), -50);
  EXPECT_FALSE(f.endSweep());
}

// ---------------------------------------------------------------------------

TEST(FieldwatchBeacon, SecurityRanks) {
  const uint8_t bssid[6] = {0x00, 0x14, 0x6C, 1, 2, 3};
  struct Case {
    Buf frame;
    uint8_t rank;
  } cases[] = {
      {beacon("open", bssid, false), fw::SEC_OPEN},
      {beacon("wep", bssid, true), fw::SEC_WEP},
      {beacon("wpa2", bssid, true, rsnIe({2})), fw::SEC_WPA2},
      {beacon("wpa3", bssid, true, rsnIe({8})), fw::SEC_WPA3},
      {beacon("mixed", bssid, true, rsnIe({2, 8})), fw::SEC_WPA2},
  };
  for (auto& c : cases) {
    fw::Beacon b;
    ASSERT_TRUE(fw::parseBeacon(c.frame.data(), c.frame.size(), b));
    EXPECT_EQ(c.rank, b.security) << b.ssid;
  }
  fw::Beacon b;
  Buf ent = beacon("corp", bssid, true, rsnIe({1}));
  fw::parseBeacon(ent.data(), ent.size(), b);
  EXPECT_TRUE(b.enterprise);
  EXPECT_FALSE(b.personal);
  EXPECT_STREQ("corp", b.ssid);
}

TEST(FieldwatchBeacon, TruncatedFrameIsSafe) {
  const uint8_t bssid[6] = {1, 2, 3, 4, 5, 6};
  Buf f = beacon("abc", bssid, true, rsnIe({2, 8}));
  for (size_t n = 0; n <= f.size(); n++) {
    fw::Beacon b;
    fw::parseBeacon(f.data(), n, b);
  }
  SUCCEED();
}

// ---------------------------------------------------------------------------

TEST(FieldwatchTrusted, LearnsThenWarns) {
  fw::TrustedNets t;
  ASSERT_TRUE(t.trust("Home"));
  const uint8_t ap1[6] = {0x00, 0x14, 0x6C, 1, 1, 1};
  const uint8_t ap2[6] = {0x00, 0x14, 0x6C, 1, 1, 2};
  const uint8_t twin[6] = {0x00, 0x13, 0x37, 9, 9, 9};
  const uint8_t randomTwin[6] = {0x02, 0x13, 0x37, 9, 9, 9};
  fw::Beacon b;
  Buf f = beacon("Home", ap1, true, rsnIe({2}));
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_EQ(fw::TrustedNets::OK, t.check(b));  // baseline
  f = beacon("Home", ap2, true, rsnIe({2}));
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_EQ(fw::TrustedNets::OK, t.check(b));  // same maker, same security: mesh
  f = beacon("Home", twin, true, rsnIe({2}));
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_EQ(fw::TrustedNets::UNKNOWN_VENDOR, t.check(b));
  f = beacon("Home", randomTwin, false);
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_EQ(fw::TrustedNets::OPEN, t.check(b));
  f = beacon("Other", twin, false);
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_EQ(fw::TrustedNets::OK, t.check(b));
}

TEST(FieldwatchTrusted, WpaUnderWpa2IsWeaker) {
  fw::TrustedNets t;
  t.trust("Net");
  const uint8_t ap[6] = {0x00, 0x14, 0x6C, 1, 1, 1};
  const uint8_t ap2[6] = {0x00, 0x14, 0x6C, 1, 1, 2};
  fw::Beacon b;
  Buf f = beacon("Net", ap, true, rsnIe({2}));
  fw::parseBeacon(f.data(), f.size(), b);
  t.check(b);
  Buf wpa{221, 22, 0x00, 0x50, 0xF2, 0x01, 0x01, 0x00, 0x00, 0x50, 0xF2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xF2, 0x02,
          0x01, 0x00, 0x00, 0x50, 0xF2, 0x02};
  f = beacon("Net", ap2, true, wpa);
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_EQ(fw::SEC_WPA, b.security);
  EXPECT_EQ(fw::TrustedNets::WEAKER, t.check(b));
}

TEST(FieldwatchTrusted, SerializeRoundTrip) {
  fw::TrustedNets t;
  t.trust("Home");
  t.trust("Empty");
  const uint8_t ap[6] = {0x00, 0x14, 0x6C, 0xAB, 0xCD, 0xEF};
  fw::Beacon b;
  Buf f = beacon("Home", ap, true, rsnIe({1}));
  fw::parseBeacon(f.data(), f.size(), b);
  t.check(b);
  char text[512];
  t.serialize(text, sizeof(text));
  fw::TrustedNets u;
  u.deserialize(text);
  ASSERT_EQ(2, u.count());
  EXPECT_STREQ("Home", u.at(0).ssid);
  ASSERT_EQ(1, u.at(0).apCount);
  EXPECT_EQ(0xEF, u.at(0).aps[0].bssid[5]);
  EXPECT_TRUE(u.at(0).aps[0].enterprise);
  EXPECT_EQ(0, u.at(1).apCount);
  EXPECT_FALSE(t.trust("bad\tname"));
}

// ---------------------------------------------------------------------------

TEST(FieldwatchTrackers, SeparatedStates) {
  uint8_t key[8];
  fw::TrackerFamily fam;
  Mac m = mac(1);

  Buf airtagSep;
  Buf payload(27, 0);
  payload[0] = 0x12;
  payload[1] = 0x19;
  payload[2] = 0x10;  // status bit 0x04 clear: separated
  ad(airtagSep, 0xFF, mfg(0x004C, payload));
  EXPECT_EQ(fw::TRACKER_SEPARATED, fw::trackerState(fw::AdView(airtagSep.data(), airtagSep.size()), m.b, key, fam));
  EXPECT_EQ(fw::TF_APPLE, fam);

  payload[2] = 0x14;
  Buf airtagNear;
  ad(airtagNear, 0xFF, mfg(0x004C, payload));
  EXPECT_EQ(fw::TRACKER_NEAR, fw::trackerState(fw::AdView(airtagNear.data(), airtagNear.size()), m.b, key, fam));

  Buf phone;
  Buf phonePayload = payload;
  phonePayload[2] = 0x10;
  phonePayload.insert(phonePayload.end(), {0x10, 0x02, 0x00, 0x00});
  ad(phone, 0xFF, mfg(0x004C, phonePayload));
  EXPECT_EQ(fw::TRACKER_NONE, fw::trackerState(fw::AdView(phone.data(), phone.size()), m.b, key, fam));

  Buf smart;
  ad(smart, 0x16, svc(0xFD5A, hex("110000000102030405060708F0")));
  EXPECT_EQ(fw::TRACKER_SEPARATED, fw::trackerState(fw::AdView(smart.data(), smart.size()), m.b, key, fam));
  EXPECT_EQ(fw::TF_SMARTTAG, fam);
  EXPECT_EQ(0x01, key[0]);
}

TEST(FieldwatchTrackers, WarnsAfterThirtyMinutesOnce) {
  fw::TrackerWatch w;
  Mac m = mac(1);
  Buf p;
  Buf payload(27, 0);
  payload[0] = 0x12;
  payload[1] = 0x19;
  ad(p, 0xFF, mfg(0x004C, payload));
  fw::AdView v(p.data(), p.size());
  int raised = 0;
  for (uint32_t t = 0; t <= 40UL * 60000; t += 60000) raised += w.observe(v, m.b, -70, t) >= 0;
  EXPECT_EQ(1, raised);
  w.tick(40UL * 60000 + fw::TrackerWatch::GAP_MS + 1);
  EXPECT_EQ(0, w.count());
}

// ---------------------------------------------------------------------------

TEST(FieldwatchCatalog, WifiMatches) {
  const uint8_t flock[6] = {0xB4, 0x1E, 0x52, 1, 2, 3};
  const uint8_t plain[6] = {0x12, 0x34, 0x56, 1, 2, 3};
  const uint8_t pwn[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD};
  const uint8_t netgear[6] = {0x00, 0x14, 0x6C, 1, 2, 3};
  fw::Beacon b;
  Buf f = beacon("cam", flock, true);
  fw::parseBeacon(f.data(), f.size(), b);
  fw::Match m = fw::matchWifi(f.data(), f.size(), b);
  ASSERT_GE(m.fleet, 0);
  EXPECT_STREQ("Flock Safety Cameras", m.name);
  EXPECT_TRUE(m.alert);

  f = beacon("Flock-12AB", plain, true);
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_STREQ("Flock Safety Cameras", fw::matchWifi(f.data(), f.size(), b).name);

  f = beacon("x", pwn, true);
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_STREQ("Pwnagotchi", fw::matchWifi(f.data(), f.size(), b).name);

  f = beacon("myhouse", netgear, true);
  fw::parseBeacon(f.data(), f.size(), b);
  m = fw::matchWifi(f.data(), f.size(), b);
  ASSERT_GE(m.fleet, 0);
  EXPECT_FALSE(m.alert);

  f = beacon("nothing here", plain, true);
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_EQ(-1, fw::matchWifi(f.data(), f.size(), b).fleet);
}

TEST(FieldwatchCatalog, BleMatches) {
  Mac m = mac(1);
  Buf rid;
  ad(rid, 0x16, svc(0xFFFA, bleRid(basicIdMsg("X"))));
  fw::Match hit = fw::matchBle(fw::AdView(rid.data(), rid.size()), m.b, true, "");
  ASSERT_GE(hit.fleet, 0);
  EXPECT_TRUE(hit.alert);
  EXPECT_STREQ("Drone", hit.className);

  Buf tile;
  ad(tile, 0x03, Buf{0xED, 0xFE});
  EXPECT_STREQ("Tile Trackers", fw::matchBle(fw::AdView(tile.data(), tile.size()), m.b, true, "").name);

  Buf none;
  EXPECT_EQ(-1, fw::matchBle(fw::AdView(none.data(), none.size()), m.b, true, "").fleet);
  EXPECT_GT(fw::catalogSize(), 300);
}

TEST(FieldwatchText, GlobAndContains) {
  EXPECT_TRUE(fw::globMatch("Flock-*", "flock-1234"));
  EXPECT_TRUE(fw::globMatch("PTT-?", "PTT-Z"));
  EXPECT_FALSE(fw::globMatch("PTT-Z", "PTT-Z01"));
  EXPECT_TRUE(fw::globMatch("*iBeacon*", "my IBEACON tag"));
  EXPECT_TRUE(fw::containsNoCase("Galaxy SmartTag2", "smarttag"));
  EXPECT_FALSE(fw::containsNoCase("abc", "abd"));
}

// --- Review follow-ups -----------------------------------------------------

TEST(FieldwatchRemoteId, WifiCounterOf0x0DStillParses) {
  Buf b = hex(kDjiPack);
  b[0] = 0x0D;  // the message counter, not the BLE app code
  fw::RemoteId r;
  ASSERT_TRUE(fw::parseRemoteIdWifi(b.data(), b.size(), r));
  EXPECT_STREQ("1581F3YTDJ1D0031Z530", r.uasId);
  EXPECT_EQ(287851142, r.lat);
}

TEST(FieldwatchRemoteId, OutOfRangeCoordinatesAreIgnored) {
  Buf d = bleRid(locationMsg(2, 2000000000, -740000000));
  fw::RemoteId r;
  fw::parseRemoteIdBle(d.data(), d.size(), r);
  EXPECT_FALSE(r.hasLocation);
  EXPECT_LT(fw::distanceM(-900000000, -1800000000, 900000000, 1800000000), 20100000u);
}

TEST(FieldwatchDrones, DistinctIdsFromOneAddressCountForSwarm) {
  fw::DroneTable t;
  Mac m = mac(1);
  int swarms = 0;
  for (int i = 0; i < 5; i++) {
    fw::RemoteId r;
    snprintf(r.uasId, sizeof(r.uasId), "SPOOF%d", i);
    swarms += (t.observe(m.b, r, -60, false, 1000 + i * 100) & fw::DroneTable::SWARM) != 0;
  }
  EXPECT_EQ(1, swarms);
}

TEST(FieldwatchDrones, BlankLocationThenIdIsOneDrone) {
  fw::DroneTable t;
  Mac ble = mac(1), wifi = mac(2);
  fw::RemoteId loc;
  loc.hasLocation = true;
  loc.lat = 1;
  t.observe(ble.b, loc, -60, false, 10);  // BLE location, no ID yet
  fw::RemoteId id;
  strcpy(id.uasId, "ABC");
  t.observe(wifi.b, id, -60, true, 20);  // Wi-Fi pack with the ID
  t.observe(ble.b, id, -60, false, 30);  // BLE basic ID
  EXPECT_EQ(1, t.count());
  t.observe(ble.b, loc, -60, false, 40);  // more BLE location adverts land on the same drone
  EXPECT_EQ(1, t.count());
}

TEST(FieldwatchDrones, SelfIdEmergencyDoesNotToggle) {
  fw::DroneTable t;
  Mac m = mac(1);
  fw::RemoteId self;
  self.selfKind = 1;
  fw::RemoteId loc;
  loc.hasLocation = true;
  int raised = 0;
  for (int i = 0; i < 6; i++)
    raised += (t.observe(m.b, i % 2 ? loc : self, -60, false, 10 + i) & fw::DroneTable::EMERGENCY) != 0;
  EXPECT_EQ(1, raised);
}

TEST(FieldwatchTrusted, ReplayedBssidRunningOpenWarns) {
  fw::TrustedNets t;
  t.trust("Home");
  const uint8_t ap[6] = {0x00, 0x14, 0x6C, 1, 1, 1};
  fw::Beacon b;
  Buf f = beacon("Home", ap, true, rsnIe({2}));
  fw::parseBeacon(f.data(), f.size(), b);
  t.check(b);
  EXPECT_TRUE(t.takeLearned());
  EXPECT_FALSE(t.takeLearned());
  f = beacon("Home", ap, false);
  fw::parseBeacon(f.data(), f.size(), b);
  EXPECT_EQ(fw::TrustedNets::OPEN, t.check(b));
}

TEST(FieldwatchTrusted, FullTableRoundTrips) {
  fw::TrustedNets t;
  for (int k = 0; k < fw::TrustedNets::NET_CAP; k++) {
    std::string name(32, static_cast<char>('a' + k));
    ASSERT_TRUE(t.trust(name.c_str()));
    for (int a = 0; a < fw::TrustedNets::AP_CAP; a++) {
      const uint8_t ap[6] = {0x00, 0x14, 0x6C, static_cast<uint8_t>(k), 0, static_cast<uint8_t>(a)};
      fw::Beacon b;
      Buf f = beacon(name, ap, true, rsnIe({2}));
      fw::parseBeacon(f.data(), f.size(), b);
      t.check(b);
    }
  }
  std::vector<char> text(fw::TrustedNets::SERIAL_MAX);
  ASSERT_GT(t.serialize(text.data(), text.size()), 0u);
  fw::TrustedNets u;
  u.deserialize(text.data());
  ASSERT_EQ(fw::TrustedNets::NET_CAP, u.count());
  for (int k = 0; k < u.count(); k++) EXPECT_EQ(fw::TrustedNets::AP_CAP, u.at(k).apCount);
  char small[64];
  EXPECT_EQ(0u, t.serialize(small, sizeof(small)));  // never a partial list
}

TEST(FieldwatchCatalog, RandomBleAddressSkipsOuiTable) {
  const uint8_t netgearLike[6] = {0x00, 0x14, 0x6C, 1, 2, 3};
  Buf none;
  EXPECT_EQ(-1, fw::matchBle(fw::AdView(none.data(), none.size()), netgearLike, true, "").fleet);
}
