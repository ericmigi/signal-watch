#pragma once
// Receive-only radio feed for FieldwatchActivity. The ESP32-C3 has one radio, so
// it alternates a passive BLE scan with a Wi-Fi beacon sweep over channels 1-13.
// Callbacks copy frames into fixed rings; the activity drains them in loop().
// FieldwatchRadio.cpp is the only file that touches NimBLE or esp_wifi.
#include <cstdint>

struct FwBleFrame {
  uint8_t mac[6];  // display order
  bool randomAddr;
  int8_t rssi;
  uint8_t len;
  uint8_t data[62];  // advertising data + scan response
};

struct FwWifiFrame {
  uint8_t channel;
  int8_t rssi;
  uint16_t len;
  uint32_t sweep;  // sweep counter when heard
  uint8_t data[512];
};

class FieldwatchRadio {
 public:
  enum class Phase : uint8_t { Off, Ble, Wifi };
  // BLE dwell must exceed the 10 s pairing-flood window.
  static constexpr uint32_t BLE_PHASE_MS = 12000;
  static constexpr uint32_t CHANNEL_DWELL_MS = 150;
  static constexpr uint8_t WIFI_SWEEPS = 2;
  static constexpr int BLE_RING = 48;
  static constexpr int WIFI_RING = 16;

  void start();
  void stop();
  void loop();  // phase switching and channel hopping
  Phase phase() const { return phase_; }
  uint8_t channel() const { return channel_; }
  uint32_t sweeps() const { return sweeps_; }  // completed Wi-Fi sweeps
  uint32_t dropped() const { return dropped_; }
  bool popBle(FwBleFrame& out);
  bool popWifi(FwWifiFrame& out);
  FwWifiFrame scratch;  // pop target for the activity, so it is freed with the radio

  // Called from radio callbacks.
  void pushBle(const FwBleFrame& f);
  void pushWifi(const uint8_t* frame, uint16_t len, int8_t rssi, uint8_t channel);

 private:
  Phase phase_ = Phase::Off;
  uint8_t channel_ = 1;
  uint8_t sweepInPhase_ = 0;
  uint32_t sweeps_ = 0;
  uint32_t phaseStart_ = 0;
  uint32_t lastHop_ = 0;
  volatile uint32_t dropped_ = 0;

  FwBleFrame ble_[BLE_RING];
  volatile int bleHead_ = 0, bleTail_ = 0;
  FwWifiFrame wifi_[WIFI_RING];
  volatile int wifiHead_ = 0, wifiTail_ = 0;

  void enterBle();
  void enterWifi();
  void leavePhase();
};
