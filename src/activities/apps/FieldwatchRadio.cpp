#include "FieldwatchRadio.h"

#include <Arduino.h>
#include <Logging.h>
#include <NimBLEDevice.h>
#include <WiFi.h>
#include <esp_wifi.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "util/RadioManager.h"

namespace {

FieldwatchRadio* active = nullptr;
portMUX_TYPE ringMux = portMUX_INITIALIZER_UNLOCKED;

class ScanCallbacks final : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* dev) override {
    FieldwatchRadio* radio = active;
    if (!radio || !dev) return;
    FwBleFrame f;
    const uint8_t* le = dev->getAddress().getVal();
    for (int i = 0; i < 6; i++) f.mac[i] = le[5 - i];
    f.randomAddr = dev->getAddressType() != BLE_ADDR_PUBLIC;
    f.rssi = static_cast<int8_t>(dev->getRSSI());
    const std::vector<uint8_t>& payload = dev->getPayload();
    f.len = static_cast<uint8_t>(std::min<size_t>(payload.size(), sizeof(f.data)));
    memcpy(f.data, payload.data(), f.len);
    radio->pushBle(f);
  }
};
ScanCallbacks scanCallbacks;

void IRAM_ATTR promiscuousCb(void* buf, wifi_promiscuous_pkt_type_t type) {
  FieldwatchRadio* radio = active;
  if (!radio || !buf || type != WIFI_PKT_MGMT) return;
  const auto* pkt = static_cast<const wifi_promiscuous_pkt_t*>(buf);
  const uint16_t len = static_cast<uint16_t>(pkt->rx_ctrl.sig_len);
  if (len < 36) return;
  const uint8_t subtype = (pkt->payload[0] >> 4) & 0xF;
  if (subtype != 8 && subtype != 5) return;  // beacons and probe responses only
  radio->pushWifi(pkt->payload, len, static_cast<int8_t>(pkt->rx_ctrl.rssi),
                  static_cast<uint8_t>(pkt->rx_ctrl.channel));
}

}  // namespace

void FieldwatchRadio::pushBle(const FwBleFrame& f) {
  portENTER_CRITICAL(&ringMux);
  const int next = (bleHead_ + 1) % BLE_RING;
  if (next != bleTail_) {
    ble_[bleHead_] = f;
    bleHead_ = next;
  } else {
    dropped_ = dropped_ + 1;
  }
  portEXIT_CRITICAL(&ringMux);
}

void IRAM_ATTR FieldwatchRadio::pushWifi(const uint8_t* frame, uint16_t len, int8_t rssi, uint8_t channel) {
  portENTER_CRITICAL_ISR(&ringMux);
  const int next = (wifiHead_ + 1) % WIFI_RING;
  if (next != wifiTail_) {
    FwWifiFrame& f = wifi_[wifiHead_];
    f.len = std::min<uint16_t>(len, sizeof(f.data));
    memcpy(f.data, frame, f.len);
    f.rssi = rssi;
    f.channel = channel;
    f.sweep = sweeps_;
    wifiHead_ = next;
  } else {
    dropped_ = dropped_ + 1;
  }
  portEXIT_CRITICAL_ISR(&ringMux);
}

bool FieldwatchRadio::popBle(FwBleFrame& out) {
  portENTER_CRITICAL(&ringMux);
  const bool have = bleTail_ != bleHead_;
  if (have) {
    out = ble_[bleTail_];
    bleTail_ = (bleTail_ + 1) % BLE_RING;
  }
  portEXIT_CRITICAL(&ringMux);
  return have;
}

bool FieldwatchRadio::popWifi(FwWifiFrame& out) {
  portENTER_CRITICAL(&ringMux);
  const bool have = wifiTail_ != wifiHead_;
  if (have) {
    out = wifi_[wifiTail_];
    wifiTail_ = (wifiTail_ + 1) % WIFI_RING;
  }
  portEXIT_CRITICAL(&ringMux);
  return have;
}

void FieldwatchRadio::start() {
  active = this;
  bleHead_ = 0;
  bleTail_ = 0;
  wifiHead_ = 0;
  wifiTail_ = 0;
  enterBle();
}

void FieldwatchRadio::stop() {
  leavePhase();
  active = nullptr;
  RADIO.shutdown();
  phase_ = Phase::Off;
}

void FieldwatchRadio::enterBle() {
  RADIO.ensureBle();
  NimBLEScan* scan = NimBLEDevice::getScan();
  scan->setScanCallbacks(&scanCallbacks, true);
  scan->setActiveScan(false);  // receive-only: no scan requests
  scan->setDuplicateFilter(0);  // Remote ID and tracker state change between adverts
  scan->setMaxResults(0);      // do not store results; a flood must not grow the heap
  scan->setInterval(100);
  scan->setWindow(99);
  scan->start(0, false, true);
  phase_ = Phase::Ble;
  phaseStart_ = millis();
  LOG_DBG("FW", "BLE phase, heap %u max %u", ESP.getFreeHeap(), ESP.getMaxAllocHeap());
}

void FieldwatchRadio::enterWifi() {
  RADIO.ensureWifi();
  WiFi.disconnect();
  wifi_promiscuous_filter_t filter{};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(promiscuousCb);
  channel_ = 1;
  sweepInPhase_ = 0;
  esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
  phase_ = Phase::Wifi;
  phaseStart_ = lastHop_ = millis();
  LOG_DBG("FW", "Wi-Fi phase, heap %u max %u", ESP.getFreeHeap(), ESP.getMaxAllocHeap());
}

void FieldwatchRadio::leavePhase() {
  if (phase_ == Phase::Ble) {
    NimBLEScan* scan = NimBLEDevice::getScan();
    scan->stop();
    scan->setScanCallbacks(nullptr);
  } else if (phase_ == Phase::Wifi) {
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
  }
}

void FieldwatchRadio::loop() {
  const uint32_t now = millis();
  if (phase_ == Phase::Ble) {
    if (now - phaseStart_ >= BLE_PHASE_MS) {
      leavePhase();
      enterWifi();
    }
  } else if (phase_ == Phase::Wifi) {
    if (now - lastHop_ < CHANNEL_DWELL_MS) return;
    lastHop_ = now;
    if (channel_ < 13) {
      esp_wifi_set_channel(++channel_, WIFI_SECOND_CHAN_NONE);
      return;
    }
    sweeps_++;
    if (++sweepInPhase_ >= WIFI_SWEEPS) {
      leavePhase();
      enterBle();
    } else {
      channel_ = 1;
      esp_wifi_set_channel(channel_, WIFI_SECOND_CHAN_NONE);
    }
  }
}
