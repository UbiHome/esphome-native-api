
HelloResponse: api_version_major: 1
api_version_minor: 10

DeviceInfoResponse: name: "bluetooth-proxy"
mac_address: "E4:65:B8:A3:90:00"
esphome_version: "2025.4.1"
compilation_time: "May  2 2025, 03:08:50"
model: "esp32dev"
legacy_bluetooth_proxy_version: 5
manufacturer: "Espressif"
friendly_name: "bluetooth-proxy"
bluetooth_proxy_feature_flags: 63
bluetooth_mac_address: "E4:65:B8:A3:90:02"

https://github.com/esphome/aioesphomeapi/blob/71bcda2c2cf9aecf3843c01937a24e012f7a3244/aioesphomeapi/model.py#L110
=> 
class BluetoothProxyFeature(enum.IntFlag):
    PASSIVE_SCAN = 1 << 0             # 1
    ACTIVE_CONNECTIONS = 1 << 1       # 2
    REMOTE_CACHING = 1 << 2           # 4
    PAIRING = 1 << 3                  # 8
    CACHE_CLEARING = 1 << 4           # 16
    RAW_ADVERTISEMENTS = 1 << 5       # 32
    FEATURE_STATE_AND_MODE = 1 << 6   # 64

    0000000000111111