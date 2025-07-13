Recently Added: https://developers.esphome.io/architecture/api/protocol_details/

The Encryption protocol is based on the general protocol: 


```mermaid
---
title: "Native API Packet (encrypted)"
---
packet-beta
  0-0: "Marker (0x01)"
  1-2: "Length"
  3-3: "Encryption Type (0x01 for Noise_NNpsk0_25519_ChaChaPoly_SHA256)"
  2-2: "Type"
  3-31: "Protobuf Content"
```


```mermaid
---
title: "SERVER HELLO"
---
packet-beta
  0-0: "Marker (0x01)"
  1-2: "Length"
  3-3: "Encryption Type (0x01 for Noise_NNpsk0_25519_ChaChaPoly_SHA256)"
  2-2: "Type"
  3-31: "Protobuf Content"
```

```mermaid
---
title: "SERVER HANDSHAKE"
---
packet-beta
  0-0: "Marker (0x01)"
  1-2: "Length"
  3-3: "Encryption Type (0x01 for Noise_NNpsk0_25519_ChaChaPoly_SHA256)"
  2-2: "Type"
  3-31: "Protobuf Content"
```



Notes: 

- for api encryption the mdns entry needs to be added: `"api_encryption=Noise_NNpsk0_25519_ChaChaPoly_SHA256"`

