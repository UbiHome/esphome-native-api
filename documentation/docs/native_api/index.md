# Missing Native API Documentation

- TCP Based
- Protocol Buffers

## Entities

- Sensor Mappings
  https://github.com/esphome/aioesphomeapi/blob/e14b6ec9315695ba13e7cf6b750bc892b77a0a2e/aioesphomeapi/model.py#L433

- Entity Keys:
  The entity key is not just a arbitrary integer, but the FNV-1 hash of the entity's unique ID (+ some sanitization and normalization).
  https://github.com/esphome/esphome/blob/58a9e30017b7094c9cf8bfb0739b610ba5bcd450/esphome/core/helpers.h#L559
