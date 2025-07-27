---
hide:
  - navigation
  - toc
---

[Crate](https://crates.io/crates/esphome-native-api) | [docs.rs](https://docs.rs/esphome-native-api/latest/esphome_native_api/)

# Rust Crate for the esphome Native API

Implementation of the [esphome native API](https://esphome.io/components/api.html) for Rust.


## Usage

For simplue usage, you can add the crate to your `Cargo.toml`:

```bash
cargo add esphome-native-api
```

Have a look at the [examples](https://github.com/DanielHabenicht/esphome-native-api/tree/main/examples) on how to use it.

### Only proto definitions

If you only want the to use the proto definitions (alrady `no_std` conform), you target the feature flag with the specific version you want to use: 

```bash
cargo add esphome-native-api --features "version_2025_7_3"
```


## Roadmap

- [ ] Fully `no_std` compatible
- [ ] "Easy" server which abstracts some of the complexity of the API