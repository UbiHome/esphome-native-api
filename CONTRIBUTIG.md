# Contributing

## Development

```bash
# Generate API code
cargo run -p generator
```

```
# Execute example
cargo run --example server
```

## Testing


### Functionality

1. Install [uv](https://docs.astral.sh/uv/getting-started/installation/)
```
cd tests
uv run pytest
```

### esphomeapi Version Matrix

```
uv tool install tox --with tox-uv

```

## Documentation

Run `cargo doc` to generate a local documentation of all crates.

For working on this package documentation use:

```bash
cargo doc -p esphome-native-api
cd target/doc/esphome_native_api/
npx http-server
```
