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
