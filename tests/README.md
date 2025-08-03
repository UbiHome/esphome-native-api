# E2E Testing

## Installation

```
uv sync
```

## Development

```bash
cd tests
uv run pytest
```

## If something is not working

```bash
# Windows:
Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 6053 }

# Linux:
ps saux | grep ubihome
pkill -8  ubihome
```

