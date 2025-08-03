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
ps aux | grep ubihome
pkill -8  ubihome

ps aux | grep _server
pkill -8 encrypted_server
pkill -8 test_server
pkill -8 password_server
```

