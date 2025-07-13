# E2E Testing

## Installation

```
pipx install poetry
```

## Development

```bash
cd tests
# Windows
.\.venv\Scripts\activate.ps1
# Linux:
eval $(poetry env activate)
pytest
```

## If something is not working

```bash
# Windows:
Get-NetTCPConnection | Where-Object { $_.LocalPort -eq 6053 }

# Linux:
ps saux | grep ubihome
pkill -8  ubihome
```

