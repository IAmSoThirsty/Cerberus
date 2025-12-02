# Cerberus Guard Bot

A hardened, multi-agent shield for AI-to-AGI systems.

## Features

- 🛡️ **Multi-Guardian Architecture**: Three different guardian types with unique analysis styles
- 🔄 **Exponential Defense**: Automatically spawns new guardians when threats are detected
- 🚨 **Automatic Shutdown**: Triggers total shutdown when guardian limit is reached
- 🎯 **Multiple Detection Methods**: Strict rules, heuristic scoring, and pattern analysis

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/IAmSoThirsty/Cerberus.git
cd Cerberus

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
make dev-install
# or
pip install -e ".[dev]"
```

### Usage

```bash
# Run the demo
make run
# or
python -m cerberus.main
```

### As a Library

```python
from cerberus.hub import HubCoordinator

hub = HubCoordinator()
result = hub.analyze("Content to analyze")

if result["is_safe"]:
    print("Content is safe")
else:
    print(f"Threat detected: {result['highest_threat']}")
```

## Guardian Types

| Guardian | Style | Description |
|----------|-------|-------------|
| **StrictGuardian** | Rule-based | Explicit pattern matching and blocklists |
| **HeuristicGuardian** | Statistical | Weighted scoring across multiple factors |
| **PatternGuardian** | Contextual | Semantic patterns and relationship analysis |

## Development

```bash
make test       # Run tests
make lint       # Check code style
make format     # Auto-format code
make typecheck  # Run type checker
make clean      # Clean build artifacts
```

## Project Structure

```
Cerberus/
├── src/cerberus/       # Source code
│   ├── guardians/      # Guardian implementations
│   ├── hub/            # Central coordinator
│   └── main.py         # Entry point
├── tests/              # Test files
├── config/             # Configuration files
├── docs/               # Documentation
└── pyproject.toml      # Project configuration
```

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Getting Started Guide](docs/getting-started.md)

## License

MIT
