# Cerberus

**Cerberus Guard Bot**: A hardened, multi-agent shield for AI-to-AGI systems.

## Overview

Cerberus is a security framework that uses multiple guardian agents to protect AI systems against:
- Prompt injection attacks
- Jailbreak attempts
- System manipulation
- Bot attacks

## Key Features

- **Multi-Agent Architecture**: Starts with 3 guardians using different detection styles
- **Central Hub Coordination**: All guardians report to a central hub for aggregated decision making
- **Exponential Defense Growth**: Any bypass attempt spawns 3 new random guardians
- **Automatic Shutdown**: Guardian count capped at 27 before triggering total shutdown
- **Defense in Depth**: Multiple detection approaches ensure comprehensive protection

## Guardian Types

1. **PatternGuardian**: Rule-based pattern matching for known attack vectors
2. **HeuristicGuardian**: Behavioral heuristics for suspicious patterns
3. **StatisticalGuardian**: Statistical anomaly detection for unusual inputs

## Installation

```bash
# Clone the repository
git clone https://github.com/IAmSoThirsty/Cerberus.git
cd Cerberus

# Install in development mode
pip install -e ".[dev]"
```

## Quick Start

```python
from cerberus import CerberusHub

# Create the hub (initializes with 3 guardians)
hub = CerberusHub()

# Analyze user input
decision = hub.analyze("Hello, how can I help you?")

if decision.should_block:
    print(f"BLOCKED: {decision.summary}")
else:
    print(f"ALLOWED: {decision.summary}")

# Check hub status
status = hub.get_status()
print(f"Active guardians: {status['active_guardians']}")
```

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cerberus

# Run specific test file
pytest tests/test_hub.py
```

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run linting
ruff check src tests

# Run type checking
mypy src
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 CerberusHub                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │
│  │ Pattern  │ │Heuristic │ │   Statistical    │ │
│  │ Guardian │ │ Guardian │ │    Guardian      │ │
│  └────┬─────┘ └────┬─────┘ └────────┬─────────┘ │
│       │            │                │           │
│       └────────────┴────────────────┘           │
│                    │                            │
│            [Aggregated Decision]                │
└─────────────────────────────────────────────────┘
```

## License

MIT License
