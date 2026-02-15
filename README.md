# Cerberus

**Cerberus Guard Bot**: A hardened, multi-agent shield for AI-to-AGI systems.

## Overview

Cerberus is a security framework that uses multiple guardian agents to protect AI systems against:
- Prompt injection attacks
- Jailbreak attempts
- System manipulation
- Bot attacks

## Key Features

### Core Protection
- **Multi-Agent Architecture**: Starts with 3 guardians using different detection styles
- **Central Hub Coordination**: All guardians report to a central hub for aggregated decision making
- **Exponential Defense Growth**: Any bypass attempt spawns 3 new random guardians
- **Automatic Shutdown**: Guardian count capped at 27 before triggering total shutdown
- **Defense in Depth**: Multiple detection approaches ensure comprehensive protection

### Advanced Security Modules (New!)
- **Input Validation**: Detects XXE, SQLi, XSS, command injection, path traversal, LDAP/NoSQL injection, prompt injection, and jailbreak attempts
- **Audit Logging**: HMAC-signed tamper-proof logging with Prometheus metrics
- **Rate Limiting**: Token bucket and sliding window algorithms with per-source limits
- **RBAC**: Role-based access control with default roles (admin, guardian, operator, viewer, auditor)
- **Encryption at Rest**: Fernet/AES encryption with key management and rotation
- **Sandboxing**: Agent and plugin isolation with resource limits and capability controls
- **Authentication**: bcrypt/pbkdf2 password hashing with session management
- **Threat Detection**: Pattern-based and behavioral threat detection with custom signatures
- **Monitoring & Alerting**: Real-time anomaly detection and alerting with Prometheus export

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

### Basic Guardian Usage

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

### Using Security Modules

```python
from cerberus.security import (
    InputValidator, AuditLogger, RateLimiter, 
    ThreatDetector, SecurityMonitor
)

# Input validation
validator = InputValidator()
result = validator.validate(user_input)
if not result.is_valid:
    print(f"Attack detected: {result.attack_type}")

# Threat detection
detector = ThreatDetector()
threat_result = detector.detect(user_input)
if threat_result.is_threat:
    print(f"Threat level: {threat_result.threat_level}")

# Audit logging
audit_logger = AuditLogger()
audit_logger.log_threat(
    threat_level="HIGH",
    details={"attack_type": "prompt_injection"}
)

# Rate limiting
@rate_limit(max_requests=10, window_seconds=60)
def protected_endpoint(user_id: str):
    return process_request(user_id)

# Monitoring
monitor = SecurityMonitor()
monitor.record_metric("requests_per_second", 100.5)
health = monitor.get_system_health()
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

## Security Documentation

Comprehensive security documentation is available:

- **[Security Guide](docs/security/guides/SECURITY_GUIDE.md)** - Core defensive procedures
- **[Threat Models](docs/security/threat-models/)** - White/Grey/Black/Red/Blue team operations
- **[Compliance](docs/security/compliance/)** - OWASP, NIST, AI/LLM security checklists
- **[Training Materials](docs/security/training/)** - Security training and awareness
- **[CI/CD Security](docs/security/ci-cd/)** - Pipeline security and automation
- **[Incident Response](docs/security/guides/incident-response.md)** - Response procedures
- **[Quick Reference](docs/security/guides/quick-reference.md)** - Best practices guide

## Security Reporting

Please report security vulnerabilities to **security@cerberus-ai.org** or via GitHub Security Advisories. See [SECURITY.md](SECURITY.md) for details.

## API Reference

### Security Modules

All security modules are available under `cerberus.security`:

```python
from cerberus.security import (
    # Input validation
    InputValidator, ValidationResult, AttackType,
    
    # Audit logging
    AuditLogger, AuditEvent, AuditEventType,
    
    # Rate limiting
    RateLimiter, rate_limit, RateLimitConfig,
    
    # Access control
    RBACManager, Role, Permission,
    
    # Encryption
    EncryptionManager, KeyManager,
    
    # Authentication
    AuthManager, PasswordHasher,
    
    # Sandboxing
    AgentSandbox, PluginSandbox, SandboxConfig,
    
    # Threat detection
    ThreatDetector, ThreatLevel, ThreatCategory,
    
    # Monitoring
    SecurityMonitor, AlertManager, AlertSeverity
)
```

See individual module documentation for detailed API reference.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](docs/security/guides/CONTRIBUTING.md) for guidelines.

## License

MIT License

