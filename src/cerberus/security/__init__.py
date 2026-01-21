"""
Cerberus Security Module

Comprehensive security features for AI/AGI system protection including:
- Input validation and sanitization
- Audit logging with tamper detection
- Rate limiting and egress controls
- Role-Based Access Control (RBAC)
- Encryption at rest
- Agent/plugin sandboxing
- Threat detection
- Monitoring and alerting
"""

from .modules.input_validation import InputValidator, ValidationResult
from .modules.audit_logger import AuditLogger, AuditEvent
from .modules.rate_limiter import RateLimiter, rate_limit
from .modules.rbac import RBACManager, Role, Permission
from .modules.encryption import EncryptionManager, KeyManager
from .modules.sandbox import AgentSandbox, PluginSandbox
from .modules.auth import AuthManager, PasswordHasher
from .modules.threat_detector import ThreatDetector, ThreatLevel
from .modules.monitoring import SecurityMonitor, AlertManager

__all__ = [
    "InputValidator",
    "ValidationResult",
    "AuditLogger",
    "AuditEvent",
    "RateLimiter",
    "rate_limit",
    "RBACManager",
    "Role",
    "Permission",
    "EncryptionManager",
    "KeyManager",
    "AuthManager",
    "PasswordHasher",
    "ThreatDetector",
    "ThreatLevel",
    "SecurityMonitor",
    "AlertManager",
    "AgentSandbox",
    "PluginSandbox",
]
