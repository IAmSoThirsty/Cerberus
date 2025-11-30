"""
Cerberus Guard Bot: A hardened, multi-agent shield for AI-to-AGI systems.

This package provides:
- Multiple guardian agents with different detection styles
- A central hub for coordinating guardians
- Exponential growth mechanism for handling bypass attempts
- Safety-first approach to blocking jailbreaks, injections & bot attacks
"""

from cerberus.guardians.base import Guardian, ThreatLevel, ThreatReport
from cerberus.hub import CerberusHub

__version__ = "0.1.0"
__all__ = ["CerberusHub", "Guardian", "ThreatLevel", "ThreatReport"]
