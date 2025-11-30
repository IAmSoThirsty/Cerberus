"""Base guardian class and result types."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any


class ThreatLevel(Enum):
    """Classification of detected threats."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class GuardianResult:
    """Result of a guardian analysis."""

    guardian_id: str
    is_safe: bool
    threat_level: ThreatLevel
    message: str
    details: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        """Validate result consistency."""
        if self.is_safe and self.threat_level != ThreatLevel.NONE:
            raise ValueError("Safe result cannot have non-zero threat level")


class BaseGuardian(ABC):
    """Abstract base class for all guardian agents.

    Each guardian implements a unique analysis style to detect threats.
    The diversity in approaches ensures comprehensive coverage against
    various attack vectors including jailbreaks, injections, and bot attacks.
    """

    def __init__(self, guardian_id: str) -> None:
        """Initialize the guardian.

        Args:
            guardian_id: Unique identifier for this guardian instance.
        """
        self.guardian_id = guardian_id
        self._active = True

    @property
    def is_active(self) -> bool:
        """Check if the guardian is currently active."""
        return self._active

    def deactivate(self) -> None:
        """Deactivate this guardian."""
        self._active = False

    @abstractmethod
    def analyze(self, content: str, context: dict[str, Any] | None = None) -> GuardianResult:
        """Analyze content for potential threats.

        Args:
            content: The content to analyze for threats.
            context: Optional context information for analysis.

        Returns:
            GuardianResult containing the analysis outcome.
        """

    @abstractmethod
    def get_style_description(self) -> str:
        """Return a description of this guardian's analysis style.

        Returns:
            Human-readable description of the guardian's approach.
        """
