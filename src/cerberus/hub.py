"""
Central Hub: Coordinator for Cerberus guardian agents.

The hub manages multiple guardians, aggregates their threat reports,
and implements the exponential growth mechanism for handling bypass attempts.
"""

import random
from typing import Any

from pydantic import BaseModel, Field

from cerberus.guardians.base import Guardian, ThreatLevel, ThreatReport
from cerberus.guardians.heuristic_guardian import HeuristicGuardian
from cerberus.guardians.pattern_guardian import PatternGuardian
from cerberus.guardians.statistical_guardian import StatisticalGuardian


class HubDecision(BaseModel):
    """Final decision from the Cerberus Hub after aggregating guardian reports."""

    should_block: bool = Field(default=False, description="Whether to block the input")
    threat_level: ThreatLevel = Field(default=ThreatLevel.NONE, description="Overall threat level")
    confidence: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Aggregated confidence score"
    )
    guardian_reports: list[ThreatReport] = Field(
        default_factory=list, description="Individual reports from guardians"
    )
    active_guardians: int = Field(default=0, description="Number of active guardians")
    bypass_attempts: int = Field(
        default=0, description="Number of bypass attempts detected so far"
    )
    shutdown_triggered: bool = Field(
        default=False, description="Whether total shutdown was triggered"
    )
    summary: str = Field(default="", description="Human-readable summary of the decision")


class CerberusHub:
    """
    Central coordinator for Cerberus guardian agents.

    Manages a pool of guardians, aggregates their threat assessments,
    and implements exponential growth on bypass detection.

    The hub starts with 3 guardians (one of each type). When a bypass
    is detected, 3 new random guardians are spawned. This continues
    until the maximum of 27 guardians is reached, at which point
    total shutdown is triggered.
    """

    INITIAL_GUARDIAN_COUNT = 3
    GUARDIANS_PER_SPAWN = 3
    MAX_GUARDIANS = 27
    GUARDIAN_TYPES: list[type[Guardian]] = [
        PatternGuardian,
        HeuristicGuardian,
        StatisticalGuardian,
    ]

    def __init__(self, auto_grow: bool = True) -> None:
        """
        Initialize the Cerberus Hub.

        Args:
            auto_grow: Whether to automatically spawn new guardians
                      when bypass attempts are detected
        """
        self._guardians: list[Guardian] = []
        self._bypass_attempts = 0
        self._auto_grow = auto_grow
        self._shutdown = False

        # Initialize with one guardian of each type
        self._initialize_guardians()

    def _initialize_guardians(self) -> None:
        """Initialize the starting set of guardians."""
        self._guardians = [
            PatternGuardian(),
            HeuristicGuardian(),
            StatisticalGuardian(),
        ]

    @property
    def guardian_count(self) -> int:
        """Return the current number of active guardians."""
        return len(self._guardians)

    @property
    def is_shutdown(self) -> bool:
        """Return whether the hub has triggered shutdown."""
        return self._shutdown

    @property
    def bypass_attempts(self) -> int:
        """Return the number of detected bypass attempts."""
        return self._bypass_attempts

    def analyze(self, content: str, context: dict[str, Any] | None = None) -> HubDecision:
        """
        Analyze content through all active guardians.

        Args:
            content: The content to analyze
            context: Optional context information

        Returns:
            HubDecision with aggregated results from all guardians
        """
        if self._shutdown:
            return HubDecision(
                should_block=True,
                threat_level=ThreatLevel.CRITICAL,
                confidence=1.0,
                active_guardians=self.guardian_count,
                bypass_attempts=self._bypass_attempts,
                shutdown_triggered=True,
                summary="SYSTEM SHUTDOWN: Maximum guardian count exceeded. All inputs blocked.",
            )

        # Collect reports from all guardians
        reports: list[ThreatReport] = []
        for guardian in self._guardians:
            report = guardian.analyze(content, context)
            reports.append(report)

        # Aggregate results
        decision = self._aggregate_reports(reports)

        # Check for bypass attempt (high threat but one guardian missed it)
        if self._detect_bypass_attempt(reports):
            self._handle_bypass()
            decision.bypass_attempts = self._bypass_attempts

            if self._shutdown:
                decision.shutdown_triggered = True
                decision.should_block = True
                decision.summary = (
                    f"SHUTDOWN TRIGGERED: {self._bypass_attempts} bypass attempts detected. "
                    f"Guardian count reached {self.guardian_count}. All inputs blocked."
                )

        return decision

    def _aggregate_reports(self, reports: list[ThreatReport]) -> HubDecision:
        """Aggregate individual guardian reports into a hub decision."""
        if not reports:
            return HubDecision(summary="No guardians available for analysis")

        # Calculate aggregated metrics
        threat_levels = [r.threat_level for r in reports]
        confidences = [r.confidence for r in reports]
        any_block = any(r.should_block for r in reports)

        # Use highest threat level
        max_threat = max(threat_levels, key=lambda t: list(ThreatLevel).index(t))

        # Aggregated confidence (simple average of guardian confidences)
        if confidences:
            weighted_conf = sum(confidences) / len(confidences)
        else:
            weighted_conf = 0.0

        # Generate summary
        blocking_guardians = [r.guardian_id for r in reports if r.should_block]
        all_threats = []
        for r in reports:
            all_threats.extend(r.threats_detected)

        if any_block:
            summary = (
                f"BLOCKED by {len(blocking_guardians)} guardian(s). "
                f"Threat level: {max_threat.value}. "
                f"Threats: {len(all_threats)} detected."
            )
        elif max_threat != ThreatLevel.NONE:
            summary = (
                f"ALLOWED with {max_threat.value} threat level. "
                f"Threats: {len(all_threats)} detected. Monitor recommended."
            )
        else:
            summary = "ALLOWED: No threats detected."

        return HubDecision(
            should_block=any_block,
            threat_level=max_threat,
            confidence=weighted_conf,
            guardian_reports=reports,
            active_guardians=self.guardian_count,
            bypass_attempts=self._bypass_attempts,
            summary=summary,
        )

    def _detect_bypass_attempt(self, reports: list[ThreatReport]) -> bool:
        """
        Detect if a bypass attempt occurred.

        A bypass is detected when:
        - At least one guardian detected a high/critical threat
        - But another guardian detected low/no threat
        This indicates an attempt to exploit blind spots.
        """
        high_threat_detected = any(
            r.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL) for r in reports
        )
        low_threat_detected = any(
            r.threat_level in (ThreatLevel.NONE, ThreatLevel.LOW) for r in reports
        )

        return high_threat_detected and low_threat_detected

    def _handle_bypass(self) -> None:
        """Handle a detected bypass attempt by spawning new guardians."""
        self._bypass_attempts += 1

        if not self._auto_grow:
            return

        # Spawn new guardians
        for _ in range(self.GUARDIANS_PER_SPAWN):
            if self.guardian_count >= self.MAX_GUARDIANS:
                self._shutdown = True
                return

            # Randomly select guardian type
            guardian_class = random.choice(self.GUARDIAN_TYPES)
            self._guardians.append(guardian_class())

    def add_guardian(self, guardian: Guardian) -> bool:
        """
        Manually add a guardian to the hub.

        Args:
            guardian: The guardian to add

        Returns:
            True if guardian was added, False if at capacity
        """
        if self.guardian_count >= self.MAX_GUARDIANS:
            return False
        self._guardians.append(guardian)
        return True

    def get_status(self) -> dict[str, Any]:
        """Get current status of the hub."""
        return {
            "active_guardians": self.guardian_count,
            "max_guardians": self.MAX_GUARDIANS,
            "bypass_attempts": self._bypass_attempts,
            "is_shutdown": self._shutdown,
            "guardian_types": [g.guardian_type for g in self._guardians],
        }

    def reset(self) -> None:
        """Reset the hub to initial state."""
        self._guardians.clear()
        self._bypass_attempts = 0
        self._shutdown = False
        self._initialize_guardians()
