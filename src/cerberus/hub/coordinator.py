"""Central hub coordinator for managing guardian agents."""

import random
import string
from typing import Any

import structlog

from cerberus.guardians.base import BaseGuardian, GuardianResult, ThreatLevel
from cerberus.guardians.heuristic import HeuristicGuardian
from cerberus.guardians.pattern import PatternGuardian
from cerberus.guardians.strict import StrictGuardian

logger = structlog.get_logger()


class HubCoordinator:
    """Central coordination hub for all guardian agents.

    The hub manages a pool of guardians, distributes analysis tasks,
    aggregates results, and handles the exponential growth mechanism
    when bypass attempts are detected.
    """

    MAX_GUARDIANS = 27
    GUARDIAN_GROWTH_FACTOR = 3

    GUARDIAN_TYPES: list[type[BaseGuardian]] = [
        StrictGuardian,
        HeuristicGuardian,
        PatternGuardian,
    ]

    def __init__(self, max_guardians: int | None = None) -> None:
        """Initialize the hub coordinator.

        Args:
            max_guardians: Maximum number of guardians before shutdown.
                          Defaults to 27.
        """
        self.max_guardians = max_guardians or self.MAX_GUARDIANS
        self._guardians: list[BaseGuardian] = []
        self._shutdown = False
        self._initialize_guardians()

    def _generate_guardian_id(self) -> str:
        """Generate a unique guardian identifier."""
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        return f"guardian-{suffix}"

    def _initialize_guardians(self) -> None:
        """Initialize the starting set of 3 guardians (one of each type)."""
        for guardian_type in self.GUARDIAN_TYPES:
            guardian_id = self._generate_guardian_id()
            guardian = guardian_type(guardian_id)
            self._guardians.append(guardian)
            logger.info(
                "guardian_initialized",
                guardian_id=guardian_id,
                guardian_type=guardian_type.__name__,
            )

    @property
    def guardian_count(self) -> int:
        """Return the current number of active guardians."""
        return len([g for g in self._guardians if g.is_active])

    @property
    def is_shutdown(self) -> bool:
        """Check if the hub has initiated shutdown."""
        return self._shutdown

    def _spawn_new_guardians(self) -> None:
        """Spawn new guardians in response to a bypass attempt.

        Spawns GUARDIAN_GROWTH_FACTOR new guardians of random types.
        If this exceeds MAX_GUARDIANS, initiates total shutdown.
        """
        for _ in range(self.GUARDIAN_GROWTH_FACTOR):
            guardian_type = random.choice(self.GUARDIAN_TYPES)
            guardian_id = self._generate_guardian_id()
            guardian = guardian_type(guardian_id)
            self._guardians.append(guardian)
            logger.warning(
                "guardian_spawned",
                guardian_id=guardian_id,
                guardian_type=guardian_type.__name__,
                total_guardians=self.guardian_count,
            )

        if self.guardian_count >= self.max_guardians:
            self._initiate_shutdown()

    def _initiate_shutdown(self) -> None:
        """Initiate total system shutdown due to excessive threats."""
        self._shutdown = True
        logger.critical(
            "hub_shutdown",
            reason="max_guardians_exceeded",
            guardian_count=self.guardian_count,
            max_guardians=self.max_guardians,
        )

    def analyze(self, content: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """Analyze content through all active guardians.

        Args:
            content: The content to analyze.
            context: Optional context for analysis.

        Returns:
            Dictionary containing aggregated results and decision.
        """
        if self._shutdown:
            return {
                "decision": "blocked",
                "reason": "system_shutdown",
                "message": "System is in shutdown mode. All requests are blocked.",
                "results": [],
            }

        results: list[GuardianResult] = []
        bypass_detected = False

        for guardian in self._guardians:
            if not guardian.is_active:
                continue

            result = guardian.analyze(content, context)
            results.append(result)

            # Check for potential bypass attempt
            if not result.is_safe and result.threat_level in (
                ThreatLevel.HIGH,
                ThreatLevel.CRITICAL,
            ):
                bypass_detected = True
                logger.warning(
                    "threat_detected",
                    guardian_id=guardian.guardian_id,
                    threat_level=result.threat_level.value,
                    message=result.message,
                )

        # Spawn new guardians if bypass was detected
        if bypass_detected:
            self._spawn_new_guardians()

        # Aggregate results
        all_safe = all(r.is_safe for r in results)
        highest_threat = ThreatLevel.NONE
        for result in results:
            if result.threat_level.value > highest_threat.value:
                highest_threat = result.threat_level

        return {
            "decision": "allowed" if all_safe else "blocked",
            "is_safe": all_safe,
            "highest_threat": highest_threat.value,
            "guardian_count": self.guardian_count,
            "results": [
                {
                    "guardian_id": r.guardian_id,
                    "is_safe": r.is_safe,
                    "threat_level": r.threat_level.value,
                    "message": r.message,
                }
                for r in results
            ],
        }

    def get_status(self) -> dict[str, Any]:
        """Get the current status of the hub and all guardians.

        Returns:
            Status dictionary with hub and guardian information.
        """
        return {
            "hub_status": "shutdown" if self._shutdown else "active",
            "guardian_count": self.guardian_count,
            "max_guardians": self.max_guardians,
            "guardians": [
                {
                    "id": g.guardian_id,
                    "type": g.__class__.__name__,
                    "active": g.is_active,
                    "style": g.get_style_description(),
                }
                for g in self._guardians
            ],
        }
