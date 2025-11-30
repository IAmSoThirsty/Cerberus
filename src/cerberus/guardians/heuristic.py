"""Heuristic-based guardian implementation.

This guardian uses statistical heuristics and scoring to evaluate
potential threats. It represents a more nuanced, probabilistic
analysis style.
"""

from typing import Any

from cerberus.guardians.base import BaseGuardian, GuardianResult, ThreatLevel


class HeuristicGuardian(BaseGuardian):
    """A heuristic guardian that uses statistical scoring.

    This guardian evaluates content based on multiple weighted factors
    and produces a threat score. It's more flexible than strict rules
    but requires careful tuning of thresholds.
    """

    # Thresholds for threat level classification
    CRITICAL_THRESHOLD = 0.9
    HIGH_THRESHOLD = 0.7
    MEDIUM_THRESHOLD = 0.5
    LOW_THRESHOLD = 0.3

    def __init__(self, guardian_id: str | None = None) -> None:
        """Initialize the heuristic guardian.

        Args:
            guardian_id: Unique identifier. Defaults to 'heuristic-guardian'.
        """
        super().__init__(guardian_id or "heuristic-guardian")

    def _calculate_threat_score(self, content: str) -> tuple[float, dict[str, float]]:
        """Calculate a threat score based on multiple heuristics.

        Args:
            content: The content to analyze.

        Returns:
            Tuple of (overall_score, individual_scores_dict).
        """
        scores: dict[str, float] = {}

        # Heuristic 1: Command-like structure ratio
        command_indicators = [":", "=", "[", "]", "{", "}", "<", ">"]
        command_count = sum(content.count(c) for c in command_indicators)
        scores["command_structure"] = min(command_count / max(len(content), 1) * 10, 1.0)

        # Heuristic 2: Unusual capitalization patterns
        upper_count = sum(1 for c in content if c.isupper())
        lower_count = sum(1 for c in content if c.islower())
        if lower_count > 0:
            cap_ratio = upper_count / lower_count
            scores["capitalization"] = min(cap_ratio / 2, 1.0) if cap_ratio > 0.5 else 0.0
        else:
            scores["capitalization"] = 0.5 if upper_count > 10 else 0.0

        # Heuristic 3: Instruction-like phrases
        instruction_phrases = [
            "must",
            "always",
            "never",
            "ignore",
            "forget",
            "instead",
            "now you",
            "from now",
        ]
        instruction_count = sum(1 for phrase in instruction_phrases if phrase in content.lower())
        scores["instruction_phrases"] = min(instruction_count / 3, 1.0)

        # Heuristic 4: Length anomaly (very short or very long)
        content_len = len(content)
        if content_len < 10:
            scores["length_anomaly"] = 0.3
        elif content_len > 5000:
            scores["length_anomaly"] = 0.5
        else:
            scores["length_anomaly"] = 0.0

        # Calculate weighted average
        weights = {
            "command_structure": 0.3,
            "capitalization": 0.15,
            "instruction_phrases": 0.4,
            "length_anomaly": 0.15,
        }

        overall = sum(scores[k] * weights[k] for k in scores)
        return overall, scores

    def _score_to_threat_level(self, score: float) -> ThreatLevel:
        """Convert a threat score to a ThreatLevel enum.

        Args:
            score: The calculated threat score (0.0 to 1.0).

        Returns:
            Corresponding ThreatLevel.
        """
        if score >= self.CRITICAL_THRESHOLD:
            return ThreatLevel.CRITICAL
        elif score >= self.HIGH_THRESHOLD:
            return ThreatLevel.HIGH
        elif score >= self.MEDIUM_THRESHOLD:
            return ThreatLevel.MEDIUM
        elif score >= self.LOW_THRESHOLD:
            return ThreatLevel.LOW
        return ThreatLevel.NONE

    def analyze(self, content: str, context: dict[str, Any] | None = None) -> GuardianResult:
        """Analyze content using heuristic scoring.

        Args:
            content: The content to analyze.
            context: Optional context for analysis adjustments.

        Returns:
            GuardianResult with threat assessment.
        """
        score, breakdown = self._calculate_threat_score(content)

        # Adjust threshold based on context if provided
        threshold = self.LOW_THRESHOLD
        if context and context.get("strict_mode"):
            threshold *= 0.5

        threat_level = self._score_to_threat_level(score)
        is_safe = score < threshold

        return GuardianResult(
            guardian_id=self.guardian_id,
            is_safe=is_safe,
            threat_level=threat_level if not is_safe else ThreatLevel.NONE,
            message=f"Heuristic analysis complete. Threat score: {score:.2f}",
            details={"score": score, "breakdown": breakdown, "threshold": threshold},
        )

    def get_style_description(self) -> str:
        """Return description of heuristic analysis style."""
        return (
            "Heuristic analysis using weighted scoring across multiple "
            "factors including command structure, capitalization patterns, "
            "instruction phrases, and content length anomalies."
        )
