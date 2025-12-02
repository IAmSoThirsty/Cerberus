"""Strict rule-based guardian implementation.

This guardian uses a strict, rule-based approach with explicit pattern
matching and blocklists. It represents a conservative, deterministic
analysis style.
"""

import re
from typing import Any

from cerberus.guardians.base import BaseGuardian, GuardianResult, ThreatLevel


class StrictGuardian(BaseGuardian):
    """A strict, rule-based guardian that uses explicit patterns.

    This guardian embodies a conservative, no-nonsense approach to threat
    detection. It maintains explicit blocklists and pattern rules that
    must be satisfied for content to pass.
    """

    BLOCKED_PATTERNS: list[re.Pattern[str]] = [
        re.compile(r"ignore\s+(?:all\s+)?(?:previous\s+)?instructions?", re.IGNORECASE),
        re.compile(r"disregard\s+(your|all)\s+(rules|guidelines)", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+(?:a|an)\s+\w+", re.IGNORECASE),
        re.compile(r"pretend\s+(?:you(?:'re| are)|to be)", re.IGNORECASE),
        re.compile(r"act\s+as\s+(?:if|though)", re.IGNORECASE),
        re.compile(r"system\s*prompt\s*[:=]", re.IGNORECASE),
        re.compile(r"\[system\]|\[admin\]|\[override\]", re.IGNORECASE),
    ]

    SUSPICIOUS_KEYWORDS: set[str] = {
        "jailbreak",
        "bypass",
        "override",
        "exploit",
        "injection",
        "sudo",
        "admin",
        "root",
    }

    def __init__(self, guardian_id: str | None = None) -> None:
        """Initialize the strict guardian.

        Args:
            guardian_id: Unique identifier. Defaults to 'strict-guardian'.
        """
        super().__init__(guardian_id or "strict-guardian")

    def analyze(self, content: str, context: dict[str, Any] | None = None) -> GuardianResult:
        """Analyze content using strict pattern matching rules.

        Args:
            content: The content to analyze.
            context: Optional context (unused in strict analysis).

        Returns:
            GuardianResult with threat assessment.
        """
        _ = context  # Strict guardian doesn't use context

        # Check for blocked patterns
        for pattern in self.BLOCKED_PATTERNS:
            if pattern.search(content):
                return GuardianResult(
                    guardian_id=self.guardian_id,
                    is_safe=False,
                    threat_level=ThreatLevel.CRITICAL,
                    message=f"Blocked pattern detected: {pattern.pattern}",
                    details={"matched_pattern": pattern.pattern},
                )

        # Check for suspicious keywords
        content_lower = content.lower()
        found_keywords = [kw for kw in self.SUSPICIOUS_KEYWORDS if kw in content_lower]
        if found_keywords:
            return GuardianResult(
                guardian_id=self.guardian_id,
                is_safe=False,
                threat_level=ThreatLevel.HIGH,
                message=f"Suspicious keywords detected: {', '.join(found_keywords)}",
                details={"keywords": found_keywords},
            )

        return GuardianResult(
            guardian_id=self.guardian_id,
            is_safe=True,
            threat_level=ThreatLevel.NONE,
            message="Content passed strict rule-based analysis",
        )

    def get_style_description(self) -> str:
        """Return description of strict analysis style."""
        return (
            "Strict rule-based analysis using explicit pattern matching "
            "and keyword blocklists. Conservative approach that prioritizes "
            "false positives over false negatives."
        )
