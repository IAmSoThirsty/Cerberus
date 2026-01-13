"""Tests for the base Guardian class and common types."""


from cerberus.guardians.base import Guardian, ThreatLevel, ThreatReport


class ConcreteGuardian(Guardian):
    """Concrete implementation for testing abstract Guardian class."""

    @property
    def guardian_type(self) -> str:
        return "test"

    def analyze(self, content: str, context: dict | None = None) -> ThreatReport:
        # Simple implementation that flags "danger" keyword
        if "danger" in content.lower():
            return self._create_report(
                threat_level=ThreatLevel.HIGH,
                confidence=0.9,
                threats=["Danger keyword detected"],
            )
        return self._create_report()


class TestThreatLevel:
    """Tests for ThreatLevel enum."""

    def test_threat_levels_exist(self) -> None:
        """Test all expected threat levels exist."""
        assert ThreatLevel.NONE == "none"
        assert ThreatLevel.LOW == "low"
        assert ThreatLevel.MEDIUM == "medium"
        assert ThreatLevel.HIGH == "high"
        assert ThreatLevel.CRITICAL == "critical"


class TestThreatReport:
    """Tests for ThreatReport model."""

    def test_create_minimal_report(self) -> None:
        """Test creating a report with minimal fields."""
        report = ThreatReport(guardian_id="test-1", guardian_type="test")
        assert report.guardian_id == "test-1"
        assert report.guardian_type == "test"
        assert report.threat_level == ThreatLevel.NONE
        assert report.confidence == 0.0
        assert report.threats_detected == []
        assert report.should_block is False

    def test_create_full_report(self) -> None:
        """Test creating a report with all fields."""
        report = ThreatReport(
            guardian_id="test-2",
            guardian_type="pattern",
            threat_level=ThreatLevel.HIGH,
            confidence=0.95,
            threats_detected=["Threat 1", "Threat 2"],
            metadata={"key": "value"},
            should_block=True,
        )
        assert report.threat_level == ThreatLevel.HIGH
        assert report.confidence == 0.95
        assert len(report.threats_detected) == 2
        assert report.should_block is True


class TestGuardian:
    """Tests for the Guardian base class."""

    def test_guardian_id_generation(self) -> None:
        """Test that guardians generate unique IDs."""
        g1 = ConcreteGuardian()
        g2 = ConcreteGuardian()
        assert g1.id != g2.id
        assert g1.id.startswith("test-")

    def test_guardian_custom_id(self) -> None:
        """Test guardian with custom ID."""
        g = ConcreteGuardian(guardian_id="custom-id")
        assert g.id == "custom-id"

    def test_guardian_type(self) -> None:
        """Test guardian type property."""
        g = ConcreteGuardian()
        assert g.guardian_type == "test"

    def test_analyze_safe_content(self) -> None:
        """Test analyzing safe content."""
        g = ConcreteGuardian()
        report = g.analyze("Hello, this is safe content")
        assert report.threat_level == ThreatLevel.NONE
        assert report.should_block is False

    def test_analyze_dangerous_content(self) -> None:
        """Test analyzing dangerous content."""
        g = ConcreteGuardian()
        report = g.analyze("This contains danger word")
        assert report.threat_level == ThreatLevel.HIGH
        assert report.should_block is True
        assert len(report.threats_detected) == 1
