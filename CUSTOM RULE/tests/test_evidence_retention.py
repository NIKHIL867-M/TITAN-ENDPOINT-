"""
Test evidence retention — severity-based cleanup (master.md Fix #7).

Verifies that the upgraded cleanup_old_evidence():
  - Deletes old evidence files based on their severity
  - Preserves recent files regardless of severity
  - Uses default retention when severity can't be read
  - Handles malformed evidence files gracefully
"""
import json
import os
import time
import pytest

from watcher.investigation import cleanup_old_evidence


def _write_evidence(evidence_dir, filename, severity, age_days):
    """Helper: create an evidence file with a given severity and simulated age."""
    filepath = evidence_dir / filename
    record = {
        "instance_id": filename.replace(".json", ""),
        "severity": severity,
        "rule_id": "test-rule",
        "matched_at": "2024-01-01T00:00:00Z",
    }
    filepath.write_text(json.dumps(record))
    # Set modification time to simulate age
    mtime = time.time() - (age_days * 86400)
    os.utime(filepath, (mtime, mtime))
    return filepath


class TestSeverityBasedRetention:
    """Tests for severity-based evidence retention."""

    def test_old_low_severity_deleted(self, tmp_evidence_dir):
        """Low severity with default 14-day retention: 15-day-old → deleted."""
        _write_evidence(tmp_evidence_dir, "low_old.json", "low", age_days=15)
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 1
        assert not (tmp_evidence_dir / "low_old.json").exists()

    def test_recent_low_severity_preserved(self, tmp_evidence_dir):
        """Low severity within 14-day retention: 10-day-old → preserved."""
        _write_evidence(tmp_evidence_dir, "low_recent.json", "low", age_days=10)
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 0
        assert (tmp_evidence_dir / "low_recent.json").exists()

    def test_old_critical_preserved(self, tmp_evidence_dir):
        """Critical severity with 180-day retention: 100-day-old → preserved."""
        _write_evidence(tmp_evidence_dir, "critical_old.json", "critical", age_days=100)
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 0
        assert (tmp_evidence_dir / "critical_old.json").exists()

    def test_very_old_critical_deleted(self, tmp_evidence_dir):
        """Critical severity past 180-day retention: 200-day-old → deleted."""
        _write_evidence(tmp_evidence_dir, "critical_ancient.json", "critical", age_days=200)
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 1
        assert not (tmp_evidence_dir / "critical_ancient.json").exists()

    def test_medium_severity_retention(self, tmp_evidence_dir):
        """Medium severity with 30-day retention: 35-day-old → deleted."""
        _write_evidence(tmp_evidence_dir, "med_old.json", "medium", age_days=35)
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 1

    def test_high_severity_retention(self, tmp_evidence_dir):
        """High severity with 90-day retention: 50-day-old → preserved."""
        _write_evidence(tmp_evidence_dir, "high_mid.json", "high", age_days=50)
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 0

    def test_mixed_severities(self, tmp_evidence_dir):
        """Multiple files with different severities: only expired ones deleted."""
        _write_evidence(tmp_evidence_dir, "low_expired.json", "low", age_days=20)
        _write_evidence(tmp_evidence_dir, "med_fresh.json", "medium", age_days=5)
        _write_evidence(tmp_evidence_dir, "high_fresh.json", "high", age_days=10)
        _write_evidence(tmp_evidence_dir, "crit_fresh.json", "critical", age_days=50)
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 1  # only the low with 20 days (> 14 day retention)
        assert not (tmp_evidence_dir / "low_expired.json").exists()
        assert (tmp_evidence_dir / "med_fresh.json").exists()
        assert (tmp_evidence_dir / "high_fresh.json").exists()
        assert (tmp_evidence_dir / "crit_fresh.json").exists()

    def test_malformed_evidence_uses_default_retention(self, tmp_evidence_dir):
        """If the evidence JSON can't be read, fall back to default retention."""
        filepath = tmp_evidence_dir / "malformed.json"
        filepath.write_text("not valid json {{{")
        mtime = time.time() - (35 * 86400)
        os.utime(filepath, (mtime, mtime))
        # Default retention is 30 days, file is 35 days old → should be deleted
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 1

    def test_custom_severity_retention(self, tmp_evidence_dir):
        """Custom severity retention map overrides the defaults."""
        _write_evidence(tmp_evidence_dir, "low_custom.json", "low", age_days=5)
        # Custom: low retains only 3 days
        deleted = cleanup_old_evidence(
            tmp_evidence_dir,
            retention_days=30,
            severity_retention={"low": 3, "medium": 7, "high": 14, "critical": 30},
        )
        assert deleted == 1

    def test_empty_directory(self, tmp_evidence_dir):
        """Empty directory → 0 deleted, no crash."""
        deleted = cleanup_old_evidence(tmp_evidence_dir, retention_days=30)
        assert deleted == 0

    def test_nonexistent_directory(self, tmp_path):
        """Non-existent directory → 0 deleted, no crash."""
        deleted = cleanup_old_evidence(tmp_path / "nope", retention_days=30)
        assert deleted == 0
