import json
import os
import pytest
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from src.security_event_processor import SecurityEventProcessor

def get_data_dir():
    """Helper to locate log_data directory"""
    base_dir = os.path.dirname(os.path.dirname(__file__))
    return os.path.join(base_dir, "log_data")


# --- Test: Output file is created ---
def test_normalized_output_exists(tmp_path):
    processor = SecurityEventProcessor()

    data_dir = get_data_dir()

    av = processor.ingest_json(os.path.join(data_dir, "events_av.json"))
    processor.normalize(av)

    output_file = tmp_path / "test_output.json"
    processor.write_normalized(output_file)

    assert output_file.exists()


# --- Test: Schema validation ---
def test_normalized_schema(tmp_path):
    processor = SecurityEventProcessor()

    data_dir = get_data_dir()
    av = processor.ingest_json(os.path.join(data_dir, "events_av.json"))
    processor.normalize(av)

    output_file = tmp_path / "test_output.json"
    processor.write_normalized(output_file)

    with open(output_file) as f:
        data = json.load(f)

    for event in data:
        assert "id" in event
        assert "timestamp" in event
        assert "host_or_source" in event
        assert "event_type" in event
        assert "severity" in event


# --- Test: Severity mapping ---
def test_severity_mapping():
    processor = SecurityEventProcessor()

    test_event = [{
        "timestamp": "2026-03-22T10:00:00-05:00",
        "host_or_source": "host01",
        "event_type": "TestEvent",
        "severity": "ERROR"
    }]

    normalized = processor.normalize(test_event)

    assert normalized[0]["severity"] == "High"


# --- Test: Aggregation rule triggers ---
def test_aggregation_rule():
    processor = SecurityEventProcessor()

    events = [
        {"event_type": "AuthenticationFailed", "timestamp": "2026-03-22T15:00:00+00:00", "host_or_source": "h1"},
        {"event_type": "AuthenticationFailed", "timestamp": "2026-03-22T15:01:00+00:00", "host_or_source": "h1"},
        {"event_type": "AuthenticationFailed", "timestamp": "2026-03-22T15:02:00+00:00", "host_or_source": "h1"},
    ]

    processor.normalized_events = events
    results = processor.process_rules()

    assert any("Aggregated" in r for r in results)


# --- Test: Malformed record handling ---
def test_malformed_record_handling():
    processor = SecurityEventProcessor()

    bad_event = [{"bad_field": "oops"}]

    normalized = processor.normalize(bad_event)

    # Should not crash, just skip or produce minimal record
    assert isinstance(normalized, list)


# --- Test: Retry logic concept (deterministic) ---
def test_retry_logic_simulation():
    """
    Simulates retry behavior for transient failures.
    This is deterministic (not flaky).
    """
    attempts = 0
    max_retries = 3
    success = False

    while attempts < max_retries:
        attempts += 1
        # Simulate failure on first 2 attempts
        if attempts < 3:
            continue
        success = True

    assert success
    assert attempts == 3


# --- Optional: Flaky test example (DO NOT RUN in CI) ---
@pytest.mark.skip(reason="Demonstration of flaky test - do not run in CI")
def test_flaky_example():
    """
    Example of a flaky test due to randomness.
    This is intentionally skipped.
    """
    import random
    assert random.choice([True, False])