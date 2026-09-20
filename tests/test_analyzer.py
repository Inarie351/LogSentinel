from logsentinel.analyzer import (
    aggregate_by_ip,
    build_recommendations,
    build_summary,
    detect_suspicious_ips,
)
from logsentinel.parser import SSHEvent


def make_events():
    return [
        SSHEvent(timestamp="Jan 17 10:00:00", event_type="failed", user="root", ip="1.2.3.4"),
        SSHEvent(timestamp="Jan 17 10:00:01", event_type="failed", user="root", ip="1.2.3.4"),
        SSHEvent(timestamp="Jan 17 10:00:02", event_type="invalid_user", user="admin", ip="1.2.3.4"),
        SSHEvent(timestamp="Jan 17 10:00:03", event_type="invalid_user", user="test", ip="1.2.3.4"),
        SSHEvent(timestamp="Jan 17 10:00:04", event_type="success", user="alice", ip="1.2.3.4"),
        SSHEvent(timestamp="Jan 17 10:01:00", event_type="failed", user="admin", ip="5.6.7.8"),
        SSHEvent(timestamp="Jan 17 10:02:00", event_type="success", user="bob", ip="9.9.9.9"),
    ]


def test_aggregate_by_ip():
    stats = aggregate_by_ip(make_events())

    assert stats["1.2.3.4"]["failed"] == 2
    assert stats["1.2.3.4"]["invalid_user"] == 2
    assert stats["1.2.3.4"]["success"] == 1
    assert stats["1.2.3.4"]["users_tried"] == {"root", "admin", "test", "alice"}

    assert stats["5.6.7.8"]["failed"] == 1
    assert stats["9.9.9.9"]["success"] == 1


def test_detect_suspicious_ips_threshold():
    stats = aggregate_by_ip(make_events())

    assert detect_suspicious_ips(stats, threshold=4) == ["1.2.3.4"]
    assert detect_suspicious_ips(stats, threshold=1) == ["1.2.3.4", "5.6.7.8"]
    assert detect_suspicious_ips(stats, threshold=100) == []


def test_detect_suspicious_ips_sorted_by_failures_desc():
    stats = {
        "low": {"failed": 5, "invalid_user": 0, "success": 0, "users_tried": set()},
        "high": {"failed": 20, "invalid_user": 0, "success": 0, "users_tried": set()},
    }

    assert detect_suspicious_ips(stats, threshold=1) == ["high", "low"]


def test_build_summary():
    events = make_events()
    stats = aggregate_by_ip(events)
    summary = build_summary(events, stats, threshold=4)

    assert summary["total_events"] == 7
    assert summary["total_failed_attempts"] == 5
    assert summary["total_successful_logins"] == 2
    assert summary["unique_ips"] == 3
    assert summary["suspicious_ips"] == ["1.2.3.4"]
    assert summary["top_attacker"] == "1.2.3.4"
    assert summary["top_attacker_attempts"] == 4
    assert summary["first_event"] == "Jan 17 10:00:00"
    assert summary["last_event"] == "Jan 17 10:02:00"
    assert summary["threshold_used"] == 4


def test_build_summary_no_events():
    summary = build_summary([], {}, threshold=10)

    assert summary["total_events"] == 0
    assert summary["suspicious_ips"] == []
    assert summary["top_attacker"] is None
    assert summary["top_attacker_attempts"] == 0
    assert summary["first_event"] is None
    assert summary["last_event"] is None


def test_build_recommendations_with_suspicious_ips():
    events = make_events()
    stats = aggregate_by_ip(events)
    summary = build_summary(events, stats, threshold=4)
    recs = build_recommendations(summary, stats)

    assert any("1.2.3.4" in rec for rec in recs)
    assert any("fail2ban" in rec for rec in recs)


def test_build_recommendations_without_suspicious_ips():
    summary = build_summary([], {}, threshold=10)
    recs = build_recommendations(summary, {})

    assert len(recs) == 1
    assert "Aucune activité suspecte" in recs[0]
