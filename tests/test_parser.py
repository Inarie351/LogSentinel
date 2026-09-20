import os

from logsentinel.parser import parse_line, parse_log_file

SAMPLE_LOG = os.path.join(
    os.path.dirname(__file__), "..", "sample_logs", "auth.log.sample"
)


def test_parse_line_failed_password():
    line = "Jan 17 10:22:11 server sshd[1350]: Failed password for root from 185.220.101.45 port 51234 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "failed"
    assert event.user == "root"
    assert event.ip == "185.220.101.45"
    assert event.port == "51234"


def test_parse_line_invalid_user():
    line = "Jan 17 10:22:14 server sshd[1352]: Failed password for invalid user admin from 185.220.101.45 port 51236 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "invalid_user"
    assert event.user == "admin"
    assert event.ip == "185.220.101.45"


def test_parse_line_accepted_publickey():
    line = "Jan 17 10:20:01 server sshd[1201]: Accepted publickey for kimberly from 192.168.1.5 port 51290 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "success"
    assert event.user == "kimberly"
    assert event.ip == "192.168.1.5"


def test_parse_line_accepted_password():
    line = "Jan 17 10:45:00 server sshd[1500]: Accepted password for kimberly from 192.168.1.5 port 51300 ssh2"
    event = parse_line(line)

    assert event is not None
    assert event.event_type == "success"


def test_parse_line_no_match_returns_none():
    assert parse_line("Jan 17 10:20:01 server systemd[1]: Starting some unrelated service") is None
    assert parse_line("") is None


def test_parse_log_file_sample():
    events = parse_log_file(SAMPLE_LOG)

    assert len(events) == 27
    assert sum(1 for e in events if e.event_type == "success") == 3
    assert sum(1 for e in events if e.event_type in ("failed", "invalid_user")) == 24
    assert {e.ip for e in events} == {
        "192.168.1.5",
        "185.220.101.45",
        "10.0.0.12",
        "45.155.204.19",
    }
