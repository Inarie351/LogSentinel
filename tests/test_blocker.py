import subprocess
from unittest.mock import patch

from logsentinel.blocker import block_ip


def test_block_ip_invalid_address():
    success, message = block_ip("not-an-ip")

    assert success is False
    assert "n'est pas une adresse IP valide" in message


def test_block_ip_success():
    with patch("logsentinel.blocker.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
        success, message = block_ip("185.220.101.45")

    assert success is True
    assert "185.220.101.45" in message
    mock_run.assert_called_once_with(
        ["iptables", "-A", "INPUT", "-s", "185.220.101.45", "-j", "DROP"],
        check=True,
        capture_output=True,
        text=True,
    )


def test_block_ip_iptables_missing():
    with patch("logsentinel.blocker.subprocess.run", side_effect=FileNotFoundError()):
        success, message = block_ip("185.220.101.45")

    assert success is False
    assert "iptables introuvable" in message


def test_block_ip_command_fails():
    error = subprocess.CalledProcessError(1, ["iptables"], stderr="permission denied")
    with patch("logsentinel.blocker.subprocess.run", side_effect=error):
        success, message = block_ip("185.220.101.45")

    assert success is False
    assert "permission denied" in message
