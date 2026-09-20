from unittest.mock import MagicMock, patch

import pytest

pydantic = pytest.importorskip("pydantic")

from logsentinel.incidentbot import (  # noqa: E402
    IncidentReport,
    build_prompt,
    generate_incident_report,
    render_markdown,
)

SAMPLE_REPORT = {
    "summary": {
        "total_events": 27,
        "total_failed_attempts": 24,
        "total_successful_logins": 3,
        "unique_ips": 4,
        "suspicious_ips": ["185.220.101.45"],
        "top_attacker": "185.220.101.45",
        "top_attacker_attempts": 19,
        "first_event": "Jan 17 10:20:01",
        "last_event": "Jan 17 11:15:44",
        "threshold_used": 10,
    },
    "ip_details": {
        "185.220.101.45": {
            "failed": 7,
            "invalid_user": 12,
            "success": 0,
            "users_tried": ["admin", "root", "test"],
        },
        "10.0.0.12": {
            "failed": 3,
            "invalid_user": 0,
            "success": 0,
            "users_tried": ["admin"],
        },
    },
    "recommendations": ["Considérer le blocage de 185.220.101.45"],
}


def test_build_prompt_includes_only_suspicious_ips():
    prompt = build_prompt(SAMPLE_REPORT)

    assert "185.220.101.45" in prompt
    assert '"failed": 7' in prompt
    assert '"invalid_user": 12' in prompt
    # 10.0.0.12 is not in suspicious_ips, so it must not leak into the prompt
    assert "10.0.0.12" not in prompt


def test_build_prompt_includes_totals():
    prompt = build_prompt(SAMPLE_REPORT)

    assert '"evenements_analyses": 27' in prompt
    assert '"tentatives_echouees": 24' in prompt
    assert '"top_attaquant": "185.220.101.45"' in prompt


def test_render_markdown_format():
    incident = IncidentReport(
        severity="ÉLEVÉE",
        summary="Une attaque par force brute a été détectée.",
        priority_actions=["Bloquer l'IP", "Activer fail2ban"],
    )

    markdown = render_markdown(incident)

    assert "**Gravité globale : ÉLEVÉE**" in markdown
    assert "## Résumé" in markdown
    assert "Une attaque par force brute a été détectée." in markdown
    assert "1. Bloquer l'IP" in markdown
    assert "2. Activer fail2ban" in markdown


def test_incident_report_rejects_invalid_severity():
    with pytest.raises(pydantic.ValidationError):
        IncidentReport(severity="INCONNUE", summary="x", priority_actions=[])


anthropic = pytest.importorskip("anthropic")


def test_generate_incident_report_uses_structured_output():
    expected = IncidentReport(
        severity="ÉLEVÉE",
        summary="Résumé généré par le modèle.",
        priority_actions=["Bloquer 185.220.101.45"],
    )

    fake_response = MagicMock(parsed_output=expected)
    fake_client = MagicMock()
    fake_client.messages.parse.return_value = fake_response

    with patch.object(anthropic, "Anthropic", return_value=fake_client):
        result = generate_incident_report(SAMPLE_REPORT, model="claude-opus-5")

    assert result == expected
    _, kwargs = fake_client.messages.parse.call_args
    assert kwargs["model"] == "claude-opus-5"
    assert kwargs["output_format"] is IncidentReport


def test_generate_incident_report_missing_api_key_exits(capsys):
    # The SDK reports "no credentials resolvable" as a TypeError raised while
    # building request headers (no network call involved) - reproduce that
    # shape directly rather than depending on this machine's env/profile state.
    fake_client = MagicMock()
    fake_client.messages.parse.side_effect = TypeError(
        "Could not resolve authentication method."
    )

    with patch.object(anthropic, "Anthropic", return_value=fake_client):
        with pytest.raises(SystemExit) as exc_info:
            generate_incident_report(SAMPLE_REPORT)

    assert exc_info.value.code == 1
    assert "clé API Anthropic" in capsys.readouterr().err
