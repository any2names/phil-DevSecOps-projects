from datetime import UTC, datetime, timedelta

import pytest
from typer.testing import CliRunner

from platformctl import certs, config
from platformctl.adapters.base import Certificate
from platformctl.cli import app

NOW = datetime(2026, 9, 21, tzinfo=UTC)


def _cert(name: str, days: int) -> Certificate:
    return Certificate(
        name=name, subject=f"CN={name}", not_after=NOW + timedelta(days=days), source="test"
    )


def test_evaluate_statuses() -> None:
    out = certs.evaluate([_cert("ok", 90), _cert("soon", 10), _cert("dead", -1)], 30, now=NOW)
    assert [(c.name, c.status, c.days_remaining) for c in out] == [
        ("dead", "expired", -1),
        ("soon", "warning", 10),
        ("ok", "ok", 90),
    ]


def test_evaluate_boundary_is_warning() -> None:
    assert certs.evaluate([_cert("edge", 30)], warn_days=30, now=NOW)[0].status == "warning"


def test_parse_openssl_time() -> None:
    assert certs.parse_not_after("Sep 21 12:00:00 2030 GMT") == datetime(
        2030, 9, 21, 12, 0, tzinfo=UTC
    )


def test_probe_tls_failure_is_probe_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import socket

    def boom(*a: object, **k: object) -> None:
        raise OSError("refused")

    monkeypatch.setattr(socket, "create_connection", boom)
    with pytest.raises(certs.ProbeError):
        certs.probe_tls("localhost", 1)


def test_cli_certs_check_uses_adapter_and_skips_probe(
    settings: config.Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(settings.repo_root)
    from platformctl import adapters
    from platformctl.adapters.fake import FakeAdapter

    monkeypatch.setattr(
        adapters, "get_adapter", lambda s: FakeAdapter(certificates=[_cert("ok", 400)])
    )
    r = CliRunner().invoke(app, ["certs", "check", "--no-probe"])
    assert r.exit_code == 0, r.output
    monkeypatch.setattr(
        adapters, "get_adapter", lambda s: FakeAdapter(certificates=[_cert("soon", 3)])
    )
    r = CliRunner().invoke(app, ["certs", "check", "--no-probe"])
    assert r.exit_code == 1 and "warning" in r.output


def test_cli_certs_check_probe_failure_is_reported(
    settings: config.Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(settings.repo_root)
    (settings.repo_root / "platformctl.toml").write_text(
        'adapter = "fake"\n[[cert_targets]]\nhost = "localhost"\nport = 1\n'
    )
    monkeypatch.setattr(
        certs, "probe_tls", lambda h, p: (_ for _ in ()).throw(certs.ProbeError("x"))
    )
    r = CliRunner().invoke(app, ["certs", "check"])
    assert r.exit_code == 0 and "probe failed" in r.output
