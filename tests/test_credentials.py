from __future__ import annotations

import json
import os

import pytest

from dtlab.collector import credentials


def test_token_round_trip_uses_keyring_and_not_files(monkeypatch) -> None:
    vault: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        credentials.keyring,
        "set_password",
        lambda service, account, value: vault.__setitem__((service, account), value),
    )
    monkeypatch.setattr(
        credentials.keyring,
        "get_password",
        lambda service, account: vault.get((service, account)),
    )

    credentials.save_token("read-only-token")

    assert credentials.load_token() == "read-only-token"
    assert credentials.token_is_configured() is True


def test_new_ui_token_is_stored_separately(monkeypatch) -> None:
    vault: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        credentials.keyring,
        "set_password",
        lambda service, account, value: vault.__setitem__((service, account), value),
    )
    monkeypatch.setattr(
        credentials.keyring,
        "get_password",
        lambda service, account: vault.get((service, account)),
    )

    credentials.save_token("classic-read-only-token")
    credentials.save_new_ui_token("new-ui-read-only-token")

    assert credentials.load_token() == "classic-read-only-token"
    assert credentials.load_new_ui_token() == "new-ui-read-only-token"
    assert credentials.new_ui_token_is_configured() is True


def test_missing_token_has_generic_error(monkeypatch) -> None:
    monkeypatch.setattr(credentials.keyring, "get_password", lambda *_: None)

    with pytest.raises(credentials.CredentialError, match="non configurato"):
        credentials.load_token()


@pytest.mark.parametrize("value", ["", "   ", "token with spaces"])
def test_invalid_token_is_rejected_before_vault_write(monkeypatch, value: str) -> None:
    called = False

    def save(*_) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(credentials.keyring, "set_password", save)

    with pytest.raises(credentials.CredentialError):
        credentials.save_token(value)

    assert called is False


def test_runtime_credential_file_supports_headless_linux(tmp_path, monkeypatch) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps(
            {
                "cybervision_classic_token": "classic-runtime-token",
                "cybervision_new_ui_token": "new-ui-runtime-token",
                "esxi_passwords": {"example-readonly-user": "esxi-runtime-password"},
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o640)
    monkeypatch.setenv(credentials.CREDENTIAL_FILE_ENV, str(path))
    monkeypatch.setattr(
        credentials.keyring,
        "get_password",
        lambda *_: pytest.fail("il vault non deve essere interrogato"),
    )

    assert credentials.load_token() == "classic-runtime-token"
    assert credentials.load_new_ui_token() == "new-ui-runtime-token"
    assert credentials.load_esxi_password("example-readonly-user") == "esxi-runtime-password"


@pytest.mark.skipif(os.name != "posix", reason="i mode bit POSIX non sono affidabili su Windows")
def test_runtime_credential_file_rejects_open_permissions(tmp_path, monkeypatch) -> None:
    path = tmp_path / "credentials.json"
    path.write_text('{"cybervision_classic_token":"token"}', encoding="utf-8")
    path.chmod(0o644)
    monkeypatch.setenv(credentials.CREDENTIAL_FILE_ENV, str(path))

    with pytest.raises(credentials.CredentialError, match="troppo aperti"):
        credentials.load_token()
