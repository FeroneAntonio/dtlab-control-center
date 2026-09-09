"""Windows Credential Manager access for the Cyber Vision read-only API token."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import keyring

SERVICE_NAME = "DTLab Control Center - Cisco Cyber Vision"
ACCOUNT_NAME = "read-only-api-token"
NEW_UI_SERVICE_NAME = "DTLab Control Center - Cisco Cyber Vision New UI"
ESXI_SERVICE_NAME = "DTLab Control Center - VMware ESXi"
CREDENTIAL_FILE_ENV = "DTLAB_CREDENTIAL_FILE"


class CredentialError(RuntimeError):
    """Credential Manager is unavailable or the stored token is invalid."""


def _credential_file_payload() -> dict[str, Any] | None:
    raw_path = os.environ.get(CREDENTIAL_FILE_ENV, "").strip()
    if not raw_path:
        return None
    path = Path(raw_path).expanduser().resolve()
    try:
        metadata = path.stat()
    except OSError as exc:
        raise CredentialError("File credenziali runtime non disponibile.") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise CredentialError("Il percorso credenziali runtime non è un file regolare.")
    if os.name == "posix" and metadata.st_mode & 0o027:
        raise CredentialError("Permessi file credenziali runtime troppo aperti.")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CredentialError("File credenziali runtime non valido.") from exc
    if not isinstance(payload, dict):
        raise CredentialError("File credenziali runtime non valido.")
    return payload


def _file_secret(key: str) -> str | None:
    payload = _credential_file_payload()
    if payload is None:
        return None
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise CredentialError("Segreto runtime richiesto non configurato.")
    return value


def _normalize_token(token: str) -> str:
    value = token.strip()
    if not value:
        raise CredentialError("Il token non può essere vuoto.")
    if any(character.isspace() for character in value):
        raise CredentialError("Il token non può contenere spazi.")
    return value


def save_token(token: str) -> None:
    """Persist a token in the OS credential vault, never in project files."""

    try:
        keyring.set_password(SERVICE_NAME, ACCOUNT_NAME, _normalize_token(token))
    except keyring.errors.KeyringError as exc:
        raise CredentialError("Windows Credential Manager non disponibile.") from exc


def save_new_ui_token(token: str) -> None:
    """Persist the separate New UI API token in the OS credential vault."""

    try:
        keyring.set_password(
            NEW_UI_SERVICE_NAME,
            ACCOUNT_NAME,
            _normalize_token(token),
        )
    except keyring.errors.KeyringError as exc:
        raise CredentialError("Windows Credential Manager non disponibile.") from exc


def load_token() -> str:
    file_token = _file_secret("cybervision_classic_token")
    if file_token is not None:
        return _normalize_token(file_token)
    try:
        token = keyring.get_password(SERVICE_NAME, ACCOUNT_NAME)
    except keyring.errors.KeyringError as exc:
        raise CredentialError("Windows Credential Manager non disponibile.") from exc
    if token is None:
        raise CredentialError("Token Cyber Vision read-only non configurato.")
    return _normalize_token(token)


def load_new_ui_token() -> str:
    file_token = _file_secret("cybervision_new_ui_token")
    if file_token is not None:
        return _normalize_token(file_token)
    try:
        token = keyring.get_password(NEW_UI_SERVICE_NAME, ACCOUNT_NAME)
    except keyring.errors.KeyringError as exc:
        raise CredentialError("Windows Credential Manager non disponibile.") from exc
    if token is None:
        raise CredentialError("Token Cyber Vision New UI read-only non configurato.")
    return _normalize_token(token)


def token_is_configured() -> bool:
    try:
        load_token()
    except CredentialError:
        return False
    return True


def new_ui_token_is_configured() -> bool:
    try:
        load_new_ui_token()
    except CredentialError:
        return False
    return True


def delete_token() -> None:
    try:
        keyring.delete_password(SERVICE_NAME, ACCOUNT_NAME)
    except keyring.errors.PasswordDeleteError:
        return
    except keyring.errors.KeyringError as exc:
        raise CredentialError("Impossibile eliminare il token dal vault.") from exc


def delete_new_ui_token() -> None:
    try:
        keyring.delete_password(NEW_UI_SERVICE_NAME, ACCOUNT_NAME)
    except keyring.errors.PasswordDeleteError:
        return
    except keyring.errors.KeyringError as exc:
        raise CredentialError("Impossibile eliminare il token dal vault.") from exc


def save_esxi_password(username: str, password: str) -> None:
    account = username.strip()
    if not account:
        raise CredentialError("Username ESXi assente.")
    if not password:
        raise CredentialError("Password ESXi vuota.")
    try:
        keyring.set_password(ESXI_SERVICE_NAME, account, password)
    except keyring.errors.KeyringError as exc:
        raise CredentialError("Windows Credential Manager non disponibile.") from exc


def load_esxi_password(username: str) -> str:
    account = username.strip()
    if not account:
        raise CredentialError("Username ESXi assente.")
    payload = _credential_file_payload()
    if payload is not None:
        passwords = payload.get("esxi_passwords")
        if not isinstance(passwords, dict):
            raise CredentialError("Password ESXi runtime non configurata.")
        password = passwords.get(account)
        if not isinstance(password, str) or not password:
            raise CredentialError("Password ESXi runtime non configurata.")
        return password
    try:
        password = keyring.get_password(ESXI_SERVICE_NAME, account)
    except keyring.errors.KeyringError as exc:
        raise CredentialError("Windows Credential Manager non disponibile.") from exc
    if password is None:
        raise CredentialError("Password ESXi non configurata nel vault.")
    if not password:
        raise CredentialError("Password ESXi nel vault non valida.")
    return password


def esxi_password_is_configured(username: str) -> bool:
    try:
        load_esxi_password(username)
    except CredentialError:
        return False
    return True


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gestisce il token Cyber Vision nel vault di Windows."
    )
    parser.add_argument("action", choices=("set", "status", "delete"))
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.action == "status":
        print("configurato" if token_is_configured() else "non configurato")
        return 0
    if args.action == "set":
        save_token(getpass.getpass("Token API Cyber Vision read-only: "))
        print("Token salvato in Windows Credential Manager.")
        return 0
    delete_token()
    print("Token eliminato da Windows Credential Manager.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
