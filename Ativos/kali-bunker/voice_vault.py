#!/usr/bin/env python3
"""Cofre local criptografado para senhas da Voz."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import string
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

from bunker_audit import STATE_DIR


VAULT_FILE = STATE_DIR / "voice-password-vault.json"
VAULT_VERSION = 2
LEGACY_KDF_ITERATIONS = 260_000
KDF_ITERATIONS = 600_000
MIN_KDF_ITERATIONS = LEGACY_KDF_ITERATIONS
MIN_MASTER_PASSWORD_LENGTH = 14
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%&*_-+="


class VaultError(RuntimeError):
    pass


def vault_exists() -> bool:
    return VAULT_FILE.exists() and not VAULT_FILE.is_symlink()


def generate_password(length: int = 32) -> str:
    length = min(max(length, 16), 80)
    while True:
        password = "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))
        if (
            any(char.islower() for char in password)
            and any(char.isupper() for char in password)
            and any(char.isdigit() for char in password)
            and any(char in "!@#$%&*_-+=" for char in password)
        ):
            return password


def master_password_strength_errors(master_password: str) -> list[str]:
    errors = []
    if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
        errors.append(f"use pelo menos {MIN_MASTER_PASSWORD_LENGTH} caracteres")
    classes = [
        any(char.islower() for char in master_password),
        any(char.isupper() for char in master_password),
        any(char.isdigit() for char in master_password),
        any(char in string.punctuation for char in master_password),
    ]
    if sum(classes) < 3:
        errors.append("misture ao menos 3 tipos: minusculas, maiusculas, numeros e simbolos")
    if master_password.strip() != master_password:
        errors.append("nao comece nem termine com espaco")
    return errors


def validate_new_master_password(master_password: str) -> None:
    errors = master_password_strength_errors(master_password)
    if errors:
        raise VaultError("Senha mestra fraca: " + "; ".join(errors) + ".")


def _derive_keys(master_password: str, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    if not master_password:
        raise VaultError("Senha mestra vazia.")
    if iterations < MIN_KDF_ITERATIONS:
        raise VaultError("Arquivo do cofre usa parametros de derivacao inseguros.")
    key_material = hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        iterations,
        dklen=64,
    )
    return key_material[:32], key_material[32:]


def _openssl_aes_ctr(data: bytes, key: bytes, iv: bytes) -> bytes:
    try:
        result = subprocess.run(
            [
                "openssl",
                "enc",
                "-aes-256-ctr",
                "-K",
                key.hex(),
                "-iv",
                iv.hex(),
                "-nosalt",
            ],
            input=data,
            capture_output=True,
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VaultError(f"OpenSSL indisponivel: {exc}") from exc
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise VaultError(detail or "Falha no OpenSSL.")
    return result.stdout


def _mac_payload_v1(salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    return b"voice-vault-v1|" + salt + iv + ciphertext


def _mac_payload_v2(
    version: int,
    kdf: str,
    iterations: int,
    cipher: str,
    salt: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    metadata = json.dumps(
        {
            "version": version,
            "kdf": kdf,
            "iterations": iterations,
            "cipher": cipher,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return b"voice-vault-v2|" + metadata + b"|" + salt + iv + ciphertext


def _encrypt(master_password: str, payload: dict[str, Any]) -> dict[str, Any]:
    salt = os.urandom(32)
    iv = os.urandom(16)
    enc_key, mac_key = _derive_keys(master_password, salt, KDF_ITERATIONS)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ciphertext = _openssl_aes_ctr(plaintext, enc_key, iv)
    cipher = "aes-256-ctr+hmac-sha256"
    kdf = "pbkdf2-sha256"
    tag = hmac.new(
        mac_key,
        _mac_payload_v2(VAULT_VERSION, kdf, KDF_ITERATIONS, cipher, salt, iv, ciphertext),
        hashlib.sha256,
    ).digest()
    return {
        "version": VAULT_VERSION,
        "kdf": kdf,
        "iterations": KDF_ITERATIONS,
        "cipher": cipher,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "mac": base64.b64encode(tag).decode("ascii"),
    }


def _decrypt(master_password: str, envelope: dict[str, Any]) -> dict[str, Any]:
    try:
        version = int(envelope.get("version", 1))
        kdf = str(envelope.get("kdf", "pbkdf2-sha256"))
        cipher = str(envelope.get("cipher", "aes-256-ctr+hmac-sha256"))
        iterations = int(envelope.get("iterations", LEGACY_KDF_ITERATIONS))
        salt = base64.b64decode(str(envelope["salt"]), validate=True)
        iv = base64.b64decode(str(envelope["iv"]), validate=True)
        ciphertext = base64.b64decode(str(envelope["ciphertext"]), validate=True)
        expected_tag = base64.b64decode(str(envelope["mac"]), validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultError("Arquivo do cofre invalido.") from exc
    if version not in {1, 2} or kdf != "pbkdf2-sha256" or cipher != "aes-256-ctr+hmac-sha256":
        raise VaultError("Arquivo do cofre usa formato criptografico desconhecido.")
    if len(salt) not in {16, 32} or len(iv) != 16 or len(expected_tag) != 32:
        raise VaultError("Arquivo do cofre invalido.")

    enc_key, mac_key = _derive_keys(master_password, salt, iterations)
    if version == 1:
        mac_payload = _mac_payload_v1(salt, iv, ciphertext)
    else:
        mac_payload = _mac_payload_v2(version, kdf, iterations, cipher, salt, iv, ciphertext)
    actual_tag = hmac.new(mac_key, mac_payload, hashlib.sha256).digest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        raise VaultError("Senha mestra incorreta ou cofre alterado.")

    plaintext = _openssl_aes_ctr(ciphertext, enc_key, iv)
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultError("Nao consegui decifrar o cofre.") from exc
    if not isinstance(payload, dict):
        raise VaultError("Conteudo do cofre invalido.")
    return payload


def _empty_payload() -> dict[str, Any]:
    return {"created_at": _now(), "updated_at": _now(), "entries": []}


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _ensure_private_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise VaultError("Diretorio do cofre aponta para link simbolico.")
    try:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
    except OSError as exc:
        raise VaultError("Nao consegui proteger o diretorio do cofre.") from exc


def _secure_existing_vault_file() -> None:
    if VAULT_FILE.is_symlink():
        raise VaultError("Cofre aponta para link simbolico; abertura recusada por seguranca.")
    if not VAULT_FILE.exists():
        return
    try:
        info = os.stat(VAULT_FILE, follow_symlinks=False)
    except OSError as exc:
        raise VaultError("Nao consegui validar o arquivo do cofre.") from exc
    if not stat.S_ISREG(info.st_mode):
        raise VaultError("Cofre nao e um arquivo regular.")
    if os.geteuid() != 0 and info.st_uid != os.geteuid():
        raise VaultError("Cofre pertence a outro usuario.")
    if info.st_mode & 0o077:
        try:
            os.chmod(VAULT_FILE, 0o600)
        except OSError as exc:
            raise VaultError("Cofre esta com permissoes inseguras.") from exc


def _read_vault_text() -> str:
    _ensure_private_directory(VAULT_FILE.parent)
    _secure_existing_vault_file()
    return VAULT_FILE.read_text(encoding="utf-8")


def _write_vault_envelope(envelope: dict[str, Any]) -> None:
    _ensure_private_directory(VAULT_FILE.parent)
    _secure_existing_vault_file()
    temporary = VAULT_FILE.with_name(f".{VAULT_FILE.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(temporary, flags, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(envelope, stream, ensure_ascii=False, indent=2)
        os.chmod(temporary, 0o600)
        temporary.replace(VAULT_FILE)
        os.chmod(VAULT_FILE, 0o600)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise VaultError("Nao consegui gravar o cofre com seguranca.") from exc


def load_vault(master_password: str) -> dict[str, Any]:
    if not VAULT_FILE.exists():
        return _empty_payload()
    try:
        envelope = json.loads(_read_vault_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise VaultError("Nao consegui ler o cofre.") from exc
    if not isinstance(envelope, dict):
        raise VaultError("Arquivo do cofre invalido.")
    payload = _decrypt(master_password, envelope)
    payload.setdefault("entries", [])
    return payload


def save_vault(master_password: str, payload: dict[str, Any], enforce_master_strength: bool = False) -> None:
    if enforce_master_strength:
        validate_new_master_password(master_password)
    payload["updated_at"] = _now()
    envelope = _encrypt(master_password, payload)
    _write_vault_envelope(envelope)


def unlock(master_password: str) -> int:
    creating = not VAULT_FILE.exists()
    if creating:
        validate_new_master_password(master_password)
    payload = load_vault(master_password)
    if creating:
        save_vault(master_password, payload, enforce_master_strength=True)
    return len(payload.get("entries", []))


def list_entries(master_password: str) -> list[dict[str, str]]:
    payload = load_vault(master_password)
    entries = payload.get("entries", [])
    safe_entries = []
    for item in entries:
        safe_entries.append(
            {
                "label": str(item.get("label", "")),
                "username": str(item.get("username", "")),
                "url": str(item.get("url", "")),
                "updated_at": str(item.get("updated_at", "")),
            }
        )
    return sorted(safe_entries, key=lambda item: item["label"].lower())


def search_entries(master_password: str, query: str) -> list[dict[str, str]]:
    query = query.strip().lower()
    entries = list_entries(master_password)
    if not query:
        return entries
    matches = []
    for item in entries:
        searchable = " ".join(
            (
                item.get("label", ""),
                item.get("username", ""),
                item.get("url", ""),
            )
        ).lower()
        if query in searchable:
            matches.append(item)
    return matches


def find_entry(master_password: str, label: str) -> dict[str, str] | None:
    wanted = label.strip().lower()
    payload = load_vault(master_password)
    for item in payload.get("entries", []):
        if str(item.get("label", "")).strip().lower() == wanted:
            return {str(key): str(value) for key, value in item.items()}
    return None


def save_entry(
    master_password: str,
    label: str,
    username: str,
    password: str,
    url: str = "",
    notes: str = "",
) -> None:
    label = label.strip()
    if not label:
        raise VaultError("Nome do item vazio.")
    if not password:
        raise VaultError("Senha vazia.")
    if not VAULT_FILE.exists():
        validate_new_master_password(master_password)
    payload = load_vault(master_password)
    entries = payload.setdefault("entries", [])
    now = _now()
    new_item = {
        "label": label[:120],
        "username": username.strip()[:180],
        "password": password,
        "url": url.strip()[:300],
        "notes": notes.strip()[:1000],
        "updated_at": now,
    }
    for index, item in enumerate(entries):
        if str(item.get("label", "")).strip().lower() == label.lower():
            new_item["created_at"] = str(item.get("created_at", now))
            entries[index] = new_item
            save_vault(master_password, payload)
            return
    new_item["created_at"] = now
    entries.append(new_item)
    save_vault(master_password, payload)


def delete_entry(master_password: str, label: str) -> bool:
    wanted = label.strip().lower()
    payload = load_vault(master_password)
    entries = payload.get("entries", [])
    remaining = [item for item in entries if str(item.get("label", "")).strip().lower() != wanted]
    if len(remaining) == len(entries):
        return False
    payload["entries"] = remaining
    save_vault(master_password, payload)
    return True


def change_master_password(current_master_password: str, new_master_password: str) -> int:
    validate_new_master_password(new_master_password)
    payload = load_vault(current_master_password)
    save_vault(new_master_password, payload, enforce_master_strength=True)
    return len(payload.get("entries", []))
