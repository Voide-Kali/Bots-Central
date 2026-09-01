#!/usr/bin/env python3
"""Utilitarios seguros para arquivos de estado do Kali Bunker."""

from __future__ import annotations

import json
import os
import secrets
from contextlib import contextmanager
from fcntl import LOCK_EX, LOCK_UN, flock
from pathlib import Path
from typing import Any, Iterator


@contextmanager
def exclusive_file_lock(path: Path, *, mode: int = 0o600) -> Iterator[None]:
    """Serializa atualizacoes entre processos sem seguir links simbolicos."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, mode)
    try:
        os.fchmod(fd, mode)
        flock(fd, LOCK_EX)
        yield
    finally:
        flock(fd, LOCK_UN)
        os.close(fd)


def atomic_write_json(path: Path, payload: Any, *, mode: int = 0o600) -> None:
    """Grava JSON via arquivo temporario unico e replace atomico."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(temporary, flags, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(temporary, mode)
        temporary.replace(path)
        os.chmod(path, mode)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def read_json_counter(path: Path, key: str) -> int | None:
    """Le um contador inteiro nao negativo; estado ausente/corrompido vira None."""
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            data = json.load(stream)
        value = data.get(key) if isinstance(data, dict) else None
        if not isinstance(value, int) or isinstance(value, bool):
            return None
        parsed = value
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return parsed if parsed >= 0 else None


def claim_monotonic_json_counter(path: Path, key: str, candidate: int) -> tuple[bool, int]:
    """Persiste e reivindica um contador apenas quando ele avanca.

    O lock torna a reivindicacao atomica entre processos. O retorno informa se o
    candidato foi aceito e qual valor ficou persistido.
    """
    if not isinstance(candidate, int) or isinstance(candidate, bool) or candidate < 0:
        raise ValueError("contador deve ser um inteiro nao negativo")

    lock_path = path.with_name(f".{path.name}.lock")
    with exclusive_file_lock(lock_path):
        current = read_json_counter(path, key)
        if current is None and path.exists():
            raise ValueError("arquivo de contador existente esta corrompido ou inseguro")
        if current is not None and candidate <= current:
            return False, current
        atomic_write_json(path, {key: candidate})
        return True, candidate
