#!/usr/bin/env python3
"""Manifesto e verificacao de integridade do runtime protegido.

O manifesto cobre apenas codigo, scripts, requisitos e unidades systemd. Segredos
(``.env``) e o ambiente virtual ficam deliberadamente fora dele.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterable


MANIFEST_FILENAME = "runtime-manifest.json"
MANIFEST_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_FILES = 512
ALLOWED_RUNTIME_MODES = {0o644, 0o755}
SYSTEMD_MODE = 0o644
FORBIDDEN_SUFFIXES = {".key", ".pem", ".p12", ".pfx", ".db", ".sqlite", ".sqlite3"}
FORBIDDEN_BASENAMES = {"credentials.json", "token.json", "secrets.json", "kali-bunker.env"}


class ManifestError(ValueError):
    """Manifesto inseguro, inconsistente ou fora do formato suportado."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_relative_path(raw: str, *, single_component: bool = False) -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise ManifestError("caminho relativo invalido")
    path = PurePosixPath(raw)
    if path.is_absolute() or path.as_posix() != raw:
        raise ManifestError("caminho nao canonico")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ManifestError("caminho contem travessia")
    if single_component and len(path.parts) != 1:
        raise ManifestError("unidade systemd deve usar somente o nome do arquivo")
    return raw


def manifest_path_allowed(raw: str) -> bool:
    name = PurePosixPath(raw).name.lower()
    if (
        raw == MANIFEST_FILENAME
        or name in FORBIDDEN_BASENAMES
        or name == ".env"
        or name.startswith(".env.")
    ):
        return False
    return PurePosixPath(name).suffix not in FORBIDDEN_SUFFIXES


def canonical_install_root(path: Path) -> Path:
    if not path.is_absolute() or path == Path("/") or ".." in path.parts:
        raise ManifestError("raiz de instalacao invalida")
    return path


def _checked_source(
    root: Path,
    relative: str,
    *,
    expected_uid: int,
    expected_gid: int,
    allowed_modes: set[int],
) -> tuple[Path, os.stat_result]:
    candidate = root / relative
    try:
        info = candidate.lstat()
    except OSError as error:
        raise ManifestError(f"arquivo de origem indisponivel: {relative}") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ManifestError(f"arquivo de origem nao e regular: {relative}")
    if info.st_uid != expected_uid or info.st_gid != expected_gid:
        raise ManifestError(f"proprietario inesperado na origem: {relative}")
    mode = stat.S_IMODE(info.st_mode)
    if mode not in allowed_modes:
        raise ManifestError(f"permissao inesperada na origem: {relative}")
    return candidate, info


def _manifest_entry(
    kind: str,
    relative: str,
    source_root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, object]:
    single_component = kind == "systemd"
    relative = canonical_relative_path(relative, single_component=single_component)
    if not manifest_path_allowed(relative):
        raise ManifestError(f"arquivo sensivel nao pode entrar no manifesto: {relative}")
    allowed_modes = {SYSTEMD_MODE} if single_component else ALLOWED_RUNTIME_MODES
    source, info = _checked_source(
        source_root,
        relative,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        allowed_modes=allowed_modes,
    )
    return {
        "kind": kind,
        "path": relative,
        "sha256": sha256_file(source),
        "size": info.st_size,
        "mode": stat.S_IMODE(info.st_mode),
        "uid": expected_uid,
        "gid": expected_gid,
    }


def create_runtime_manifest(
    *,
    runtime_source_root: Path,
    runtime_install_root: Path,
    runtime_files: Iterable[str],
    systemd_source_root: Path,
    systemd_install_root: Path,
    systemd_files: Iterable[str],
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> dict[str, object]:
    """Cria em memoria um manifesto a partir de listas explicitas e canonicas."""

    runtime_install_root = canonical_install_root(runtime_install_root)
    systemd_install_root = canonical_install_root(systemd_install_root)
    for source_root in (runtime_source_root, systemd_source_root):
        try:
            root_info = source_root.lstat()
        except OSError as error:
            raise ManifestError("raiz de origem indisponivel") from error
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            raise ManifestError("raiz de origem deve ser um diretorio real")

    entries: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for kind, root, names in (
        ("runtime", runtime_source_root, runtime_files),
        ("systemd", systemd_source_root, systemd_files),
    ):
        for name in names:
            canonical = canonical_relative_path(name, single_component=kind == "systemd")
            identity = (kind, canonical)
            if identity in seen:
                raise ManifestError(f"entrada duplicada: {kind}/{canonical}")
            seen.add(identity)
            entries.append(
                _manifest_entry(
                    kind,
                    canonical,
                    root,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
            )

    if not entries or len(entries) > MAX_MANIFEST_FILES:
        raise ManifestError("quantidade invalida de arquivos no manifesto")
    entries.sort(key=lambda item: (str(item["kind"]), str(item["path"])))
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "algorithm": "sha256",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runtime_dir": str(runtime_install_root),
        "systemd_dir": str(systemd_install_root),
        "files": entries,
    }


def write_runtime_manifest(destination: Path, payload: dict[str, object]) -> None:
    """Grava o manifesto por substituicao atomica, sem seguir link no destino."""

    destination.parent.mkdir(parents=False, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, ensure_ascii=False, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _problem(path: str, reason: str) -> dict[str, str]:
    return {"path": path, "reason": reason}


def _integrity_result(
    *,
    ok: bool,
    status: str,
    manifest_path: Path,
    checked_files: int = 0,
    problems: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "ok": ok,
        "status": status,
        "manifest": str(manifest_path),
        "checked_files": checked_files,
        "problems": problems or [],
    }


def verify_runtime_integrity(
    manifest_path: Path | None = None,
    *,
    expected_owner_uid: int = 0,
    expected_owner_gid: int = 0,
    expected_runtime_dir: Path | None = None,
    expected_systemd_dir: Path | None = None,
) -> dict[str, object]:
    """Verifica manifesto, ownership, modos, tipo e SHA-256 sem expor conteudo."""

    configured_runtime = Path(
        os.environ.get("KALI_BUNKER_RUNTIME_DIR", "/opt/kali-bunker")
    )
    manifest_path = manifest_path or configured_runtime / MANIFEST_FILENAME
    expected_runtime_dir = expected_runtime_dir or manifest_path.parent
    expected_systemd_dir = expected_systemd_dir or Path("/etc/systemd/system")
    problems: list[dict[str, str]] = []

    try:
        manifest_info = manifest_path.lstat()
    except FileNotFoundError:
        return _integrity_result(
            ok=False,
            status="missing_manifest",
            manifest_path=manifest_path,
            problems=[_problem(MANIFEST_FILENAME, "manifesto ausente")],
        )
    except OSError:
        return _integrity_result(
            ok=False,
            status="invalid_manifest",
            manifest_path=manifest_path,
            problems=[_problem(MANIFEST_FILENAME, "manifesto inacessivel")],
        )

    manifest_mode = stat.S_IMODE(manifest_info.st_mode)
    if stat.S_ISLNK(manifest_info.st_mode) or not stat.S_ISREG(manifest_info.st_mode):
        problems.append(_problem(MANIFEST_FILENAME, "manifesto nao e arquivo regular"))
    if manifest_info.st_uid != expected_owner_uid or manifest_info.st_gid != expected_owner_gid:
        problems.append(_problem(MANIFEST_FILENAME, "proprietario inesperado"))
    if manifest_mode != 0o644:
        problems.append(_problem(MANIFEST_FILENAME, "permissao diferente de 0644"))
    if manifest_info.st_size > MAX_MANIFEST_BYTES:
        problems.append(_problem(MANIFEST_FILENAME, "manifesto excede o limite de tamanho"))
    if problems:
        return _integrity_result(
            ok=False,
            status="invalid_manifest",
            manifest_path=manifest_path,
            problems=problems,
        )

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _integrity_result(
            ok=False,
            status="invalid_manifest",
            manifest_path=manifest_path,
            problems=[_problem(MANIFEST_FILENAME, "conteudo invalido")],
        )

    if not isinstance(payload, dict):
        problems.append(_problem(MANIFEST_FILENAME, "estrutura invalida"))
        payload = {}
    if payload.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        problems.append(_problem(MANIFEST_FILENAME, "versao nao suportada"))
    if payload.get("algorithm") != "sha256":
        problems.append(_problem(MANIFEST_FILENAME, "algoritmo nao suportado"))

    try:
        runtime_root = canonical_install_root(Path(str(payload.get("runtime_dir", ""))))
        systemd_root = canonical_install_root(Path(str(payload.get("systemd_dir", ""))))
        expected_runtime = canonical_install_root(expected_runtime_dir)
        expected_systemd = canonical_install_root(expected_systemd_dir)
    except ManifestError:
        problems.append(_problem(MANIFEST_FILENAME, "raiz de instalacao invalida"))
        runtime_root = expected_runtime_dir
        systemd_root = expected_systemd_dir
        expected_runtime = expected_runtime_dir
        expected_systemd = expected_systemd_dir
    if runtime_root != expected_runtime:
        problems.append(_problem(MANIFEST_FILENAME, "raiz do runtime inesperada"))
    if systemd_root != expected_systemd:
        problems.append(_problem(MANIFEST_FILENAME, "raiz do systemd inesperada"))

    for label, root in (("runtime", runtime_root), ("systemd", systemd_root)):
        try:
            root_info = root.lstat()
        except OSError:
            problems.append(_problem(label, "diretorio ausente ou inacessivel"))
            continue
        if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
            problems.append(_problem(label, "raiz nao e diretorio real"))
        if root_info.st_uid != expected_owner_uid or root_info.st_gid != expected_owner_gid:
            problems.append(_problem(label, "proprietario da raiz inesperado"))
        if stat.S_IMODE(root_info.st_mode) & 0o022:
            problems.append(_problem(label, "raiz permite escrita fora do proprietario"))

    entries = payload.get("files")
    if not isinstance(entries, list) or not entries or len(entries) > MAX_MANIFEST_FILES:
        problems.append(_problem(MANIFEST_FILENAME, "lista de arquivos invalida"))
        entries = []

    seen: set[tuple[str, str]] = set()
    checked = 0
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            problems.append(_problem(MANIFEST_FILENAME, "entrada de arquivo invalida"))
            continue
        kind = raw_entry.get("kind")
        relative = raw_entry.get("path")
        if kind not in {"runtime", "systemd"} or not isinstance(relative, str):
            problems.append(_problem(MANIFEST_FILENAME, "entrada de arquivo invalida"))
            continue
        try:
            canonical_relative_path(relative, single_component=kind == "systemd")
        except ManifestError:
            problems.append(_problem(MANIFEST_FILENAME, "caminho de arquivo invalido"))
            continue
        if not manifest_path_allowed(relative):
            problems.append(_problem(MANIFEST_FILENAME, "entrada sensivel recusada"))
            continue
        identity = (kind, relative)
        if identity in seen:
            problems.append(_problem(f"{kind}/{relative}", "entrada duplicada"))
            continue
        seen.add(identity)

        display_path = f"{kind}/{relative}"
        expected_hash = raw_entry.get("sha256")
        expected_size = raw_entry.get("size")
        expected_mode = raw_entry.get("mode")
        entry_uid = raw_entry.get("uid")
        entry_gid = raw_entry.get("gid")
        allowed_modes = {SYSTEMD_MODE} if kind == "systemd" else ALLOWED_RUNTIME_MODES
        if (
            not isinstance(expected_hash, str)
            or len(expected_hash) != 64
            or any(character not in "0123456789abcdef" for character in expected_hash)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or expected_mode not in allowed_modes
            or entry_uid != expected_owner_uid
            or entry_gid != expected_owner_gid
        ):
            problems.append(_problem(display_path, "metadados invalidos"))
            continue

        root = runtime_root if kind == "runtime" else systemd_root
        target = root / relative
        try:
            info = target.lstat()
        except FileNotFoundError:
            problems.append(_problem(display_path, "arquivo ausente"))
            continue
        except OSError:
            problems.append(_problem(display_path, "arquivo inacessivel"))
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            problems.append(_problem(display_path, "tipo de arquivo inseguro"))
            continue
        checked += 1
        if info.st_uid != expected_owner_uid or info.st_gid != expected_owner_gid:
            problems.append(_problem(display_path, "proprietario alterado"))
            continue
        if stat.S_IMODE(info.st_mode) != expected_mode:
            problems.append(_problem(display_path, "permissao alterada"))
            continue
        if info.st_size != expected_size:
            problems.append(_problem(display_path, "tamanho alterado"))
            continue
        try:
            actual_hash = sha256_file(target)
        except OSError:
            problems.append(_problem(display_path, "arquivo inacessivel"))
            continue
        if actual_hash != expected_hash:
            problems.append(_problem(display_path, "conteudo alterado"))

    return _integrity_result(
        ok=not problems,
        status="ok" if not problems else "mismatch",
        manifest_path=manifest_path,
        checked_files=checked,
        problems=problems[:64],
    )


def describe_integrity(result: dict[str, object]) -> str:
    if result.get("ok"):
        return f"{result.get('checked_files', 0)} arquivo(s) verificado(s)"
    problems = result.get("problems")
    if not isinstance(problems, list) or not problems:
        return "falha de integridade sem detalhes"
    summaries = []
    for problem in problems[:3]:
        if isinstance(problem, dict):
            summaries.append(f"{problem.get('path', '?')}: {problem.get('reason', 'falha')}")
    suffix = "" if len(problems) <= 3 else f"; e mais {len(problems) - 3}"
    return "; ".join(summaries) + suffix


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verifica o runtime protegido do Kali Bunker")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = verify_runtime_integrity(args.manifest)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        prefix = "OK" if result["ok"] else "FALHA"
        print(f"{prefix}: {describe_integrity(result)}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
