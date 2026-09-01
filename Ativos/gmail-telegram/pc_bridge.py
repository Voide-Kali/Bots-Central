#!/usr/bin/env python3
"""Fila persistente que conecta o bot no servidor ao agente do computador.

O bot importa este módulo diretamente. O agente local acessa a mesma API pelo
subcomando CLI, transportado por uma conexão SSH já autorizada pelo usuário.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
DB_FILE = Path(os.environ.get("PC_BRIDGE_DB", BASE_DIR / "pc_bridge.db")).expanduser()
ARTIFACT_DIR = Path(
    os.environ.get("PC_BRIDGE_ARTIFACT_DIR", BASE_DIR / "runtime" / "pc-artifacts")
).expanduser()
DEFAULT_AGENT_ID = os.environ.get("PC_AGENT_ID", "kali-principal").strip() or "kali-principal"
AGENT_ONLINE_SECONDS = max(15, int(os.environ.get("PC_AGENT_ONLINE_SECONDS", "45")))
JOB_LEASE_SECONDS = max(60, int(os.environ.get("PC_JOB_LEASE_SECONDS", "900")))
MAX_RESULT_CHARS = max(1000, int(os.environ.get("PC_JOB_MAX_RESULT_CHARS", "12000")))
MAX_ARTIFACT_BYTES = max(1, int(os.environ.get("PC_JOB_MAX_ARTIFACT_MB", "45"))) * 1024 * 1024

AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,32}$")
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
VALID_ACTIONS = {
    "status",
    "shell",
    "network_scan",
    "webcam",
    "service",
    "service_logs",
    "lock",
    "unlock",
    "shutdown",
    "reboot",
    "suspend",
    "cleanup",
    "emergency",
    "send_path",
    "install_package",
}
FINAL_STATUSES = {"completed", "failed", "canceled"}
_SCHEMA_LOCK = threading.Lock()
_INITIALIZED_DB: Path | None = None


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_FILE, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 15000")
    return connection


def _json_object(value: Any, *, field: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} deve ser um objeto JSON")
    return value


def _agent_id(value: str) -> str:
    normalized = str(value).strip()
    if not AGENT_ID_RE.fullmatch(normalized):
        raise ValueError("identificador de agente inválido")
    return normalized


def _job_id(value: str) -> str:
    normalized = str(value).strip()
    if not JOB_ID_RE.fullmatch(normalized):
        raise ValueError("identificador de tarefa inválido")
    return normalized


def _decode_json(raw: str | None, *, fallback: dict[str, Any] | None = None) -> dict[str, Any]:
    if not raw:
        return dict(fallback or {})
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return dict(fallback or {})
    return value if isinstance(value, dict) else dict(fallback or {})


def _row_to_job(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    item = dict(row)
    item["payload"] = _decode_json(item.pop("payload_json", "{}"))
    item["cancel_requested"] = bool(item.get("cancel_requested"))
    item["notified"] = bool(item.get("notified"))
    return item


def init_db() -> None:
    global _INITIALIZED_DB
    current_db = DB_FILE
    if _INITIALIZED_DB == current_db and current_db.exists():
        return

    with _SCHEMA_LOCK:
        if _INITIALIZED_DB == current_db and current_db.exists():
            return
        DB_FILE.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
        connection = _connect()
        try:
            # journal_mode é persistente no arquivo; configure uma vez durante
            # inicialização em vez de renegociá-lo em toda conexão do hot path.
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
            CREATE TABLE IF NOT EXISTS pc_agents (
                agent_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL DEFAULT '',
                version TEXT NOT NULL DEFAULT '',
                metadata_json TEXT NOT NULL DEFAULT '{}',
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                last_error TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS pc_jobs (
                job_id TEXT PRIMARY KEY,
                target_agent TEXT NOT NULL,
                action TEXT NOT NULL,
                payload_json TEXT NOT NULL DEFAULT '{}',
                description TEXT NOT NULL DEFAULT '',
                requested_by TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'queued'
                    CHECK (status IN ('queued', 'running', 'completed', 'failed', 'canceled')),
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                result_text TEXT NOT NULL DEFAULT '',
                artifact_name TEXT,
                notified INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                started_at REAL,
                completed_at REAL,
                updated_at REAL NOT NULL,
                lease_until REAL
            );

            CREATE INDEX IF NOT EXISTS idx_pc_jobs_queue
            ON pc_jobs(target_agent, status, created_at);

            CREATE INDEX IF NOT EXISTS idx_pc_jobs_notifications
            ON pc_jobs(notified, status, completed_at);

            CREATE INDEX IF NOT EXISTS idx_pc_jobs_agent_recent
            ON pc_jobs(target_agent, created_at DESC);

            CREATE INDEX IF NOT EXISTS idx_pc_jobs_running_lease
            ON pc_jobs(status, lease_until);
                """
            )
            connection.commit()
        finally:
            connection.close()
        for path in (DB_FILE, ARTIFACT_DIR):
            try:
                path.chmod(0o600 if path.is_file() else 0o700)
            except OSError:
                pass
        _INITIALIZED_DB = current_db


def _upsert_agent(
    connection: sqlite3.Connection,
    agent_id: str,
    metadata: dict[str, Any],
    *,
    now: float,
    last_error: str = "",
) -> None:
    hostname = str(metadata.get("hostname", ""))[:120]
    version = str(metadata.get("version", ""))[:40]
    encoded = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
    connection.execute(
        """
        INSERT INTO pc_agents (
            agent_id, hostname, version, metadata_json,
            first_seen, last_seen, last_error
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(agent_id) DO UPDATE SET
            hostname = excluded.hostname,
            version = excluded.version,
            metadata_json = excluded.metadata_json,
            last_seen = excluded.last_seen,
            last_error = excluded.last_error
        """,
        (agent_id, hostname, version, encoded, now, now, str(last_error)[:500]),
    )


def heartbeat_agent(
    agent_id: str,
    metadata: dict[str, Any] | None = None,
    *,
    last_error: str = "",
    now: float | None = None,
) -> dict[str, Any]:
    init_db()
    normalized_id = _agent_id(agent_id)
    normalized_metadata = _json_object(metadata, field="metadata")
    timestamp = time.time() if now is None else float(now)
    connection = _connect()
    try:
        _upsert_agent(
            connection,
            normalized_id,
            normalized_metadata,
            now=timestamp,
            last_error=last_error,
        )
        connection.commit()
    finally:
        connection.close()
    return {"ok": True, "server_time": timestamp}


def enqueue_job(
    action: str,
    payload: dict[str, Any] | None = None,
    *,
    description: str = "",
    requested_by: str = "",
    target_agent: str = DEFAULT_AGENT_ID,
    now: float | None = None,
) -> dict[str, Any]:
    init_db()
    normalized_action = str(action).strip().lower()
    if normalized_action not in VALID_ACTIONS:
        raise ValueError(f"ação não suportada pelo agente: {normalized_action}")
    normalized_payload = _json_object(payload, field="payload")
    normalized_agent = _agent_id(target_agent)
    timestamp = time.time() if now is None else float(now)
    encoded_payload = json.dumps(normalized_payload, ensure_ascii=False, separators=(",", ":"))
    connection = _connect()
    try:
        for _ in range(8):
            job_id = secrets.token_urlsafe(9).rstrip("=")
            try:
                connection.execute(
                    """
                    INSERT INTO pc_jobs (
                        job_id, target_agent, action, payload_json,
                        description, requested_by, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        job_id,
                        normalized_agent,
                        normalized_action,
                        encoded_payload,
                        str(description)[:2000],
                        str(requested_by)[:160],
                        timestamp,
                        timestamp,
                    ),
                )
                connection.commit()
                row = connection.execute(
                    "SELECT * FROM pc_jobs WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
                return _row_to_job(row) or {"job_id": job_id, "status": "queued"}
            except sqlite3.IntegrityError:
                continue
    finally:
        connection.close()
    raise RuntimeError("não foi possível gerar um ID para a tarefa")


def _recover_expired_jobs(connection: sqlite3.Connection, timestamp: float) -> None:
    connection.execute(
        """
        UPDATE pc_jobs
        SET status = CASE WHEN cancel_requested = 1 THEN 'canceled' ELSE 'queued' END,
            completed_at = CASE WHEN cancel_requested = 1 THEN ? ELSE completed_at END,
            result_text = CASE
                WHEN cancel_requested = 1 AND result_text = '' THEN 'Cancelada antes de concluir.'
                ELSE result_text
            END,
            updated_at = ?, lease_until = NULL
        WHERE status = 'running' AND lease_until IS NOT NULL AND lease_until <= ?
        """,
        (timestamp, timestamp, timestamp),
    )


def claim_job(
    agent_id: str,
    metadata: dict[str, Any] | None = None,
    *,
    lease_seconds: int = JOB_LEASE_SECONDS,
    now: float | None = None,
    update_agent: bool = True,
) -> dict[str, Any] | None:
    init_db()
    normalized_id = _agent_id(agent_id)
    normalized_metadata = _json_object(metadata, field="metadata")
    timestamp = time.time() if now is None else float(now)
    lease = max(60, int(lease_seconds))
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        if update_agent:
            _upsert_agent(connection, normalized_id, normalized_metadata, now=timestamp)
        _recover_expired_jobs(connection, timestamp)
        row = connection.execute(
            """
            SELECT * FROM pc_jobs
            WHERE target_agent = ? AND status = 'queued'
            ORDER BY created_at, job_id
            LIMIT 1
            """,
            (normalized_id,),
        ).fetchone()
        if row is None:
            connection.commit()
            return None
        cursor = connection.execute(
            """
            UPDATE pc_jobs
            SET status = 'running', started_at = COALESCE(started_at, ?),
                updated_at = ?, lease_until = ?
            WHERE job_id = ? AND status = 'queued'
            """,
            (timestamp, timestamp, timestamp + lease, row["job_id"]),
        )
        if cursor.rowcount != 1:
            connection.rollback()
            return None
        connection.commit()
        claimed = connection.execute(
            "SELECT * FROM pc_jobs WHERE job_id = ?",
            (row["job_id"],),
        ).fetchone()
        return _row_to_job(claimed)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _queued_job_exists(agent_id: str) -> bool:
    normalized_agent = _agent_id(agent_id)
    connection = _connect()
    try:
        row = connection.execute(
            """
            SELECT 1 FROM pc_jobs
            WHERE target_agent = ? AND status = 'queued'
            LIMIT 1
            """,
            (normalized_agent,),
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def wait_for_job(
    agent_id: str,
    metadata: dict[str, Any] | None = None,
    *,
    lease_seconds: int = JOB_LEASE_SECONDS,
    wait_seconds: int = 0,
    interval_seconds: float = 1.0,
) -> dict[str, Any] | None:
    """Long-poll local no servidor com leitura barata enquanto a fila está vazia."""
    wait = max(0, min(int(wait_seconds), 60))
    interval = max(0.2, min(float(interval_seconds), 5.0))
    deadline = time.monotonic() + wait

    # Primeiro claim atualiza heartbeat/metadata e também recupera leases vencidos.
    job = claim_job(
        agent_id,
        metadata,
        lease_seconds=lease_seconds,
        update_agent=True,
    )
    if job is not None or wait <= 0:
        return job

    # Enquanto o agente espera, evite BEGIN IMMEDIATE em cada tick. A maioria
    # absoluta dos ticks ociosos vira um SELECT indexado. A cada ~5 s fazemos
    # um claim completo para preservar recuperação de leases expirados.
    next_recovery = time.monotonic() + min(5.0, max(interval, 1.0))
    while True:
        now = time.monotonic()
        if now >= deadline:
            return None

        if _queued_job_exists(agent_id) or now >= next_recovery:
            job = claim_job(
                agent_id,
                None,
                lease_seconds=lease_seconds,
                update_agent=False,
            )
            if job is not None:
                return job
            next_recovery = time.monotonic() + min(5.0, max(interval, 1.0))

        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))


def renew_job(
    job_id: str,
    agent_id: str,
    *,
    lease_seconds: int = JOB_LEASE_SECONDS,
    now: float | None = None,
) -> dict[str, Any]:
    normalized_job = _job_id(job_id)
    normalized_agent = _agent_id(agent_id)
    timestamp = time.time() if now is None else float(now)
    lease = max(60, int(lease_seconds))
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """
            SELECT cancel_requested FROM pc_jobs
            WHERE job_id = ? AND target_agent = ? AND status = 'running'
            """,
            (normalized_job, normalized_agent),
        ).fetchone()
        if row is None:
            connection.rollback()
            return {"valid": False, "cancel_requested": True}
        connection.execute(
            "UPDATE pc_jobs SET updated_at = ?, lease_until = ? WHERE job_id = ?",
            (timestamp, timestamp + lease, normalized_job),
        )
        connection.commit()
        return {"valid": True, "cancel_requested": bool(row["cancel_requested"])}
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def complete_job(
    job_id: str,
    agent_id: str,
    *,
    ok: bool,
    result_text: str = "",
    artifact_name: str | None = None,
    canceled: bool = False,
    now: float | None = None,
) -> bool:
    normalized_job = _job_id(job_id)
    normalized_agent = _agent_id(agent_id)
    timestamp = time.time() if now is None else float(now)
    normalized_artifact: str | None = None
    if artifact_name:
        candidate = Path(str(artifact_name)).name
        if candidate != str(artifact_name) or not ARTIFACT_NAME_RE.fullmatch(candidate):
            raise ValueError("nome de artefato inválido")
        artifact_path = ARTIFACT_DIR / candidate
        if not artifact_path.is_file() or artifact_path.is_symlink():
            raise ValueError("artefato não foi recebido pelo servidor")
        if artifact_path.stat().st_size > MAX_ARTIFACT_BYTES:
            artifact_path.unlink(missing_ok=True)
            raise ValueError("artefato excede o limite configurado")
        normalized_artifact = candidate
    status = "canceled" if canceled else "completed" if ok else "failed"
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """
            UPDATE pc_jobs
            SET status = ?, result_text = ?, artifact_name = ?,
                completed_at = ?, updated_at = ?, lease_until = NULL
            WHERE job_id = ? AND target_agent = ? AND status = 'running'
            """,
            (
                status,
                str(result_text)[-MAX_RESULT_CHARS:],
                normalized_artifact,
                timestamp,
                timestamp,
                normalized_job,
                normalized_agent,
            ),
        )
        if cursor.rowcount != 1:
            connection.rollback()
            if normalized_artifact:
                (ARTIFACT_DIR / normalized_artifact).unlink(missing_ok=True)
            return False
        connection.commit()
        return True
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def artifact_target(job_id: str, agent_id: str, suffix: str = ".bin") -> dict[str, str]:
    normalized_job = _job_id(job_id)
    normalized_agent = _agent_id(agent_id)
    normalized_suffix = str(suffix).lower().strip()
    if not re.fullmatch(r"\.[a-z0-9]{1,8}", normalized_suffix):
        normalized_suffix = ".bin"
    connection = _connect()
    try:
        row = connection.execute(
            """
            SELECT 1 FROM pc_jobs
            WHERE job_id = ? AND target_agent = ? AND status = 'running'
            """,
            (normalized_job, normalized_agent),
        ).fetchone()
    finally:
        connection.close()
    if row is None:
        raise ValueError("tarefa não está em execução")
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    name = f"{normalized_job}{normalized_suffix}"
    return {"name": name, "path": str(ARTIFACT_DIR / name)}


def cancel_job(job_id: str, *, now: float | None = None) -> dict[str, Any] | None:
    normalized_job = _job_id(job_id)
    timestamp = time.time() if now is None else float(now)
    connection = _connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT status FROM pc_jobs WHERE job_id = ?",
            (normalized_job,),
        ).fetchone()
        if row is None:
            connection.rollback()
            return None
        status = str(row["status"])
        if status == "queued":
            connection.execute(
                """
                UPDATE pc_jobs
                SET status = 'canceled', cancel_requested = 1,
                    result_text = 'Cancelada antes de iniciar.', completed_at = ?, updated_at = ?
                WHERE job_id = ?
                """,
                (timestamp, timestamp, normalized_job),
            )
        elif status == "running":
            connection.execute(
                "UPDATE pc_jobs SET cancel_requested = 1, updated_at = ? WHERE job_id = ?",
                (timestamp, normalized_job),
            )
        connection.commit()
        current = connection.execute(
            "SELECT * FROM pc_jobs WHERE job_id = ?",
            (normalized_job,),
        ).fetchone()
        return _row_to_job(current)
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def get_job(job_id: str) -> dict[str, Any] | None:
    normalized_job = _job_id(job_id)
    connection = _connect()
    try:
        row = connection.execute("SELECT * FROM pc_jobs WHERE job_id = ?", (normalized_job,)).fetchone()
        return _row_to_job(row)
    finally:
        connection.close()


def list_jobs(
    *,
    target_agent: str = DEFAULT_AGENT_ID,
    limit: int = 12,
) -> list[dict[str, Any]]:
    normalized_agent = _agent_id(target_agent)
    connection = _connect()
    try:
        rows = connection.execute(
            """
            SELECT * FROM pc_jobs
            WHERE target_agent = ?
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (normalized_agent, max(1, min(int(limit), 100))),
        ).fetchall()
        return [_row_to_job(row) for row in rows if row is not None]
    finally:
        connection.close()


def pending_notifications(limit: int = 10) -> list[dict[str, Any]]:
    connection = _connect()
    try:
        rows = connection.execute(
            """
            SELECT * FROM pc_jobs
            WHERE notified = 0 AND status IN ('completed', 'failed', 'canceled')
            ORDER BY completed_at, created_at
            LIMIT ?
            """,
            (max(1, min(int(limit), 50)),),
        ).fetchall()
        return [_row_to_job(row) for row in rows if row is not None]
    finally:
        connection.close()


def mark_notified(job_id: str) -> bool:
    normalized_job = _job_id(job_id)
    connection = _connect()
    try:
        cursor = connection.execute(
            "UPDATE pc_jobs SET notified = 1, updated_at = ? WHERE job_id = ?",
            (time.time(), normalized_job),
        )
        connection.commit()
        return cursor.rowcount == 1
    finally:
        connection.close()


def delete_artifact(artifact_name: str | None) -> None:
    if not artifact_name:
        return
    candidate = Path(str(artifact_name)).name
    if candidate == str(artifact_name) and ARTIFACT_NAME_RE.fullmatch(candidate):
        (ARTIFACT_DIR / candidate).unlink(missing_ok=True)


def get_agent(agent_id: str = DEFAULT_AGENT_ID, *, now: float | None = None) -> dict[str, Any] | None:
    normalized_agent = _agent_id(agent_id)
    timestamp = time.time() if now is None else float(now)
    connection = _connect()
    try:
        row = connection.execute(
            "SELECT * FROM pc_agents WHERE agent_id = ?",
            (normalized_agent,),
        ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["metadata"] = _decode_json(item.pop("metadata_json", "{}"))
        item["online"] = timestamp - float(item["last_seen"]) <= AGENT_ONLINE_SECONDS
        item["age_seconds"] = max(0, int(timestamp - float(item["last_seen"])))
        return item
    finally:
        connection.close()


def job_counts(target_agent: str = DEFAULT_AGENT_ID) -> dict[str, int]:
    normalized_agent = _agent_id(target_agent)
    counts = {status: 0 for status in ("queued", "running", "completed", "failed", "canceled")}
    connection = _connect()
    try:
        rows = connection.execute(
            """
            SELECT status, COUNT(*) AS total FROM pc_jobs
            WHERE target_agent = ? GROUP BY status
            """,
            (normalized_agent,),
        ).fetchall()
    finally:
        connection.close()
    for row in rows:
        counts[str(row["status"])] = int(row["total"])
    return counts


def _stdin_json() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("entrada deve ser um objeto JSON")
    return value


def _print_json(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, separators=(",", ":")), flush=True)


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ponte do agente remoto do Kali Bunker")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init")

    heartbeat_parser = subparsers.add_parser("heartbeat")
    heartbeat_parser.add_argument("--agent", required=True)

    claim_parser = subparsers.add_parser("claim")
    claim_parser.add_argument("--agent", required=True)
    claim_parser.add_argument("--lease", type=int, default=JOB_LEASE_SECONDS)
    claim_parser.add_argument("--wait", type=int, default=0)
    claim_parser.add_argument("--interval", type=float, default=1.0)

    renew_parser = subparsers.add_parser("renew")
    renew_parser.add_argument("--agent", required=True)
    renew_parser.add_argument("--job", required=True)
    renew_parser.add_argument("--lease", type=int, default=JOB_LEASE_SECONDS)

    complete_parser = subparsers.add_parser("complete")
    complete_parser.add_argument("--agent", required=True)
    complete_parser.add_argument("--job", required=True)

    artifact_parser = subparsers.add_parser("artifact-target")
    artifact_parser.add_argument("--agent", required=True)
    artifact_parser.add_argument("--job", required=True)
    artifact_parser.add_argument("--suffix", default=".bin")

    args = parser.parse_args(argv)
    init_db()
    if args.command == "init":
        _print_json({"ok": True, "database": str(DB_FILE), "artifact_dir": str(ARTIFACT_DIR)})
        return 0
    if args.command == "heartbeat":
        body = _stdin_json()
        _print_json(
            heartbeat_agent(
                args.agent,
                body.get("metadata", body),
                last_error=str(body.get("last_error", "")),
            )
        )
        return 0
    if args.command == "claim":
        body = _stdin_json()
        job = wait_for_job(
            args.agent,
            body.get("metadata", body),
            lease_seconds=args.lease,
            wait_seconds=args.wait,
            interval_seconds=args.interval,
        )
        _print_json({"ok": True, "job": job})
        return 0
    if args.command == "renew":
        _print_json(renew_job(args.job, args.agent, lease_seconds=args.lease))
        return 0
    if args.command == "artifact-target":
        _print_json(artifact_target(args.job, args.agent, args.suffix))
        return 0
    if args.command == "complete":
        body = _stdin_json()
        saved = complete_job(
            args.job,
            args.agent,
            ok=bool(body.get("ok")),
            result_text=str(body.get("result", "")),
            artifact_name=str(body["artifact_name"]) if body.get("artifact_name") else None,
            canceled=bool(body.get("canceled")),
        )
        _print_json({"ok": saved})
        return 0 if saved else 2
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(cli())
    except (ValueError, sqlite3.Error, OSError, json.JSONDecodeError) as exc:
        _print_json({"ok": False, "error": str(exc)})
        raise SystemExit(1)
