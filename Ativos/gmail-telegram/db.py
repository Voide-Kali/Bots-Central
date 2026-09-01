"""Estado SQLite do bot, incluindo a caixa de saída Gmail -> Telegram."""

import logging
import secrets
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger(__name__)
DB_FILE = Path(__file__).resolve().parent / "gmail_bot.db"

DELIVERY_PENDING = "pending"
DELIVERY_SENDING = "sending"
DELIVERY_SENT = "sent"
DELIVERY_FAILED = "failed"
DELIVERY_FILTERED = "filtered"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 10000")
    return conn


def init_db():
    """Cria/migra o banco sem apagar o histórico de versões anteriores.

    ``seen_emails`` continua existindo para compatibilidade. Registros antigos
    não permitem distinguir mensagens filtradas das efetivamente enviadas;
    por isso são migrados conservadoramente como concluídos.
    """
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS seen_emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_email TEXT NOT NULL,
                message_id TEXT NOT NULL,
                notified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(account_email, message_id)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS action_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                ok INTEGER NOT NULL,
                detail TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS email_delivery (
                account_email TEXT NOT NULL,
                message_id TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'sending', 'sent', 'failed', 'filtered')),
                attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
                next_attempt_at REAL NOT NULL DEFAULT 0,
                lease_token TEXT,
                lease_until REAL,
                last_error TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                sent_at REAL,
                PRIMARY KEY (account_email, message_id)
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_email_delivery_due
            ON email_delivery(status, next_attempt_at, created_at)
        """)
        now = time.time()
        conn.execute(
            """
            INSERT OR IGNORE INTO email_delivery (
                account_email, message_id, status, attempt_count,
                next_attempt_at, created_at, updated_at, sent_at
            )
            SELECT account_email, message_id, 'sent', 0, 0,
                   COALESCE(CAST(strftime('%s', notified_at) AS REAL), ?),
                   COALESCE(CAST(strftime('%s', notified_at) AS REAL), ?),
                   COALESCE(CAST(strftime('%s', notified_at) AS REAL), ?)
            FROM seen_emails
            """,
            (now, now, now),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    try:
        DB_FILE.chmod(0o600)
    except OSError:
        logger.warning("Não foi possível restringir as permissões de %s", DB_FILE)
    logger.info("Banco de dados inicializado.")


def is_seen(account_email: str, message_id: str) -> bool:
    """Verifica se a mensagem já foi aceita pelo fluxo durável.

    O nome é legado: ``pending``/``sending`` também retornam verdadeiro para
    impedir que duas verificações enfileirem a mesma mensagem.
    """
    conn = _connect()
    try:
        result = conn.execute(
            """
            SELECT 1 FROM email_delivery
            WHERE account_email = ? AND message_id = ?
            UNION ALL
            SELECT 1 FROM seen_emails
            WHERE account_email = ? AND message_id = ?
            LIMIT 1
            """,
            (account_email, message_id, account_email, message_id),
        ).fetchone()
        return result is not None
    finally:
        conn.close()


def seen_message_ids(account_email: str) -> set[str]:
    """Retorna IDs já concluídos ou sob responsabilidade da caixa de saída."""
    conn = _connect()
    try:
        rows = conn.execute(
            """
            SELECT message_id FROM email_delivery WHERE account_email = ?
            UNION
            SELECT message_id FROM seen_emails WHERE account_email = ?
            """,
            (account_email, account_email),
        ).fetchall()
        return {str(row[0]) for row in rows}
    finally:
        conn.close()


def mark_seen(account_email: str, message_id: str):
    """Marca uma mensagem descartada pelo filtro (API legada)."""
    conn = _connect()
    try:
        now = time.time()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT OR IGNORE INTO seen_emails (account_email, message_id) VALUES (?, ?)",
            (account_email, message_id),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO email_delivery (
                account_email, message_id, status, attempt_count,
                next_attempt_at, created_at, updated_at
            ) VALUES (?, ?, 'filtered', 0, 0, ?, ?)
            """,
            (account_email, message_id, now, now),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def enqueue_delivery(
    account_email: str,
    message_id: str,
    *,
    now: float | None = None,
) -> bool:
    """Persiste uma entrega antes do primeiro envio.

    Nenhum conteúdo do e-mail é gravado: somente conta e ID opaco do Gmail.
    Retorna ``True`` apenas quando um novo item foi criado.
    """
    timestamp = time.time() if now is None else float(now)
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        legacy = conn.execute(
            "SELECT 1 FROM seen_emails WHERE account_email = ? AND message_id = ?",
            (account_email, message_id),
        ).fetchone()
        if legacy:
            conn.commit()
            return False
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO email_delivery (
                account_email, message_id, status, attempt_count,
                next_attempt_at, created_at, updated_at
            ) VALUES (?, ?, 'pending', 0, ?, ?, ?)
            """,
            (account_email, message_id, timestamp, timestamp, timestamp),
        )
        conn.commit()
        return cursor.rowcount == 1
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def claim_due_delivery(
    *,
    max_attempts: int,
    lease_seconds: int,
    now: float | None = None,
) -> dict | None:
    """Reivindica atomicamente uma entrega vencida para um único trabalhador."""
    timestamp = time.time() if now is None else float(now)
    attempts_limit = max(1, int(max_attempts))
    lease_duration = max(1, int(lease_seconds))
    token = secrets.token_urlsafe(24)
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """
            UPDATE email_delivery
            SET status = CASE WHEN attempt_count >= ? THEN 'failed' ELSE 'pending' END,
                lease_token = NULL,
                lease_until = NULL,
                updated_at = ?
            WHERE status = 'sending' AND (lease_until IS NULL OR lease_until <= ?)
            """,
            (attempts_limit, timestamp, timestamp),
        )
        row = conn.execute(
            """
            SELECT account_email, message_id, attempt_count
            FROM email_delivery
            WHERE status = 'pending'
              AND attempt_count < ?
              AND next_attempt_at <= ?
            ORDER BY next_attempt_at, created_at, account_email, message_id
            LIMIT 1
            """,
            (attempts_limit, timestamp),
        ).fetchone()
        if row is None:
            conn.commit()
            return None
        cursor = conn.execute(
            """
            UPDATE email_delivery
            SET status = 'sending',
                attempt_count = attempt_count + 1,
                lease_token = ?,
                lease_until = ?,
                updated_at = ?
            WHERE account_email = ? AND message_id = ? AND status = 'pending'
            """,
            (
                token,
                timestamp + lease_duration,
                timestamp,
                row["account_email"],
                row["message_id"],
            ),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return None
        conn.commit()
        return {
            "account_email": str(row["account_email"]),
            "message_id": str(row["message_id"]),
            "attempt_count": int(row["attempt_count"]) + 1,
            "lease_token": token,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def mark_delivery_sent(
    account_email: str,
    message_id: str,
    lease_token: str,
    *,
    now: float | None = None,
) -> bool:
    """Conclui somente o item ainda pertencente ao trabalhador informado."""
    timestamp = time.time() if now is None else float(now)
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cursor = conn.execute(
            """
            UPDATE email_delivery
            SET status = 'sent', sent_at = ?, updated_at = ?,
                lease_token = NULL, lease_until = NULL, last_error = NULL
            WHERE account_email = ? AND message_id = ?
              AND status = 'sending' AND lease_token = ?
            """,
            (timestamp, timestamp, account_email, message_id, lease_token),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return False
        conn.execute(
            "INSERT OR IGNORE INTO seen_emails (account_email, message_id) VALUES (?, ?)",
            (account_email, message_id),
        )
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def defer_delivery(
    account_email: str,
    message_id: str,
    lease_token: str,
    error: str,
    *,
    max_attempts: int,
    base_backoff_seconds: int,
    max_backoff_seconds: int,
    now: float | None = None,
) -> dict | None:
    """Agenda nova tentativa com backoff ou encerra após o limite."""
    timestamp = time.time() if now is None else float(now)
    attempts_limit = max(1, int(max_attempts))
    base = max(1, int(base_backoff_seconds))
    cap = max(base, int(max_backoff_seconds))
    safe_error = " ".join(str(error).split())[:300]
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            """
            SELECT attempt_count FROM email_delivery
            WHERE account_email = ? AND message_id = ?
              AND status = 'sending' AND lease_token = ?
            """,
            (account_email, message_id, lease_token),
        ).fetchone()
        if row is None:
            conn.rollback()
            return None
        attempt_count = int(row["attempt_count"])
        terminal = attempt_count >= attempts_limit
        exponent = min(30, max(0, attempt_count - 1))
        delay = 0 if terminal else min(cap, base * (2 ** exponent))
        status = DELIVERY_FAILED if terminal else DELIVERY_PENDING
        next_attempt_at = timestamp if terminal else timestamp + delay
        conn.execute(
            """
            UPDATE email_delivery
            SET status = ?, next_attempt_at = ?, last_error = ?,
                lease_token = NULL, lease_until = NULL, updated_at = ?
            WHERE account_email = ? AND message_id = ? AND lease_token = ?
            """,
            (
                status,
                next_attempt_at,
                safe_error,
                timestamp,
                account_email,
                message_id,
                lease_token,
            ),
        )
        conn.commit()
        return {
            "status": status,
            "attempt_count": attempt_count,
            "next_attempt_at": next_attempt_at,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def retry_failed_deliveries(*, now: float | None = None) -> int:
    """Reabre itens terminais após intervenção explícita do operador."""
    timestamp = time.time() if now is None else float(now)
    conn = _connect()
    try:
        cursor = conn.execute(
            """
            UPDATE email_delivery
            SET status = 'pending', attempt_count = 0,
                next_attempt_at = ?, last_error = NULL,
                lease_token = NULL, lease_until = NULL, updated_at = ?
            WHERE status = 'failed'
            """,
            (timestamp, timestamp),
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def get_delivery(account_email: str, message_id: str) -> dict | None:
    """Retorna metadados operacionais de uma entrega, sem conteúdo do e-mail."""
    conn = _connect()
    try:
        row = conn.execute(
            """
            SELECT account_email, message_id, status, attempt_count,
                   next_attempt_at, lease_until, last_error, created_at,
                   updated_at, sent_at
            FROM email_delivery
            WHERE account_email = ? AND message_id = ?
            """,
            (account_email, message_id),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_stats() -> dict:
    """Retorna estatísticas do banco de dados."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT account_email, COUNT(*) as total
        FROM seen_emails
        GROUP BY account_email
    """)
    rows = cursor.fetchall()
    conn.close()
    return {row[0]: row[1] for row in rows}


def record_action(action: str, actor: str, ok: bool, detail: str):
    """Registra uma ação remota sem armazenar tokens ou segredos."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO action_history (action, actor, ok, detail)
            VALUES (?, ?, ?, ?)
            """,
            (action[:80], actor[:80], 1 if ok else 0, detail[:1000]),
        )
        conn.commit()
    except sqlite3.OperationalError:
        logger.exception("Tabela action_history indisponível.")
    finally:
        conn.close()


def get_action_history(limit: int = 20) -> list[dict]:
    """Retorna as ações remotas mais recentes."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            SELECT action, actor, ok, detail, created_at
            FROM action_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, min(limit, 100)),),
        )
        rows = cursor.fetchall()
    except sqlite3.OperationalError:
        rows = []
    finally:
        conn.close()
    return [
        {
            "action": row[0],
            "actor": row[1],
            "ok": bool(row[2]),
            "detail": row[3],
            "created_at": row[4],
        }
        for row in rows
    ]
