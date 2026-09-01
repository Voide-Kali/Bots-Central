"""
Cliente Gmail - lê emails usando a Gmail API com OAuth2
"""

import base64
import html
import logging
import os
import re
from pathlib import Path

import httplib2
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_httplib2 import AuthorizedHttp
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


class GmailClientError(RuntimeError):
    """Falha de uma operação remota do Gmail que deve chegar ao monitor."""


def gmail_error(operation: str, exc: Exception) -> GmailClientError:
    """Cria uma mensagem curta sem transformar falha de API em resultado vazio."""
    detail = " ".join(str(exc).split())[:300]
    if detail:
        return GmailClientError(f"{operation}: {detail}")
    return GmailClientError(f"{operation}: {type(exc).__name__}")


def api_timeout_seconds() -> int:
    try:
        return max(3, int(os.environ.get("GMAIL_API_TIMEOUT_SECONDS", "12")))
    except ValueError:
        return 12


def get_gmail_service(credentials_file: str, token_file: str, *, interactive: bool = False):
    """Autentica e retorna o serviço Gmail da conta."""
    creds = None
    credentials_path = Path(credentials_file)
    token_path = Path(token_file)

    if token_path.exists():
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError:
                if not interactive:
                    raise
                logger.warning("Token OAuth revogado ou expirado sem renovação: %s", token_path)
                token_path.unlink(missing_ok=True)
                creds = None
        if not creds or not creds.valid:
            if not interactive:
                raise RuntimeError(
                    f"Token OAuth ausente ou inválido: {token_path}. "
                    "Execute: ./venv/bin/python authorize.py"
                )
            if not credentials_path.exists():
                raise FileNotFoundError(f"Credencial OAuth não encontrada: {credentials_path}")
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            # O bot normalmente roda em servidor sem interface gráfica. A porta
            # fixa permite encaminhamento SSH e o link pode ser aberto no PC do usuário.
            oauth_port = int(os.environ.get("GMAIL_OAUTH_PORT", "8765"))
            creds = flow.run_local_server(port=oauth_port, open_browser=False)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        with token_path.open("w", encoding="utf-8") as token:
            token.write(creds.to_json())
        token_path.chmod(0o600)

    http = AuthorizedHttp(creds, http=httplib2.Http(timeout=api_timeout_seconds()))
    return build("gmail", "v1", http=http, cache_discovery=False)


def get_unread_emails(
    service,
    max_results: int = 5,
    *,
    excluded_ids: set[str] | None = None,
    scan_limit: int = 100,
) -> list[dict]:
    """Busca não lidos ainda não processados, paginando sem baixar toda a caixa."""
    try:
        wanted = max(1, max_results)
        remaining_scan = max(wanted, scan_limit)
        excluded = excluded_ids or set()
        messages: list[dict] = []
        page_token: str | None = None

        while len(messages) < wanted and remaining_scan > 0:
            page_size = min(100, remaining_scan)
            request_args = {
                "userId": "me",
                "labelIds": ["INBOX", "UNREAD"],
                "maxResults": page_size,
            }
            if page_token:
                request_args["pageToken"] = page_token
            results = service.users().messages().list(**request_args).execute()
            page = results.get("messages", [])
            remaining_scan -= len(page)
            for message in page:
                message_id = str(message.get("id", ""))
                if message_id and message_id not in excluded:
                    messages.append(message)
                    if len(messages) >= wanted:
                        break
            page_token = results.get("nextPageToken")
            if not page_token or not page:
                break

        emails = []
        for msg in messages:
            email_data = get_email_details(service, msg["id"])
            if email_data:
                emails.append(email_data)

        return emails

    except GmailClientError:
        raise
    except Exception as exc:
        raise gmail_error("Falha ao buscar e-mails não lidos", exc) from exc


def get_email_details(service, message_id: str) -> dict:
    """Busca os detalhes de um email específico."""
    try:
        msg = service.users().messages().get(
            userId="me",
            id=message_id,
            format="full"
        ).execute()

        headers = {h["name"]: h["value"] for h in msg["payload"].get("headers", [])}

        sender = headers.get("From", "Desconhecido")
        subject = headers.get("Subject", "(sem assunto)")
        date = headers.get("Date", "")

        body = extract_body(msg["payload"])

        return {
            "id": message_id,
            "sender": sender,
            "subject": subject,
            "date": date,
            "body": body[:2000] if body else "",  # limita para a IA
            "snippet": msg.get("snippet", ""),
        }

    except GmailClientError:
        raise
    except Exception as exc:
        raise gmail_error(f"Falha ao buscar detalhes da mensagem {message_id}", exc) from exc


def extract_body(payload: dict) -> str:
    """Extrai o corpo do email (texto puro ou HTML convertido)."""
    body = ""
    html_body = ""

    def decode_part(part: dict) -> str:
        data = part.get("body", {}).get("data", "")
        if not data:
            return ""
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="ignore")

    if "parts" in payload:
        for part in payload["parts"]:
            mime_type = part.get("mimeType", "")
            if mime_type == "text/plain":
                body = decode_part(part)
                if body:
                    break
            elif mime_type == "text/html":
                html_body = decode_part(part)
            elif "parts" in part:
                body = extract_body(part)
                if body:
                    break
    else:
        body = decode_part(payload)

    if body:
        return body.strip()
    if html_body:
        text = re.sub(r"<[^>]+>", " ", html_body)
        text = html.unescape(text)
        return re.sub(r"\s+", " ", text).strip()
    return ""


def get_unread_count(service) -> int:
    """Retorna o total de emails não lidos."""
    try:
        result = service.users().labels().get(
            userId="me",
            id="INBOX",
        ).execute()
        return int(result.get("messagesUnread", 0))
    except GmailClientError:
        raise
    except Exception as exc:
        raise gmail_error("Falha ao buscar contador de e-mails não lidos", exc) from exc
