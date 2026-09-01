#!/usr/bin/env python3
"""Autoriza uma conta Gmail específica do `config.GMAIL_ACCOUNTS`.

Uso:
  ./venv/bin/python authorize_one.py --email user@example.com
ou
  ./venv/bin/python authorize_one.py --index 2

Define `GMAIL_OAUTH_PORT=0` para usar uma porta dinâmica se necessário.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import config
from gmail_client import get_gmail_service


def main() -> None:
    parser = argparse.ArgumentParser(description="Autorizar uma conta Gmail específica")
    parser.add_argument("--email", help="Endereço de e-mail da conta a autorizar")
    parser.add_argument("--index", type=int, help="Índice (1-based) da conta em config.GMAIL_ACCOUNTS")
    args = parser.parse_args()

    accounts = config.GMAIL_ACCOUNTS
    if not accounts:
        print("Nenhuma conta configurada em config.GMAIL_ACCOUNTS")
        raise SystemExit(1)

    if args.email:
        account = next((a for a in accounts if a["email"].lower() == args.email.lower()), None)
        if account is None:
            print(f"Conta não encontrada: {args.email}")
            raise SystemExit(2)
    elif args.index:
        idx = args.index - 1
        if idx < 0 or idx >= len(accounts):
            print(f"Índice inválido: {args.index}")
            raise SystemExit(2)
        account = accounts[idx]
    else:
        print("Contas disponíveis:")
        for i, a in enumerate(accounts, start=1):
            print(f"  {i}. {a['email']} -> {a['token_file']}")
        print("\nUse --email ou --index para autorizar uma conta específica.")
        raise SystemExit(0)

    project_dir = Path(__file__).resolve().parent
    credentials = project_dir / account["credentials_file"]
    token = project_dir / account["token_file"]

    print(f"\n[AUTORIZANDO] {account['email']}\nCredenciais: {credentials}\nToken: {token}\n")
    try:
        service = get_gmail_service(str(credentials), str(token), interactive=True)
        authenticated_email = service.users().getProfile(userId="me").execute()["emailAddress"]
        if authenticated_email.lower() != account["email"].lower():
            token.unlink(missing_ok=True)
            print(
                f"Conta incorreta: foi autorizada {authenticated_email}, mas era esperada {account['email']}."
            )
            raise SystemExit(3)
        print(f"[OK] {authenticated_email}")
    except Exception as exc:  # pragma: no cover - debugging helper
        print("Falha ao autorizar:", exc)
        raise


if __name__ == "__main__":
    main()
