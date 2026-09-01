#!/usr/bin/env python3
"""Autoriza interativamente as contas Gmail configuradas."""

from __future__ import annotations

from pathlib import Path

import config
from gmail_client import get_gmail_service


def main() -> None:
    project_dir = Path(__file__).resolve().parent
    authorized = 0

    for account in config.GMAIL_ACCOUNTS:
        credentials = project_dir / account["credentials_file"]
        token = project_dir / account["token_file"]

        if not credentials.exists():
            raise SystemExit(
                f"Credencial OAuth ausente: {credentials}\n"
                "Baixe no Google Cloud um cliente OAuth do tipo Aplicativo para computador "
                "e salve-o como credentials/client_secret.json."
            )

        print(f"\n[AUTORIZANDO] Selecione no navegador: {account['email']}")
        service = get_gmail_service(str(credentials), str(token), interactive=True)
        authenticated_email = service.users().getProfile(userId="me").execute()["emailAddress"]
        if authenticated_email.lower() != account["email"].lower():
            token.unlink(missing_ok=True)
            raise SystemExit(
                f"Conta incorreta: foi autorizada {authenticated_email}, mas era esperada "
                f"{account['email']}. Execute novamente e escolha a conta correta."
            )
        print(f"[OK] {authenticated_email}")
        authorized += 1

    if authorized == 0:
        raise SystemExit(
            "Nenhuma conta autorizada."
        )

    print(f"{authorized} conta(s) autorizada(s).")


if __name__ == "__main__":
    main()
