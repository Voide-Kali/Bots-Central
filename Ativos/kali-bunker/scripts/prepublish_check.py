#!/usr/bin/env python3
"""Verifica nomes sensíveis e formatos comuns de segredo sem exibir valores."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path


SENSITIVE_PATH = re.compile(
    r"(^|/)(\.env($|\.)|credentials?|secrets?|.*token.*\.json$|"
    r".*client_secret.*|.*\.pem$|.*\.key$|id_rsa|.*\.db$)",
    re.IGNORECASE,
)
SECRET_PATTERN = re.compile(
    rb"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----|"
    rb"AIza[0-9A-Za-z_-]{35}|"
    rb"[0-9]{8,12}:[A-Za-z0-9_-]{35}|"
    rb"gh[pousr]_[A-Za-z0-9]{20,}|"
    rb"gsk_[A-Za-z0-9]{20,}|"
    rb"GOCSPX-[A-Za-z0-9_-]{20,}|"
    rb"sk-[A-Za-z0-9_-]{24,}|"
    rb"1//[0-9A-Za-z_-]{20,}"
)
PUSHOVER_CONTEXT_PATTERN = re.compile(
    rb"(?:PUSHOVER_(?:TOKEN|USER)|API\s+Token|User\s+Key)"
    rb"\s*(?:=|:)\s*[\"']?[A-Za-z0-9]{30}",
    re.IGNORECASE,
)
ALLOWED_EXAMPLES = {".env.example"}


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *args],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=check,
    )


def tracked_files() -> list[str]:
    return git(
        "ls-files", "--cached", "--others", "--exclude-standard", "-z"
    ).stdout.decode("utf-8", errors="replace").split("\0")[:-1]


def scan_blob(label: str, content: bytes, findings: set[str]) -> None:
    scanned = content
    if label.casefold().endswith(".pdf"):
        converter = shutil.which("pdftotext")
        if not converter:
            findings.add(f"PDF nao verificado (instale pdftotext): {label}")
            return
        converted = subprocess.run(
            [converter, "-", "-"], input=content, capture_output=True, check=False
        )
        if converted.returncode != 0:
            findings.add(f"PDF ilegivel para o scanner: {label}")
            return
        scanned = converted.stdout
    if SECRET_PATTERN.search(scanned) or PUSHOVER_CONTEXT_PATTERN.search(scanned):
        findings.add(label)


def scan_current(findings: set[str]) -> None:
    root = Path(__file__).resolve().parents[1]
    for relative in tracked_files():
        if SENSITIVE_PATH.search(relative) and relative not in ALLOWED_EXAMPLES:
            findings.add(f"caminho sensivel rastreado: {relative}")
        path = root / relative
        if not path.exists():
            continue
        try:
            scan_blob(f"possivel segredo: {relative}", path.read_bytes(), findings)
        except OSError:
            findings.add(f"arquivo rastreado ilegivel: {relative}")


def scan_history(findings: set[str]) -> None:
    revisions = git("rev-list", "--all").stdout.decode().split()
    for revision in revisions:
        names = git("ls-tree", "-r", "--name-only", "-z", revision).stdout
        for relative in names.decode("utf-8", errors="replace").split("\0")[:-1]:
            if SENSITIVE_PATH.search(relative) and relative not in ALLOWED_EXAMPLES:
                findings.add(f"historico com caminho sensivel: {revision[:12]}:{relative}")
            blob = git("show", f"{revision}:{relative}", check=False)
            if blob.returncode == 0:
                scan_blob(f"historico com possivel segredo: {revision[:12]}:{relative}", blob.stdout, findings)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--history", action="store_true", help="tambem verifica todos os commits locais")
    args = parser.parse_args()
    findings: set[str] = set()
    scan_current(findings)
    if args.history:
        scan_history(findings)
    if findings:
        print("Falha: revise os seguintes locais (valores nunca sao exibidos):")
        for finding in sorted(findings):
            print(f"- {finding}")
        return 1
    print("OK: nenhum caminho sensivel rastreado ou formato conhecido de segredo foi encontrado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
