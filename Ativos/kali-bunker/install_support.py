#!/usr/bin/env python3
"""Validacao e renderizacao usadas pelo instalador do Kali Bunker."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path

from runtime_integrity import (
    MANIFEST_FILENAME,
    create_runtime_manifest,
    write_runtime_manifest,
)


@dataclass(frozen=True)
class ConfigStatus:
    alert_ready: bool
    bluetooth_ready: bool
    protected_dir_ready: bool
    telegram_polling_ready: bool

    def flags(self) -> str:
        return " ".join(
            str(int(value))
            for value in (
                self.alert_ready,
                self.bluetooth_ready,
                self.protected_dir_ready,
                self.telegram_polling_ready,
            )
        )


def load_env_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            values[key] = value.strip().strip("\"'")
    return values


def inspect_config(path: Path, target_home: Path) -> ConfigStatus:
    values = load_env_values(path)
    provider = values.get("ALERT_PROVIDER", "telegram").strip().lower()
    telegram_alert = bool(
        values.get("TELEGRAM_BOT_TOKEN") and values.get("TELEGRAM_CHAT_ID")
    )
    pushover_alert = bool(
        values.get("PUSHOVER_TOKEN") and values.get("PUSHOVER_USER")
    )
    protected_raw = values.get("PROTECTED_DIR", str(target_home / "Documentos"))
    protected_raw = protected_raw.replace("${HOME}", str(target_home)).replace(
        "$HOME", str(target_home)
    )
    if protected_raw.startswith("~/"):
        protected_raw = str(target_home / protected_raw[2:])

    return ConfigStatus(
        alert_ready=(provider == "telegram" and telegram_alert)
        or (provider == "pushover" and pushover_alert),
        bluetooth_ready=bool(values.get("IPHONE_MAC")),
        protected_dir_ready=Path(protected_raw).is_dir(),
        telegram_polling_ready=bool(
            values.get("TELEGRAM_BOT_TOKEN")
            and (
                values.get("TELEGRAM_ALLOWED_CHAT_IDS")
                or values.get("TELEGRAM_CHAT_ID")
            )
        ),
    )


def _environment_line(name: str, value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'Environment="{name}={escaped}"'


def render_systemd_unit(
    source: str,
    *,
    target_user: str,
    target_group: str,
    target_home: Path,
    runtime_dir: Path,
    runtime_python: Path,
    system_config: Path,
) -> str:
    rendered: list[str] = []
    for original_line in source.splitlines():
        if original_line == "[Service]":
            rendered.extend(
                (
                    "[Service]",
                    _environment_line("HOME", str(target_home)),
                    _environment_line("KALI_BUNKER_USER", target_user),
                    _environment_line("KALI_BUNKER_HOME", str(target_home)),
                    _environment_line("KALI_BUNKER_RUNTIME_DIR", str(runtime_dir)),
                    f"EnvironmentFile=-{system_config}",
                )
            )
            continue
        if original_line.startswith(
            (
                "EnvironmentFile=",
                "Environment=KALI_BUNKER_USER=",
                "Environment=KALI_BUNKER_HOME=",
            )
        ):
            continue

        line = original_line.replace(
            "/home/voide/Kali-Bunker-main", "__KALI_BUNKER_RUNTIME__"
        )
        line = line.replace("/home/voide", str(target_home))
        line = line.replace("__KALI_BUNKER_RUNTIME__", str(runtime_dir))
        line = line.replace("/usr/bin/python3", str(runtime_python))
        if line == "User=voide":
            line = f"User={target_user}"
        elif line == "Group=voide":
            line = f"Group={target_group}"
        rendered.append(line)
    return "\n".join(rendered) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check-config")
    check.add_argument("config", type=Path)
    check.add_argument("target_home", type=Path)

    render = subparsers.add_parser("render-unit")
    render.add_argument("source", type=Path)
    render.add_argument("destination", type=Path)
    render.add_argument("--user", required=True)
    render.add_argument("--group", required=True)
    render.add_argument("--home", required=True, type=Path)
    render.add_argument("--runtime", required=True, type=Path)
    render.add_argument("--python", required=True, type=Path)
    render.add_argument("--config", required=True, type=Path)

    manifest = subparsers.add_parser("write-manifest")
    manifest.add_argument("--runtime-source", required=True, type=Path)
    manifest.add_argument("--runtime-install", required=True, type=Path)
    manifest.add_argument("--systemd-source", required=True, type=Path)
    manifest.add_argument("--systemd-install", required=True, type=Path)
    manifest.add_argument("--output", required=True, type=Path)
    manifest.add_argument("--runtime-file", action="append", required=True)
    manifest.add_argument("--systemd-file", action="append", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "check-config":
        print(inspect_config(args.config, args.target_home).flags())
        return 0

    if args.command == "write-manifest":
        if os.geteuid() != 0:
            raise SystemExit("write-manifest exige root e e usado somente pelo instalador")
        expected_output = args.runtime_source / MANIFEST_FILENAME
        if args.output != expected_output:
            raise SystemExit(f"o manifesto deve ser gravado em {expected_output}")
        payload = create_runtime_manifest(
            runtime_source_root=args.runtime_source,
            runtime_install_root=args.runtime_install,
            runtime_files=args.runtime_file,
            systemd_source_root=args.systemd_source,
            systemd_install_root=args.systemd_install,
            systemd_files=args.systemd_file,
        )
        write_runtime_manifest(args.output, payload)
        return 0

    source = args.source.read_text(encoding="utf-8")
    rendered = render_systemd_unit(
        source,
        target_user=args.user,
        target_group=args.group,
        target_home=args.home,
        runtime_dir=args.runtime,
        runtime_python=args.python,
        system_config=args.config,
    )
    args.destination.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
