"""Exemplo de configuração do monitor Gmail."""

import getpass
import os
import shlex
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_DIR = Path(__file__).resolve().parent
_legacy_kali_bunker_dir = Path.home() / "Kali-Bunker-main"
KALI_BUNKER_DIR = Path(
    os.environ.get("KALI_BUNKER_DIR", str(_legacy_kali_bunker_dir))
).expanduser()
PC_AGENT_ID = os.environ.get("PC_AGENT_ID", "kali-principal")
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
TELEGRAM_ALLOWED_USER_IDS = os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "")
IPHONE_MAC = os.environ.get("IPHONE_MAC", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.1-70b-versatile")
AI_EMAIL_SUMMARY_ENABLED = os.environ.get("AI_EMAIL_SUMMARY_ENABLED", "0") == "1"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")


def env_int(name: str, default: int, minimum: int = 1) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return max(minimum, value)


CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 60, minimum=10)
GMAIL_API_TIMEOUT_SECONDS = env_int("GMAIL_API_TIMEOUT_SECONDS", 12, minimum=3)
MAX_EMAILS_PER_CHECK = env_int("MAX_EMAILS_PER_CHECK", 5, minimum=1)
SUMMARY_MAX_TOKENS = env_int("SUMMARY_MAX_TOKENS", 150, minimum=50)
AI_AUDIO_MAX_MB = env_int("AI_AUDIO_MAX_MB", 25, minimum=1)
AI_AUDIO_TIMEOUT_SECONDS = env_int("AI_AUDIO_TIMEOUT_SECONDS", 180, minimum=30)
AI_AUDIO_OPENAI_MODEL = os.environ.get("AI_AUDIO_OPENAI_MODEL", "whisper-1")
AI_AUDIO_LANGUAGE = os.environ.get("AI_AUDIO_LANGUAGE", "pt")
AI_AUDIO_THREADS = env_int("AI_AUDIO_THREADS", 4, minimum=1)
AI_AUDIO_WHISPER_CPP_BIN = os.environ.get("AI_AUDIO_WHISPER_CPP_BIN", "")
AI_AUDIO_WHISPER_CPP_MODEL = os.environ.get("AI_AUDIO_WHISPER_CPP_MODEL", "")
AI_AUDIO_WHISPER_CPP_BACKEND = os.environ.get("AI_AUDIO_WHISPER_CPP_BACKEND", "")
LOCAL_WHISPER_MODEL = os.environ.get("LOCAL_WHISPER_MODEL", "base")
REMOTE_SHUTDOWN_ENABLED = os.environ.get("REMOTE_SHUTDOWN_ENABLED", "0") == "1"
SHUTDOWN_COMMAND = shlex.split(
    os.environ.get("SHUTDOWN_COMMAND", "")
)
REMOTE_REBOOT_ENABLED = os.environ.get("REMOTE_REBOOT_ENABLED", "0") == "1"
REBOOT_COMMAND = shlex.split(
    os.environ.get("REBOOT_COMMAND", "")
)
REMOTE_SUSPEND_ENABLED = os.environ.get("REMOTE_SUSPEND_ENABLED", "0") == "1"
SUSPEND_COMMAND = shlex.split(
    os.environ.get("SUSPEND_COMMAND", "")
)
LOCK_COMMAND = shlex.split(
    os.environ.get("LOCK_COMMAND", "")
)
UNLOCK_COMMAND = shlex.split(
    os.environ.get("UNLOCK_COMMAND", "")
)
LOCK_USER = os.environ.get("LOCK_USER", getpass.getuser())
NETWORK_SCAN_TARGET = os.environ.get("NETWORK_SCAN_TARGET", "")
NETWORK_SCAN_INTERFACE = os.environ.get("NETWORK_SCAN_INTERFACE", "")
NETWORK_SCAN_TIMEOUT_SECONDS = env_int("NETWORK_SCAN_TIMEOUT_SECONDS", 90, minimum=10)
WEBCAM_RESOLUTION = os.environ.get("WEBCAM_RESOLUTION", "1280x720")
WEBCAM_DEVICE = os.environ.get("WEBCAM_DEVICE") or os.environ.get("AUTH_CAMERA_DEVICE", "")
BATTERY_ALERTS_ENABLED = os.environ.get("BATTERY_ALERTS_ENABLED", "1") == "1"
BATTERY_LOW_PERCENT = env_int("BATTERY_LOW_PERCENT", 25, minimum=1)
BATTERY_ALERT_INTERVAL_SECONDS = env_int("BATTERY_ALERT_INTERVAL_SECONDS", 1800, minimum=60)
DAILY_REPORT_ENABLED = os.environ.get("DAILY_REPORT_ENABLED", "0") == "1"
DAILY_REPORT_HOUR = min(env_int("DAILY_REPORT_HOUR", 9, minimum=0), 23)
DAILY_REPORT_MINUTE = min(env_int("DAILY_REPORT_MINUTE", 0, minimum=0), 59)
SMART_ALERTS_ENABLED = os.environ.get("SMART_ALERTS_ENABLED", "1") == "1"
SMART_ALERT_COOLDOWN_SECONDS = env_int("SMART_ALERT_COOLDOWN_SECONDS", 1800, minimum=60)
SMART_ALERT_DURATION_SECONDS = env_int("SMART_ALERT_DURATION_SECONDS", 180, minimum=30)
SMART_CPU_PERCENT = env_int("SMART_CPU_PERCENT", 90, minimum=1)
SMART_DISK_PERCENT = env_int("SMART_DISK_PERCENT", 90, minimum=1)
SMART_TEMP_C = env_int("SMART_TEMP_C", 82, minimum=1)
APT_UPGRADE_COMMAND = shlex.split(
    os.environ.get("APT_UPGRADE_COMMAND", "")
)
REMOTE_CLEANUP_ENABLED = os.environ.get("REMOTE_CLEANUP_ENABLED", "0") == "1"
CLEANUP_COMMAND = shlex.split(
    os.environ.get("CLEANUP_COMMAND", "")
)

GMAIL_ACCOUNTS = [
    {
        "email": "usuario@gmail.com",
        "credentials_file": "credentials/client_secret.json",
        "token_file": "credentials/conta1_token.json",
        "label": "Conta principal",
    }
]

IGNORE_SENDERS = []
IGNORE_SENDER_DOMAINS = ["noreply", "no-reply", "newsletter", "marketing"]
IGNORE_SUBJECT_KEYWORDS = ["promo", "cupom", "desconto", "oferta"]
