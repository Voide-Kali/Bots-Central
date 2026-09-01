"""
Gmail Monitor Bot - Entry Point
Monitora múltiplas contas Gmail e envia notificações pelo Telegram
"""

import logging
from bot import start_bot

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("apscheduler.scheduler").setLevel(logging.WARNING)
logging.getLogger("apscheduler.executors.default").setLevel(logging.WARNING)

if __name__ == "__main__":
    start_bot()
