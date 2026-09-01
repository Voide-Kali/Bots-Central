#!/usr/bin/env python3
"""Assistente de estudos profissional para Telegram."""

from __future__ import annotations

import asyncio
import html
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

from telegram import BotCommand, InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction, ParseMode
from telegram.error import BadRequest
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)
from telegram.request import HTTPXRequest

import config
from ia import chat, chamar_groq_com_imagem, gerar_flashcards, gerar_questoes, gerar_resumo
from pdf_utils import extrair_texto


logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    level=logging.INFO,
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

ALLOWED_CHAT_IDS = config.allowed_chat_ids()
TEMP_DIR = Path(__file__).resolve().parent / "temp_pdfs"
TEMP_DIR.mkdir(mode=0o700, exist_ok=True)

document_texts: dict[str, str] = {}
document_names: dict[str, str] = {}
histories: dict[str, list[dict]] = {}
user_locks: dict[str, asyncio.Lock] = {}


@dataclass
class BotStats:
    started_at: float = field(default_factory=time.time)
    pdfs: int = 0
    images: int = 0
    questions: int = 0
    generations: int = 0


stats = BotStats()


def permitted(update: Update) -> bool:
    chat = update.effective_chat
    if not chat:
        return False
    allowed = not ALLOWED_CHAT_IDS or chat.id in ALLOWED_CHAT_IDS
    if not allowed:
        logger.warning("Acesso recusado para o chat %s", chat.id)
    return allowed


async def reject(update: Update) -> None:
    if update.callback_query:
        await update.callback_query.answer("Acesso não autorizado.", show_alert=True)
    elif update.effective_message:
        await update.effective_message.reply_text("Acesso não autorizado.")


def main_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📄 Estudar PDF", callback_data="help_pdf"),
                InlineKeyboardButton("🖼 Analisar imagem", callback_data="help_image"),
            ],
            [
                InlineKeyboardButton("💬 Conversar", callback_data="help_chat"),
                InlineKeyboardButton("📊 Meu painel", callback_data="dashboard"),
            ],
            [
                InlineKeyboardButton("🧹 Limpar sessão", callback_data="clear"),
                InlineKeyboardButton("ℹ️ Ajuda", callback_data="help"),
            ],
        ]
    )


def document_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [
            [
                InlineKeyboardButton("📝 Resumo", callback_data="generate:summary"),
                InlineKeyboardButton("❓ Questões", callback_data="generate:questions"),
            ],
            [
                InlineKeyboardButton("🧠 Flashcards", callback_data="generate:flashcards"),
                InlineKeyboardButton("✨ Kit completo", callback_data="generate:all"),
            ],
            [InlineKeyboardButton("‹ Menu principal", callback_data="dashboard")],
        ]
    )


def back_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        [[InlineKeyboardButton("‹ Voltar ao painel", callback_data="dashboard")]]
    )


def uptime() -> str:
    total = int(time.time() - stats.started_at)
    hours, remainder = divmod(total, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{hours}h {minutes}min" if hours else f"{minutes}min"


def dashboard_text(chat_id: str) -> str:
    history_size = len(histories.get(chat_id, [])) // 2
    has_pdf = chat_id in document_texts
    provider = config.active_ai_provider()
    ai_state = {
        "gemini": f"Gemini · {config.GEMINI_MODEL}",
        "groq": f"Groq · {config.GROQ_MODEL}",
    }.get(provider, "não configurada")
    return (
        "<b>🎓 CENTRAL DE ESTUDOS</b>\n"
        "<i>Assistente acadêmico com inteligência artificial</i>\n\n"
        f"🟢 <b>Estado:</b> OPERACIONAL\n"
        f"🤖 <b>IA:</b> {ai_state}\n"
        f"📄 <b>PDF carregado:</b> {'sim' if has_pdf else 'não'}\n"
        f"💬 <b>Mensagens na sessão:</b> {history_size}\n"
        f"⏱ <b>Uptime:</b> {uptime()}\n\n"
        "<b>Como começar</b>\n"
        "Envie um PDF, uma imagem ou simplesmente escreva uma pergunta."
    )


def help_text() -> str:
    return (
        "<b>ℹ️ GUIA RÁPIDO</b>\n\n"
        "📄 <b>PDF</b>\n"
        "Envie um documento para gerar resumo, questões e flashcards.\n\n"
        "🖼 <b>Imagem</b>\n"
        "Envie uma foto com uma legenda dizendo o que deseja analisar.\n\n"
        "💬 <b>Chat</b>\n"
        "Faça perguntas sobre qualquer matéria. O contexto é mantido durante a sessão.\n\n"
        "🧹 <b>Limpar sessão</b>\n"
        "Remove o histórico da conversa e o PDF carregado."
    )


async def edit_or_reply(
    update: Update,
    text: str,
    keyboard: InlineKeyboardMarkup,
) -> None:
    if update.callback_query:
        try:
            await update.callback_query.edit_message_text(
                text,
                parse_mode=ParseMode.HTML,
                reply_markup=keyboard,
            )
        except BadRequest as exc:
            if "Message is not modified" not in str(exc):
                raise
        return
    await update.effective_message.reply_text(
        text,
        parse_mode=ParseMode.HTML,
        reply_markup=keyboard,
    )


async def send_long(message, title: str, content: str) -> None:
    text = content.strip() or "Não foi possível gerar o conteúdo."
    max_size = 3800
    parts = [text[i : i + max_size] for i in range(0, len(text), max_size)]
    for index, part in enumerate(parts, start=1):
        heading = title if len(parts) == 1 else f"{title} · {index}/{len(parts)}"
        await message.reply_text(
            f"<b>{html.escape(heading)}</b>\n\n{html.escape(part)}",
            parse_mode=ParseMode.HTML,
        )


async def show_dashboard(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not permitted(update):
        return await reject(update)
    chat_id = str(update.effective_chat.id)
    await edit_or_reply(update, dashboard_text(chat_id), main_keyboard())


async def show_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not permitted(update):
        return await reject(update)
    await edit_or_reply(update, help_text(), back_keyboard())


async def clear_session(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not permitted(update):
        return await reject(update)
    chat_id = str(update.effective_chat.id)
    histories.pop(chat_id, None)
    document_texts.pop(chat_id, None)
    document_names.pop(chat_id, None)
    text = (
        "<b>🧹 SESSÃO LIMPA</b>\n\n"
        "O histórico da conversa e o documento carregado foram removidos."
    )
    await edit_or_reply(update, text, main_keyboard())


async def handle_pdf(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not permitted(update):
        return await reject(update)
    chat_id = str(update.effective_chat.id)
    document = update.message.document
    if not document.file_name.lower().endswith(".pdf"):
        await update.message.reply_text("Envie um arquivo no formato PDF.")
        return

    progress = await update.message.reply_text(
        "📥 <b>Recebendo documento...</b>",
        parse_mode=ParseMode.HTML,
    )
    path = TEMP_DIR / f"{chat_id}_{int(time.time())}.pdf"
    try:
        telegram_file = await context.bot.get_file(
            document.file_id,
            read_timeout=60,
            connect_timeout=60,
        )
        await telegram_file.download_to_drive(
            path,
            read_timeout=120,
            connect_timeout=60,
        )
        await progress.edit_text(
            "🔎 <b>Extraindo e analisando o texto...</b>",
            parse_mode=ParseMode.HTML,
        )
        text = await asyncio.to_thread(extrair_texto, str(path))
    except Exception:
        logger.exception("Falha ao processar PDF")
        await progress.edit_text("Não foi possível processar esse PDF.")
        return
    finally:
        path.unlink(missing_ok=True)

    if len(text) < 100:
        await progress.edit_text(
            "Não encontrei texto suficiente. Tente um PDF com texto selecionável."
        )
        return

    document_texts[chat_id] = text
    document_names[chat_id] = document.file_name
    stats.pdfs += 1
    pages = getattr(document, "file_size", 0) / (1024**2)
    await progress.edit_text(
        "<b>✅ DOCUMENTO PRONTO</b>\n\n"
        f"📄 <b>Arquivo:</b> {html.escape(document.file_name)}\n"
        f"📝 <b>Palavras:</b> {len(text.split()):,}\n"
        f"💾 <b>Tamanho:</b> {pages:.1f} MB\n\n"
        "Escolha o material que deseja gerar:",
        parse_mode=ParseMode.HTML,
        reply_markup=document_keyboard(),
    )


async def handle_photo(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not permitted(update):
        return await reject(update)
    chat_id = str(update.effective_chat.id)
    progress = await update.message.reply_text("🔍 Analisando a imagem...")
    path = TEMP_DIR / f"{chat_id}_{int(time.time())}.jpg"
    try:
        photo = update.message.photo[-1]
        telegram_file = await context.bot.get_file(photo.file_id)
        await telegram_file.download_to_drive(path)
        image_bytes = await asyncio.to_thread(path.read_bytes)
        answer = await asyncio.to_thread(
            chamar_groq_com_imagem,
            update.message.caption or "Analise esta imagem para fins de estudo.",
            image_bytes,
        )
        stats.images += 1
        await progress.delete()
        await send_long(update.message, "🖼 ANÁLISE DA IMAGEM", answer)
    except Exception:
        logger.exception("Falha ao analisar imagem")
        await progress.edit_text("Não foi possível analisar a imagem.")
    finally:
        path.unlink(missing_ok=True)


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not permitted(update):
        return await reject(update)
    chat_id = str(update.effective_chat.id)
    lock = user_locks.setdefault(chat_id, asyncio.Lock())
    if lock.locked():
        await update.message.reply_text("Ainda estou processando sua mensagem anterior.")
        return

    async with lock:
        history = histories.setdefault(chat_id, [])
        await update.message.chat.send_action(ChatAction.TYPING)
        try:
            answer = await asyncio.to_thread(chat, history, update.message.text)
            history.extend(
                [
                    {"role": "user", "content": update.message.text},
                    {"role": "assistant", "content": answer},
                ]
            )
            histories[chat_id] = history[-20:]
            stats.questions += 1
            await send_long(update.message, "💬 RESPOSTA", answer)
        except Exception:
            logger.exception("Falha no chat de estudos")
            await update.message.reply_text("Não consegui responder agora. Tente novamente.")


async def generate_content(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query or not permitted(update):
        return await reject(update)
    await query.answer()
    chat_id = str(update.effective_chat.id)
    text = document_texts.get(chat_id)
    if not text:
        await query.edit_message_text(
            "O documento não está mais carregado. Envie o PDF novamente.",
            reply_markup=main_keyboard(),
        )
        return

    action = query.data.split(":", 1)[1]
    lock = user_locks.setdefault(chat_id, asyncio.Lock())
    if lock.locked():
        await query.answer("Já existe uma geração em andamento.", show_alert=True)
        return

    labels = {
        "summary": ("📝 RESUMO", gerar_resumo),
        "questions": ("❓ QUESTÕES", gerar_questoes),
        "flashcards": ("🧠 FLASHCARDS", gerar_flashcards),
    }
    await query.edit_message_text(
        "<b>✨ GERANDO MATERIAL...</b>\n\n"
        "A IA está preparando o conteúdo. Você pode continuar usando outros bots.",
        parse_mode=ParseMode.HTML,
    )

    async with lock:
        try:
            selected = list(labels) if action == "all" else [action]
            for item in selected:
                title, generator = labels[item]
                result = await asyncio.to_thread(generator, text)
                await send_long(query.message, title, result)
                stats.generations += 1
            await query.message.reply_text(
                "<b>✅ MATERIAL CONCLUÍDO</b>\n\n"
                f"Documento: {html.escape(document_names.get(chat_id, 'PDF atual'))}",
                parse_mode=ParseMode.HTML,
                reply_markup=document_keyboard(),
            )
        except Exception:
            logger.exception("Falha ao gerar material")
            await query.message.reply_text(
                "Não foi possível gerar o material.",
                reply_markup=document_keyboard(),
            )


async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    if not query:
        return
    if query.data.startswith("generate:"):
        return await generate_content(update, context)
    await query.answer()
    actions = {
        "dashboard": show_dashboard,
        "help": show_help,
        "clear": clear_session,
        "help_pdf": show_help,
        "help_image": show_help,
        "help_chat": show_help,
    }
    action = actions.get(query.data)
    if action:
        await action(update, context)


async def post_init(application: Application) -> None:
    await application.bot.set_my_commands(
        [
            BotCommand("painel", "Abrir central de estudos"),
            BotCommand("ajuda", "Ver instruções"),
            BotCommand("limpar", "Limpar sessão atual"),
            BotCommand("chatid", "Mostrar o ID deste chat"),
        ]
    )


async def show_chat_id(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    if not permitted(update):
        return await reject(update)
    await update.message.reply_text(f"Chat ID: <code>{update.effective_chat.id}</code>", parse_mode=ParseMode.HTML)


async def handle_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    logger.exception("Erro ao processar atualização", exc_info=context.error)


def main() -> None:
    if not config.TELEGRAM_TOKEN:
        raise RuntimeError("TELEGRAM_TOKEN não configurado.")
    request = HTTPXRequest(
        connect_timeout=30,
        read_timeout=120,
        write_timeout=120,
        pool_timeout=30,
    )
    application = (
        Application.builder()
        .token(config.TELEGRAM_TOKEN)
        .request(request)
        .post_init(post_init)
        .build()
    )
    application.add_handler(CommandHandler(["start", "painel"], show_dashboard))
    application.add_handler(CommandHandler("ajuda", show_help))
    application.add_handler(CommandHandler("limpar", clear_session))
    application.add_handler(CommandHandler("chatid", show_chat_id))
    application.add_handler(MessageHandler(filters.Document.PDF, handle_pdf))
    application.add_handler(MessageHandler(filters.PHOTO, handle_photo))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_error_handler(handle_error)
    logger.info("Central de estudos iniciada")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
