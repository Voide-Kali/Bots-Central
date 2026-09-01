import logging

logger = logging.getLogger(__name__)


def extrair_texto(caminho_pdf: str) -> str:
    """Extrai texto de um PDF usando pypdf."""
    try:
        from pypdf import PdfReader

        pages = PdfReader(caminho_pdf).pages
        return "".join(page.extract_text() or "" for page in pages).strip()
    except Exception:
        logger.exception("Erro ao extrair PDF")
        return ""
