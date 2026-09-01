import logging

logger = logging.getLogger(__name__)


def extrair_texto(caminho_pdf: str) -> str:
    """Extrai texto de um PDF usando pypdf."""
    try:
        from pypdf import PdfReader
        reader = PdfReader(caminho_pdf)
        texto = ""
        for page in reader.pages:
            texto += page.extract_text() or ""
        return texto.strip()
    except Exception as e:
        logger.error(f"Erro ao extrair PDF: {e}")
        return ""


def dividir_em_chunks(texto: str, max_chars: int = 3000) -> list:
    """Divide o texto em partes menores para a IA processar."""
    palavras = texto.split()
    chunks = []
    chunk_atual = []
    tamanho_atual = 0

    for palavra in palavras:
        tamanho_atual += len(palavra) + 1
        if tamanho_atual > max_chars:
            chunks.append(" ".join(chunk_atual))
            chunk_atual = [palavra]
            tamanho_atual = len(palavra)
        else:
            chunk_atual.append(palavra)

    if chunk_atual:
        chunks.append(" ".join(chunk_atual))

    return chunks
