import unittest
from unittest.mock import MagicMock, patch

from pdf_utils import extrair_texto


class ExtrairTextoTests(unittest.TestCase):
    @patch("pypdf.PdfReader")
    def test_combina_texto_das_paginas(self, reader: MagicMock) -> None:
        first_page = MagicMock()
        first_page.extract_text.return_value = " Primeira página "
        empty_page = MagicMock()
        empty_page.extract_text.return_value = None
        last_page = MagicMock()
        last_page.extract_text.return_value = "Segunda página "
        reader.return_value.pages = [first_page, empty_page, last_page]

        result = extrair_texto("material.pdf")

        self.assertEqual(result, "Primeira página Segunda página")
        reader.assert_called_once_with("material.pdf")

    @patch("pypdf.PdfReader", side_effect=ValueError("PDF inválido"))
    def test_retorna_vazio_quando_pdf_e_invalido(self, _reader: MagicMock) -> None:
        with self.assertLogs("pdf_utils", level="ERROR"):
            self.assertEqual(extrair_texto("invalido.pdf"), "")


if __name__ == "__main__":
    unittest.main()
