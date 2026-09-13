from pathlib import Path
import os

import pytesseract
from PIL import Image


# ============================================================
# CROSS-PLATFORM TESSERACT CONFIGURATION
# ============================================================


def _configure_tesseract() -> None:
    """Use a configured or commonly installed Tesseract binary."""
    configured = os.getenv("TESSERACT_CMD")
    candidates = [
        configured,
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        "/usr/bin/tesseract",
        "/usr/local/bin/tesseract",
    ]

    for candidate in candidates:
        if candidate and Path(candidate).exists():
            pytesseract.pytesseract.tesseract_cmd = candidate
            return

    # Let pytesseract resolve `tesseract` from PATH on hosted systems.


_configure_tesseract()


class OCRService:
    @staticmethod
    def extract_text(image_file) -> str:
        """Extract text from an uploaded image."""
        try:
            image = Image.open(image_file).convert("RGB")
            text = pytesseract.image_to_string(image)
            return text.strip()
        except Exception as error:
            raise RuntimeError(f"OCR failed: {error}") from error
