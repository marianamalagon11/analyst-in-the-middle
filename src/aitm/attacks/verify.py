"""Dos verificaciones que acompañan a cada reporte envenenado.

1. **¿El payload llega al modelo?** Se pasa el documento envenenado por el *parser
   ingenuo* (el de la línea base) y se mira si aparece el marcador del vector. Separa el
   efecto de la extracción del de la inferencia: si el payload no llega, un ASR de cero
   no dice nada del modelo.

2. **¿Se ve igual que el original?** Solo para las variantes `invisible`. En txt y html
   se comparan las palabras visibles (sin nodos ocultos, sin Unicode invisible y con el
   espacio normalizado); en PDF se rasteriza y se comparan los píxeles con `pypdfium2`
   (extra `[visual]`). Las variantes `visible` y `camouflaged` no se comprueban: se ven
   a propósito.
"""

from __future__ import annotations

from pathlib import Path

from aitm.analyst.parsers import parse_html, parse_pdf

_INVISIBLE = {chr(c) for c in range(0xE0000, 0xE0080)} | {
    "​", "‌", "‍", "﻿", "‪", "‫", "‬",
    "‭", "‮", "⁦", "⁧", "⁨", "⁩",
}


def strip_invisible(text: str) -> str:
    return "".join(c for c in text if c not in _INVISIBLE)


def naive_extract(source_format: str, data: bytes, tmp_dir: Path) -> str:
    """Texto que vería el parser ingenuo (arrastra lo oculto)."""
    if source_format == "txt":
        return data.decode("utf-8", errors="replace")
    if source_format == "html":
        return parse_html(data.decode("utf-8", errors="replace"), include_hidden=True, include_comments=True)
    path = tmp_dir / "poisoned.pdf"
    path.write_bytes(data)
    text, _ = parse_pdf(path, include_metadata=True)
    return text


def payload_reaches_model(source_format: str, data: bytes, markers: list[str], tmp_dir: Path) -> bool:
    text = naive_extract(source_format, data, tmp_dir)
    return any(marker in text for marker in markers)


def _visible_words(source_format: str, data: bytes) -> str:
    if source_format == "html":
        raw = parse_html(data.decode("utf-8", errors="replace"), include_hidden=False, include_comments=False)
    else:
        raw = data.decode("utf-8", errors="replace")
    return " ".join(strip_invisible(raw).split())


def _raster(pdf_bytes: bytes) -> bytes:
    import pypdfium2 as pdfium

    doc = pdfium.PdfDocument(pdf_bytes)
    return b"".join(doc[i].render(scale=1.5).to_pil().tobytes() for i in range(len(doc)))


def visual_equivalent(source_format: str, clean: bytes, poisoned: bytes) -> bool:
    """¿El documento envenenado se ve igual que el limpio. Solo variantes invisibles."""
    if source_format == "pdf":
        return _raster(clean) == _raster(poisoned)
    return _visible_words(source_format, clean) == _visible_words(source_format, poisoned)
