"""Utilidades de PDF para los vectores de ataque: añadir texto y escribir metadatos.

Se apoya en `reportlab` (construir la página o la capa a estampar) y `pypdf` (fundirla
con el PDF limpio), las mismas dependencias que ya usa el render del dataset. Todo es
determinista: `invariant=True` en reportlab y sin fechas, para que el envenenado difiera
del limpio solo en la inyección.
"""

from __future__ import annotations

import io

from pypdf import PdfReader, PdfWriter


def _text_page_pdf(text: str, *, invisible: bool) -> bytes:
    """Un PDF de una página con `text`. Si `invisible`, en modo de render 3 (no se ve)."""
    from reportlab.lib.pagesizes import LETTER
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=LETTER, invariant=True)
    width, height = LETTER
    text_object = pdf.beginText(2 * 28.35, height - 2 * 28.35)  # margen de 2 cm
    text_object.setFont("Helvetica", 11)
    # Modo 3 = "no dibujar": pypdf lo extrae igual que el texto visible, pero un humano
    # no lo ve. Es lo que explota el vector pdf_hidden (variante render_mode_3).
    text_object.setTextRenderMode(3 if invisible else 0)
    for line in text.split("\n"):
        text_object.textLine(line)
    pdf.drawText(text_object)
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()


def append_text_page(pdf_bytes: bytes, text: str, *, invisible: bool = False) -> bytes:
    """Añade una página nueva con `text` al final del PDF. No toca las páginas visibles."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    extra = PdfReader(io.BytesIO(_text_page_pdf(text, invisible=invisible)))
    writer.add_page(extra.pages[0])
    _carry_metadata(reader, writer)
    return _to_bytes(writer)


def overlay_invisible(pdf_bytes: bytes, text: str) -> bytes:
    """Estampa `text` en modo invisible sobre la primera página, sin añadir páginas."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    layer = PdfReader(io.BytesIO(_text_page_pdf(text, invisible=True)))
    first = reader.pages[0]
    first.merge_page(layer.pages[0])
    writer.add_page(first)
    for page in reader.pages[1:]:
        writer.add_page(page)
    _carry_metadata(reader, writer)
    return _to_bytes(writer)


def set_metadata(pdf_bytes: bytes, extra: dict[str, str]) -> bytes:
    """Escribe/mezcla metadatos del documento (p. ej. /Subject, /Keywords)."""
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    merged = dict(reader.metadata or {})
    merged.update(extra)
    writer.add_metadata(merged)
    return _to_bytes(writer)


def _carry_metadata(reader: PdfReader, writer: PdfWriter) -> None:
    if reader.metadata:
        writer.add_metadata(dict(reader.metadata))


def _to_bytes(writer: PdfWriter) -> bytes:
    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()
