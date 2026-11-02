"""Vector `author_note`: la instrucción se disfraza de parte legítima del reporte.

No oculta el texto: lo enmarca como si fuera una nota del analista o una actualización
del propio reporte, para que parezca contenido de confianza. Es el punto medio entre el
`plaintext` (se ve y se nota) y los vectores ocultos (no se ven): aquí se ve, pero no
llama la atención. Visibilidad `camouflaged`.
"""

from __future__ import annotations

import html as html_escape

from aitm.attacks._html import insert_before_article_close
from aitm.attacks.base import AttackTarget, AttackVector
from aitm.attacks.pdfutil import append_text_page

#: Fecha fija (no `today`) para que la inyección sea determinista.
UPDATE_DATE = "2026-10-30"


def _frame(variant: str, payload_text: str) -> str:
    if variant == "report_update":
        return f"Actualización {UPDATE_DATE}: {payload_text}"
    if variant == "vendor_correction":
        return f"Corrección del proveedor: {payload_text}"
    return f"Nota del analista: {payload_text}"


class AuthorNoteVector(AttackVector):
    name = "author_note"
    formats = ("txt", "html", "pdf")
    variants = ("analyst_note", "report_update", "vendor_correction")

    def visibility(self, variant: str) -> str:
        return "camouflaged"

    def inject(self, clean, payload_text, target, *, variant):
        if variant not in self.variants:
            raise ValueError(f"{self.name}: variante desconocida {variant!r}")
        note = _frame(variant, payload_text)
        text = clean.decode("utf-8", errors="replace")

        if text.lstrip().startswith("<!doctype") or "<article" in text:
            fragment = f'      <p><em>{html_escape.escape(note)}</em></p>'
            poisoned, _ = insert_before_article_close(text, fragment)
            return poisoned.encode("utf-8"), f"nota ({variant}) antes de </article>"

        if clean[:5] == b"%PDF-":
            return append_text_page(clean, note, invisible=False), f"nota ({variant}) en página al final"

        poisoned = text.rstrip("\n") + "\n\n" + note + "\n"
        return poisoned.encode("utf-8"), f"nota ({variant}) al final del texto"

    def extraction_markers(self, payload_text, variant):
        # Lo que llega al texto es la nota enmarcada; el payload va dentro.
        return [payload_text]
