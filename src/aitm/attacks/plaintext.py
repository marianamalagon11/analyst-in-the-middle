"""Vector `plaintext`: la instrucción va a la vista, camuflada en el cuerpo del reporte.

Es el ataque más simple y el más fácil de detectar por un humano. Sirve de referencia:
si ni siquiera la instrucción visible mueve al modelo, los vectores ocultos tampoco
deberían. Por eso su visibilidad es `visible` y no se le exige equivalencia visual.
"""

from __future__ import annotations

import html as html_escape

from aitm.attacks._html import insert_before_article_close
from aitm.attacks.base import AttackTarget, AttackVector
from aitm.attacks.pdfutil import append_text_page


class PlaintextVector(AttackVector):
    name = "plaintext"
    formats = ("txt", "html", "pdf")
    variants = ("inline",)

    def visibility(self, variant: str) -> str:
        return "visible"

    def inject(self, clean, payload_text, target, *, variant):
        if variant not in self.variants:
            raise ValueError(f"{self.name}: variante desconocida {variant!r}")
        text = clean.decode("utf-8", errors="replace")

        if text.lstrip().startswith("<!doctype") or "<article" in text:
            fragment = f"      <p>{html_escape.escape(payload_text)}</p>"
            poisoned, _ = insert_before_article_close(text, fragment)
            return poisoned.encode("utf-8"), "párrafo visible antes de </article>"

        if text.startswith("%PDF") or clean[:5] == b"%PDF-":
            return append_text_page(clean, payload_text, invisible=False), "página visible al final del PDF"

        # txt: una línea más en el cuerpo.
        poisoned = text.rstrip("\n") + "\n\n" + payload_text + "\n"
        return poisoned.encode("utf-8"), "línea visible al final del texto"
