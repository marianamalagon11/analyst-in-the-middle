"""Vector `pdf_hidden`: la instrucción va en el PDF pero no se ve al abrirlo.

Dos variantes, las de la arquitectura:

- `metadata`: escribe el payload en los metadatos del documento (`/Subject` y
  `/Keywords`). El parser ingenuo arrastra esos metadatos al texto (ver `parsers.py`),
  un lector de PDF normal no los muestra en la página.
- `render_mode_3`: estampa el payload sobre la primera página en modo de render 3
  ("no dibujar"). `pypdf` lo extrae igual que el texto visible; un humano no lo ve.

Solo PDF. Las páginas visibles no se tocan, así que la verificación visual (rasterizar
y comparar) debe dar diferencia cero.
"""

from __future__ import annotations

from aitm.attacks.base import AttackTarget, AttackVector
from aitm.attacks.pdfutil import overlay_invisible, set_metadata


class PdfHiddenVector(AttackVector):
    name = "pdf_hidden"
    formats = ("pdf",)
    variants = ("metadata", "render_mode_3")

    def visibility(self, variant: str) -> str:
        return "invisible"

    def inject(self, clean, payload_text, target, *, variant):
        if clean[:5] != b"%PDF-":
            raise ValueError(f"{self.name}: el documento no es un PDF")
        if variant == "metadata":
            poisoned = set_metadata(clean, {"/Subject": payload_text, "/Keywords": payload_text})
            return poisoned, "payload en los metadatos /Subject y /Keywords"
        if variant == "render_mode_3":
            poisoned = overlay_invisible(clean, payload_text)
            return poisoned, "texto en modo de render invisible sobre la primera página"
        raise ValueError(f"{self.name}: variante desconocida {variant!r}")
