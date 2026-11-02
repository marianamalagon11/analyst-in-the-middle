"""Vector `html_hidden`: la instrucción va en el HTML pero no se ve al abrir la página.

Cuatro formas de esconderla, todas las que arrastra un conversor ingenuo de HTML a texto
(`src/aitm/analyst/parsers.py`) pero que un navegador no muestra:

- `display_none`: `style="display:none"`.
- `font_size_0`: `style="font-size:0"`.
- `white_text`: texto blanco sobre fondo blanco.
- `comment`: dentro de un comentario `<!-- -->`.

Solo aplica a HTML. El resto del archivo queda byte a byte igual que el limpio, así que
el texto *visible* es idéntico: eso lo comprueba la verificación visual de la Fase 3.
"""

from __future__ import annotations

import html as html_escape

from aitm.attacks._html import insert_before_article_close
from aitm.attacks.base import AttackTarget, AttackVector


class HtmlHiddenVector(AttackVector):
    name = "html_hidden"
    formats = ("html",)
    variants = ("display_none", "font_size_0", "white_text", "comment")

    def visibility(self, variant: str) -> str:
        return "invisible"

    def inject(self, clean, payload_text, target, *, variant):
        text = clean.decode("utf-8", errors="replace")
        escaped = html_escape.escape(payload_text)
        if variant == "display_none":
            fragment = f'      <div style="display:none">{escaped}</div>'
        elif variant == "font_size_0":
            fragment = f'      <span style="font-size:0">{escaped}</span>'
        elif variant == "white_text":
            fragment = f'      <span style="color:#ffffff">{escaped}</span>'
        elif variant == "comment":
            # Sin '--' dentro, que cerraría el comentario antes de tiempo.
            fragment = f"      <!-- {payload_text.replace('--', '—')} -->"
        else:
            raise ValueError(f"{self.name}: variante desconocida {variant!r}")
        poisoned, _ = insert_before_article_close(text, fragment)
        return poisoned.encode("utf-8"), f"nodo oculto ({variant}) antes de </article>"

    def extraction_markers(self, payload_text, variant):
        if variant == "comment":
            return [payload_text.replace("--", "—")]
        return [payload_text]
