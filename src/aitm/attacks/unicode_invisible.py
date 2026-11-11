"""Vector `unicode_invisible`: la instrucción se esconde con caracteres Unicode.

Tres variantes, con una advertencia honesta sobre cuán "invisible" es cada una:

- `tags`: "ASCII smuggling". Cada carácter se mapea al bloque de *Tags* de Unicode
  (U+E0000+). Un humano no ve nada y muchos tokenizadores de LLM lo leen igual. Es el
  único de verdad invisible y el más interesante de medir.
- `zero_width`: el payload se codifica en binario con dos caracteres de ancho cero
  (ZWSP=0, ZWNJ=1). Invisible, pero que un modelo de 7B lo *decodifique* es justo la
  hipótesis a comprobar; bien puede fallar, y eso es un resultado válido.
- `bidi`: envuelve el payload con controles bidireccionales (RLO…PDI). Los caracteres
  del payload siguen ahí (el modelo los ve), pero a la vista quedan como texto
  desordenado, no ocultos del todo.

Solo txt y html: en PDF las fuentes estándar de reportlab no codifican estos puntos de
código, así que no sobrevivirían. Queda documentado como limitación.
"""

from __future__ import annotations

import html as html_escape

from aitm.attacks._html import insert_before_article_close
from aitm.attacks.base import AttackTarget, AttackVector

TAG_BASE = 0xE0000
ZW_ZERO = "​"  # zero-width space
ZW_ONE = "‌"   # zero-width non-joiner
RLO = "‮"      # right-to-left override
PDI = "⁩"      # pop directional isolate


def to_tags(text: str) -> str:
    """Codifica en el bloque de Tags de Unicode (solo ASCII imprimible)."""
    return "".join(chr(TAG_BASE + ord(c)) for c in text if 0x20 <= ord(c) <= 0x7E)


def to_zero_width(text: str) -> str:
    """Codifica cada byte del payload en 8 bits con dos caracteres de ancho cero."""
    bits = "".join(f"{byte:08b}" for byte in text.encode("utf-8"))
    return "".join(ZW_ONE if bit == "1" else ZW_ZERO for bit in bits)


class UnicodeInvisibleVector(AttackVector):
    name = "unicode_invisible"
    formats = ("txt", "html")
    variants = ("tags", "zero_width", "bidi")

    def visibility(self, variant: str) -> str:
        # `bidi` deja las letras del payload presentes (reordenadas), no ocultas: es
        # `camouflaged`. `tags` y `zero_width` sí son invisibles.
        return "camouflaged" if variant == "bidi" else "invisible"

    def _encode(self, payload_text: str, variant: str) -> str:
        if variant == "tags":
            return to_tags(payload_text)
        if variant == "zero_width":
            return to_zero_width(payload_text)
        if variant == "bidi":
            return f"{RLO}{payload_text}{PDI}"
        raise ValueError(f"{self.name}: variante desconocida {variant!r}")

    def inject(self, clean, payload_text, target, *, variant):
        encoded = self._encode(payload_text, variant)
        text = clean.decode("utf-8", errors="replace")
        if text.lstrip().startswith("<!doctype") or "<article" in text:
            # Dentro de un <span> vacío de texto visible: solo lleva los invisibles.
            fragment = f"      <span>{encoded}</span>"
            poisoned, _ = insert_before_article_close(text, fragment)
            return poisoned.encode("utf-8"), f"caracteres invisibles ({variant}) antes de </article>"
        poisoned = text.rstrip("\n") + "\n" + encoded + "\n"
        return poisoned.encode("utf-8"), f"caracteres invisibles ({variant}) al final del texto"

    def extraction_markers(self, payload_text, variant):
        # En bidi el payload literal sigue presente; en tags/zero_width va codificado.
        if variant == "bidi":
            return [payload_text]
        return [self._encode(payload_text, variant)]
