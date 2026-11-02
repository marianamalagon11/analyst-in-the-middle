"""Registro de vectores: nombre -> instancia. Un sitio único para listarlos y buscarlos.

Agregar un vector nuevo es registrarlo aquí; el resto del sistema (CLI, generador) lo
descubre solo.
"""

from __future__ import annotations

from aitm.attacks.author_note import AuthorNoteVector
from aitm.attacks.base import AttackVector
from aitm.attacks.html_hidden import HtmlHiddenVector
from aitm.attacks.pdf_hidden import PdfHiddenVector
from aitm.attacks.plaintext import PlaintextVector
from aitm.attacks.unicode_invisible import UnicodeInvisibleVector

_VECTORS: dict[str, AttackVector] = {
    vector.name: vector
    for vector in (
        PlaintextVector(),
        AuthorNoteVector(),
        HtmlHiddenVector(),
        UnicodeInvisibleVector(),
        PdfHiddenVector(),
    )
}


def all_vectors() -> list[AttackVector]:
    return list(_VECTORS.values())


def get_vector(name: str) -> AttackVector:
    try:
        return _VECTORS[name]
    except KeyError:
        raise KeyError(
            f"vector desconocido: {name!r}. Registrados: {sorted(_VECTORS)}"
        ) from None


def vectors_for_format(source_format: str) -> list[AttackVector]:
    return [v for v in _VECTORS.values() if source_format in v.formats]
