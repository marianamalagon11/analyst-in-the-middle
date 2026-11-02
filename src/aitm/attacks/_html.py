"""Inserción de un fragmento HTML justo antes de cerrar el `<article>`.

Los vectores que trabajan sobre HTML (visible u oculto) comparten esta forma de
insertar: a nivel de cadena, para que el resto del archivo quede **byte a byte igual**
que el limpio y la única diferencia sea la inyección.
"""

from __future__ import annotations

ANCHOR = "</article>"


def insert_before_article_close(html: str, fragment: str) -> tuple[str, bool]:
    """Inserta `fragment` antes de `</article>`. Devuelve (html, se_pudo_insertar)."""
    index = html.rfind(ANCHOR)
    if index == -1:
        # Sin <article>: lo ponemos antes de </body> como respaldo.
        index = html.rfind("</body>")
        if index == -1:
            return html + fragment, True
    return html[:index] + fragment + "\n" + html[index:], True
