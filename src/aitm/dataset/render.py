"""Render de un reporte en texto a los tres formatos del laboratorio: txt, html, pdf.

Por que renderizamos nosotros en vez de descargar HTML y PDF reales:

1. **Licencia.** El corpus que usamos (AnnoCTR, CC-BY-SA 4.0) distribuye el texto de
   los reportes, no las paginas originales. Bajar los HTML de los blogs de los vendors
   seria redistribuir material con copyright propio y sin licencia clara.
2. **Control del experimento.** Para medir el efecto de un vector de ataque necesitamos
   que la version limpia y la envenenada difieran *solo* en la inyeccion. Partiendo del
   mismo texto y el mismo render, esa es la unica diferencia.
3. **Reutilizacion.** Los vectores `html_hidden` y `pdf_hidden` de la Fase 3 necesitan
   generar HTML y PDF de todos modos; este modulo es la base limpia sobre la que
   inyectan.

El HTML imita la estructura de un blog de vendor (cabecera, articulo, pie) para que el
contenido no confiable llegue al modelo rodeado del mismo ruido que en la vida real.
"""

from __future__ import annotations

import html as html_escape
import re
from pathlib import Path

#: Metadatos que se escriben en el PDF limpio. El vector `pdf_hidden` los sobreescribe.
DEFAULT_PDF_METADATA = {
    "author": "Threat Research",
    "subject": "Cyber threat intelligence report",
}


def split_title(text: str) -> tuple[str, str]:
    """Separa la primera linea no vacia como titulo y devuelve el resto del cuerpo."""
    lines = text.strip().split("\n")
    for index, line in enumerate(lines):
        if line.strip():
            title = re.sub(r"^#+\s*|\*+", "", line).strip()
            body = "\n".join(lines[index + 1 :]).strip()
            return title or "Threat Report", body
    return "Threat Report", ""


#: Longitud a partir de la cual un token se considera "indicador largo" (hash, URL).
LONG_TOKEN = 24


def has_long_token(line: str) -> bool:
    """La linea contiene un token largo sin espacios: casi seguro un hash o una URL."""
    return any(len(token) >= LONG_TOKEN for token in line.split())


def _blocks(body: str) -> list[tuple[str, str]]:
    """Trocea el cuerpo en bloques ('heading'|'paragraph'|'mono', texto).

    Los textos de AnnoCTR conservan marcas tipo markdown de los blogs originales
    (`### **IOCs**`), que son la pista mas fiable de donde empieza cada seccion.

    Las lineas con tokens largos se marcan como `mono`: en el PDF se renderizan en
    monoespaciada pequena para que un sha256 completo entre en una sola linea. Sin
    eso, el salto de linea parte el hash y `pypdf` lo devuelve en dos pedazos, lo que
    hundiria el recall de IoCs del formato PDF por una razon que no tiene nada que ver
    con el modelo. Las URLs de mas de ~100 caracteres se parten igual: ver la nota de
    limitaciones en docs/DATASET.md.
    """
    result: list[tuple[str, str]] = []
    for raw in re.split(r"\n\s*\n", body):
        chunk = raw.strip()
        if not chunk:
            continue
        for line in chunk.split("\n"):
            line = line.strip()
            if not line:
                continue
            if re.match(r"^#{1,6}\s", line) or re.match(r"^\*\*[^*]{1,80}\*\*$", line):
                result.append(("heading", re.sub(r"^#+\s*|\*+", "", line).strip()))
            elif has_long_token(line):
                result.append(("mono", line))
            else:
                result.append(("paragraph", line))
    return result


def render_txt(text: str) -> str:
    """El formato txt es el texto tal cual, con salto de linea final."""
    return text.strip() + "\n"


def render_html(text: str, *, report_id: str = "") -> str:
    """Envuelve el reporte en una pagina de blog de vendor plausible."""
    title, body = split_title(text)
    parts: list[str] = []
    for kind, content in _blocks(body):
        escaped = html_escape.escape(content)
        if kind == "heading":
            parts.append(f"      <h2>{escaped}</h2>")
        else:
            parts.append(f"      <p>{escaped}</p>")
    article = "\n".join(parts)
    safe_title = html_escape.escape(title)
    identifier = html_escape.escape(report_id)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{safe_title}</title>
  <meta name="description" content="Threat research publication">
</head>
<body>
  <header>
    <nav><a href="/">Home</a> &middot; <a href="/research">Research</a></nav>
  </header>
  <main>
    <article data-report-id="{identifier}">
      <h1>{safe_title}</h1>
{article}
    </article>
  </main>
  <footer>
    <p>Threat research blog &middot; shared for analysis purposes.</p>
  </footer>
</body>
</html>
"""


def _mono_markup(line: str) -> str:
    """Prepara una linea de IoCs para el PDF, escapada y con los tokens largos sueltos.

    Un `sha256` de 64 caracteres entra completo en una linea de Courier 7,5pt, pero no
    si va detras de una etiqueta ("SHA256: <hash> (dropper.exe)"): el renglon se pasa
    de ancho y el salto de linea parte el hash por la mitad. Metiendo un `<br/>` antes
    de cada token largo, cada indicador empieza en el margen izquierdo y sobrevive a la
    extraccion de texto.
    """
    parts: list[str] = []
    for token in line.split():
        escaped = html_escape.escape(token)
        if len(token) >= LONG_TOKEN and parts:
            parts.append(f"<br/>{escaped}")
        else:
            parts.append(escaped)
    return " ".join(parts)


def render_pdf(
    text: str,
    destination: Path | str,
    *,
    report_id: str = "",
    metadata: dict[str, str] | None = None,
) -> Path:
    """Escribe el reporte como PDF de texto corrido.

    Se usa `platypus` en vez de dibujar en el canvas a mano porque parte el texto en
    paginas solo; `wordWrap="CJK"` es necesario para que un sha256 de 64 caracteres
    no desborde el margen.
    """
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import LETTER
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    title, body = split_title(text)
    merged_metadata = {**DEFAULT_PDF_METADATA, **(metadata or {})}

    document = SimpleDocTemplate(
        str(destination),
        pagesize=LETTER,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=title,
        author=merged_metadata.get("author", ""),
        subject=merged_metadata.get("subject", ""),
        keywords=merged_metadata.get("keywords", report_id),
    )

    sheet = getSampleStyleSheet()
    body_style = ParagraphStyle(
        "ReportBody",
        parent=sheet["BodyText"],
        fontSize=10,
        leading=14,
        alignment=TA_LEFT,
        wordWrap="CJK",
    )
    heading_style = ParagraphStyle(
        "ReportHeading", parent=sheet["Heading2"], fontSize=12, spaceBefore=10
    )
    # Courier 7.5pt: ~0,6 em por caracter deja ~110 caracteres por linea en LETTER con
    # margenes de 2 cm, suficiente para un sha256 y para la mayoria de las URLs.
    mono_style = ParagraphStyle(
        "ReportMono",
        parent=body_style,
        fontName="Courier",
        fontSize=7.5,
        leading=10,
        wordWrap="CJK",
    )
    styles = {
        "heading": heading_style,
        "paragraph": body_style,
        "mono": mono_style,
    }

    flowables = [Paragraph(html_escape.escape(title), sheet["Title"]), Spacer(1, 8)]
    for kind, content in _blocks(body):
        markup = _mono_markup(content) if kind == "mono" else html_escape.escape(content)
        flowables.append(Paragraph(markup, styles[kind]))

    document.build(flowables)
    return destination
