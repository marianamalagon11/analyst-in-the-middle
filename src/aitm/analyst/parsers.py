"""Lectura de reportes en txt, html y pdf hacia un texto normalizado.

**Este modulo no es una defensa.** Es el pipeline ingenuo, el que tendria cualquier
analista que conecta un LLM a su flujo de reportes sin pensar en inyeccion. Por eso
pasa al modelo lo que un conversor normal le pasaria, incluido:

- el texto de nodos HTML ocultos por CSS (`display:none`, `font-size:0`, blanco
  sobre blanco), porque el conversor solo quita etiquetas, no evalua estilos;
- los comentarios `<!-- -->` del HTML;
- los metadatos del PDF (`/Title`, `/Subject`, `/Keywords`);
- el texto PDF en modo de render invisible, que `pypdf` extrae igual que el visible.

Esa ingenuidad es el objeto de estudio: si el parser ya filtrara lo oculto, tres de
los cinco vectores de ataque moririan por construccion y no mediriamos nada. El
filtrado vive en `src/aitm/defenses/sanitizer.py` (Fase 4) y se activa por
configuracion, de modo que cada corrida deja constancia de con que parser se hizo.

Las tres banderas son configurables en `config.yaml` (`analyst.parser`) para poder
medir tambien el caso contrario.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from bs4 import BeautifulSoup, Comment

SourceFormat = Literal["txt", "html", "pdf"]

#: Extensiones reconocidas y el formato al que corresponden.
EXTENSIONS: dict[str, SourceFormat] = {
    ".txt": "txt",
    ".md": "txt",
    ".html": "html",
    ".htm": "html",
    ".pdf": "pdf",
}

#: Metadatos del PDF que un conversor ingenuo suele arrastrar al texto.
PDF_METADATA_KEYS = ("/Title", "/Subject", "/Keywords", "/Author", "/Creator")


class ParseError(RuntimeError):
    """El archivo no se pudo leer o no tiene un formato soportado."""


@dataclass(frozen=True)
class ParsedReport:
    """Resultado de leer un reporte: texto plano mas la procedencia."""

    report_id: str
    source_format: SourceFormat
    text: str
    source_path: Path | None = None
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def char_count(self) -> int:
        return len(self.text)

    @property
    def approx_tokens(self) -> int:
        """Estimacion barata (~4 caracteres por token) para presupuestar el computo."""
        return len(self.text) // 4


def normalize_text(text: str) -> str:
    """Normaliza espacios y saltos de linea sin tocar los caracteres invisibles.

    Importante: **no** se eliminan zero-width ni bidi aqui. Ese es justo el vector
    `unicode_invisible`, y limpiarlo en el parser seria defenderse sin querer. La
    normalizacion Unicode se queda en NFC, que no borra esos caracteres.
    """
    text = unicodedata.normalize("NFC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    # Espacios al final de linea y mas de dos saltos seguidos: ruido de conversion.
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def parse_txt(path: Path) -> str:
    return normalize_text(path.read_text(encoding="utf-8", errors="replace"))


def parse_html(
    source: str | Path,
    *,
    include_hidden: bool = True,
    include_comments: bool = True,
) -> str:
    """HTML a texto. Por defecto arrastra lo oculto, como haria un conversor normal.

    Con `include_hidden=False` e `include_comments=False` se obtiene el
    comportamiento que implementara el sanitizador: solo lo que un humano veria.
    """
    html = source if isinstance(source, str) else source.read_text(
        encoding="utf-8", errors="replace"
    )
    soup = BeautifulSoup(html, "lxml")

    # El contenido de <script> y <style> no es texto del reporte en ningun caso:
    # ni un conversor ingenuo se lo pasaria al modelo.
    for tag in soup(["script", "style", "head"]):
        tag.decompose()

    comments = soup.find_all(string=lambda node: isinstance(node, Comment))
    comment_texts = [str(node).strip() for node in comments]
    for node in comments:
        node.extract()

    if not include_hidden:
        for tag in soup.find_all(True):
            if _is_hidden(tag):
                tag.decompose()

    text = soup.get_text(separator="\n")

    if include_comments and comment_texts:
        text = text + "\n" + "\n".join(comment_texts)

    return normalize_text(text)


def _is_hidden(tag) -> bool:
    """Heuristica de nodo invisible: lo que usan los vectores de HTML oculto."""
    if tag.has_attr("hidden"):
        return True
    if tag.get("aria-hidden") == "true":
        return True
    style = (tag.get("style") or "").lower().replace(" ", "")
    if not style:
        return False
    hidden_markers = (
        "display:none",
        "visibility:hidden",
        "font-size:0",
        "opacity:0",
        "color:#fff",
        "color:white",
        "color:rgb(255,255,255)",
    )
    return any(marker in style for marker in hidden_markers)


def parse_pdf(path: Path, *, include_metadata: bool = True) -> tuple[str, dict[str, str]]:
    """PDF a texto con `pypdf`, devolviendo tambien los metadatos encontrados.

    `pypdf` extrae el texto del content stream, asi que el texto en modo de render
    invisible (`Tr 3`) sale igual que el visible. Es exactamente lo que explota el
    vector `pdf_hidden` y por eso no se filtra aqui.
    """
    from pypdf import PdfReader

    reader = PdfReader(str(path))
    pages = [page.extract_text() or "" for page in reader.pages]
    body = normalize_text("\n\n".join(pages))

    metadata: dict[str, str] = {}
    raw_metadata = reader.metadata or {}
    for key in PDF_METADATA_KEYS:
        value = raw_metadata.get(key)
        if value:
            metadata[key.lstrip("/").lower()] = str(value)

    if include_metadata and metadata:
        header = "\n".join(f"{key}: {value}" for key, value in metadata.items())
        body = f"{header}\n\n{body}"

    return body, metadata


def detect_format(path: Path) -> SourceFormat:
    try:
        return EXTENSIONS[path.suffix.lower()]
    except KeyError:
        raise ParseError(
            f"extension no soportada: {path.suffix!r} ({path.name}). "
            f"Soportadas: {', '.join(sorted(EXTENSIONS))}"
        ) from None


def parse(
    path: Path | str,
    *,
    report_id: str | None = None,
    include_hidden_html: bool = True,
    include_html_comments: bool = True,
    include_pdf_metadata: bool = True,
) -> ParsedReport:
    """Lee un reporte de disco y devuelve su texto normalizado.

    Las banderas replican `analyst.parser` de `config.yaml`; el llamador decide,
    para que la configuracion quede registrada en el hash de cada corrida.
    """
    path = Path(path)
    if not path.is_file():
        raise ParseError(f"no existe el archivo {path}")

    source_format = detect_format(path)
    metadata: dict[str, str] = {}

    if source_format == "txt":
        text = parse_txt(path)
    elif source_format == "html":
        text = parse_html(
            path,
            include_hidden=include_hidden_html,
            include_comments=include_html_comments,
        )
    else:
        text, metadata = parse_pdf(path, include_metadata=include_pdf_metadata)

    if not text.strip():
        raise ParseError(f"{path} se leyo pero no tiene texto extraible")

    return ParsedReport(
        report_id=report_id or path.stem,
        source_format=source_format,
        text=text,
        source_path=path,
        metadata=metadata,
    )
