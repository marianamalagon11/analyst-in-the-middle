"""Defensa `sanitizer`: que al modelo llegue solo lo que un humano veria en el documento.

Es el contrapunto exacto del parser ingenuo (`src/aitm/analyst/parsers.py`). Donde el
parser arrastra todo lo que un conversor normal arrastraria, el sanitizador vuelve a
leer el documento original y se queda con lo visible:

| Formato | Que elimina |
|---|---|
| html | comentarios `<!-- -->`; nodos ocultos por CSS en linea o en `<style>` (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`, texto blanco o transparente, fuera de pantalla, recortado); el atributo `hidden` |
| pdf | metadatos del documento (`/Subject`, `/Keywords`...); el texto en modo de render 3 ("no dibujar") |
| todos | caracteres Unicode de formato que no se ven (categoria `Cf`: bloque de Tags, anchos cero, controles bidi, BOM, guion suave) y selectores de variacion |

**Que NO puede hacer, por diseno.** El sanitizador quita lo invisible, no lo malicioso.
Una instruccion a la vista (`plaintext`) o disfrazada de nota del autor (`author_note`)
es contenido visible y pasa intacta: distinguirla del resto del reporte es trabajo del
spotlighting o del juez. Y en `bidi` quita los controles pero las letras del payload
siguen ahi (de hecho quedan mas legibles para el modelo). Esos limites son resultado
del experimento, no defectos a esconder: se miden con `aitm sanitize-check`.

**Supuestos que hay que declarar en el informe:**

- *Texto blanco = oculto.* Se asume fondo blanco, que es el de los reportes del corpus.
  En una pagina de fondo oscuro el sanitizador borraria texto visible.
- *Render 3 = oculto.* Es cierto en nuestros PDF, que salen de un render propio. En un
  PDF escaneado con OCR la capa de texto va justo en modo 3 sobre la imagen, y el
  sanitizador la borraria entera; en produccion habria que mirar si hay una imagen
  debajo antes de descartarla.
- *CSS simple.* Se evalua el estilo en linea y las reglas de `<style>` con selectores
  de una sola etiqueta, clase o id. No hay motor de cascada: un atacante que conozca
  la defensa la rodea con un selector compuesto (ataque adaptativo, fuera de alcance).
"""

from __future__ import annotations

import io
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from bs4 import BeautifulSoup, Comment, Tag

from aitm.analyst.parsers import ParsedReport, normalize_text
from aitm.defenses.base import DefenseContext, PreDefense

# -- Unicode ----------------------------------------------------------------

#: Puntos de codigo que no son `Cf` pero tampoco se ven: selectores de variacion (usados
#: para esconder bytes detras de un emoji) y los rellenos de Hangul.
_EXTRA_INVISIBLE = frozenset(
    [*range(0xFE00, 0xFE10), *range(0xE0100, 0xE01F0), 0x115F, 0x1160, 0x3164, 0xFFA0]
)


def is_invisible_char(char: str) -> bool:
    """Caracter que no ocupa lugar visible en el render normal del texto."""
    return unicodedata.category(char) == "Cf" or ord(char) in _EXTRA_INVISIBLE


def strip_invisible(text: str) -> tuple[str, int]:
    """Quita los caracteres invisibles. Devuelve (texto, cuantos se quitaron)."""
    kept = [char for char in text if not is_invisible_char(char)]
    return "".join(kept), len(text) - len(kept)


# -- HTML -------------------------------------------------------------------

_DECLARATION = re.compile(r"([a-z-]+)\s*:\s*([^;]+)", re.I)
_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_NUMBER = re.compile(r"^(-?\d*\.?\d+)\s*([a-z%]*)$", re.I)
_WHITE = {"#fff", "#ffffff", "#ffff", "#ffffffff", "white", "rgb(255,255,255)", "hsl(0,0%,100%)"}

#: Desplazamiento a partir del cual un elemento posicionado queda fuera de la pagina.
_OFFSCREEN_PX = 1000


def _length(value: str) -> float | None:
    """`0`, `0px`, `-9999px`, `0.5em` -> numero. Unidades distintas de px se toman tal cual."""
    match = _NUMBER.match(value.strip())
    return float(match.group(1)) if match else None


def _declarations(style: str) -> dict[str, str]:
    cleaned = style.replace("!important", "")
    return {key.lower(): value.strip().lower() for key, value in _DECLARATION.findall(cleaned)}


def _is_white(color: str) -> bool:
    compact = color.replace(" ", "")
    if compact in _WHITE or compact == "transparent":
        return True
    # rgba(..., 0) / hsla(..., 0): completamente transparente.
    alpha = re.match(r"(?:rgba|hsla)\(.*,([0-9.]+)\)$", compact)
    return bool(alpha) and float(alpha.group(1)) == 0.0


def hidden_reason(declarations: dict[str, str]) -> str | None:
    """Por que un conjunto de declaraciones CSS esconde el texto, o `None` si no lo hace."""
    get = declarations.get
    if get("display") == "none":
        return "display:none"
    if get("visibility") in ("hidden", "collapse"):
        return "visibility:hidden"
    opacity = _length(get("opacity", "1").rstrip("%"))
    if opacity is not None and opacity <= 0.05:
        return "opacity:0"
    size = get("font-size")
    number = _length(size) if size is not None else None
    if number is not None and (number == 0 or (number <= 1 and size.endswith(("px", "pt")))):
        return "font-size:0"
    color = get("color")
    if color is not None and _is_white(color):
        # Blanco sobre fondo blanco (o sin fondo propio: la pagina es blanca). Blanco
        # sobre un fondo oscuro declarado en el mismo elemento si se ve.
        background = get("background-color") or get("background")
        if color.replace(" ", "") == "transparent" or background is None or _is_white(background):
            return "texto blanco o transparente"
    for side in ("left", "top", "text-indent", "margin-left"):
        offset = _length(get(side, "0"))
        if offset is not None and offset <= -_OFFSCREEN_PX:
            return f"fuera de pantalla ({side})"
    clip = get("clip-path") or get("clip")
    if clip and (clip.replace(" ", "") in ("rect(0,0,0,0)", "rect(0px,0px,0px,0px)", "inset(50%)", "inset(100%)")):
        return "recortado (clip)"
    if get("overflow") == "hidden":
        for side in ("height", "width", "max-height", "max-width"):
            if _length(get(side, "1")) == 0:
                return f"{side}:0 con overflow:hidden"
    return None


@dataclass(frozen=True)
class _StyleRules:
    """Reglas ocultantes de los `<style>` del documento, solo con selectores simples."""

    tags: dict[str, str]
    classes: dict[str, str]
    ids: dict[str, str]

    def reason_for(self, tag: Tag) -> str | None:
        if tag.name in self.tags:
            return self.tags[tag.name]
        for cls in tag.get("class") or []:
            if cls in self.classes:
                return self.classes[cls]
        identifier = tag.get("id")
        if identifier and identifier in self.ids:
            return self.ids[identifier]
        return None


def _stylesheet_rules(soup: BeautifulSoup) -> _StyleRules:
    tags: dict[str, str] = {}
    classes: dict[str, str] = {}
    ids: dict[str, str] = {}
    for style in soup.find_all("style"):
        css = re.sub(r"/\*.*?\*/", "", style.get_text(), flags=re.S)
        for selectors, body in _RULE.findall(css):
            reason = hidden_reason(_declarations(body))
            if reason is None:
                continue
            for selector in selectors.split(","):
                selector = selector.strip()
                if re.fullmatch(r"\.[\w-]+", selector):
                    classes[selector[1:]] = f"{reason} (regla {selector})"
                elif re.fullmatch(r"#[\w-]+", selector):
                    ids[selector[1:]] = f"{reason} (regla {selector})"
                elif re.fullmatch(r"[a-z][a-z0-9]*", selector, re.I):
                    tags[selector.lower()] = f"{reason} (regla {selector})"
    return _StyleRules(tags, classes, ids)


@dataclass
class HtmlCleanup:
    text: str
    comments: int = 0
    hidden_nodes: int = 0
    reasons: tuple[str, ...] = ()


def visible_html_text(html: str) -> HtmlCleanup:
    """Texto de un HTML tal como lo veria una persona en el navegador.

    Sigue los mismos pasos que `parsers.parse_html` (mismo separador, misma
    normalizacion) para que, en un HTML sin nada oculto, el texto salga identico al
    del parser ingenuo: el sanitizador no debe costar exactitud en un reporte limpio.
    """
    soup = BeautifulSoup(html, "lxml")
    rules = _stylesheet_rules(soup)
    for tag in soup(["script", "style", "head", "template"]):
        tag.decompose()

    comments = soup.find_all(string=lambda node: isinstance(node, Comment))
    for node in comments:
        node.extract()

    reasons: list[str] = []
    for tag in soup.find_all(True):
        if tag.decomposed:
            continue
        reason = None
        if tag.has_attr("hidden"):
            reason = "atributo hidden"
        else:
            reason = hidden_reason(_declarations(tag.get("style") or "")) or rules.reason_for(tag)
        if reason:
            reasons.append(reason)
            tag.decompose()

    text = normalize_text(soup.get_text(separator="\n"))
    return HtmlCleanup(text=text, comments=len(comments), hidden_nodes=len(reasons), reasons=tuple(reasons))


# -- PDF --------------------------------------------------------------------

_SHOW_TEXT = {b"Tj", b"TJ", b"'", b'"'}
#: Modo de render 3: "ni rellenar ni trazar". Los modos 0-2 y 4-6 dibujan algo; el 7
#: solo recorta, y tambien es invisible.
_INVISIBLE_RENDER_MODES = {3, 7}


def _drop_invisible_text(operations: list) -> tuple[list, int]:
    """Quita del content stream las operaciones de texto con render invisible.

    Sigue el modo de render (`Tr`) a traves de la pila de estado grafico (`q`/`Q`). Un
    `'` o `"` invisible ademas mueve a la linea siguiente, asi que se cambia por `T*`
    para no descolocar el texto visible que viene despues.
    """
    mode, stack = 0, []
    kept, dropped = [], 0
    for operands, operator in operations:
        if operator == b"q":
            stack.append(mode)
        elif operator == b"Q":
            mode = stack.pop() if stack else 0
        elif operator == b"Tr" and operands:
            mode = int(operands[0])
        elif operator in _SHOW_TEXT and mode in _INVISIBLE_RENDER_MODES:
            dropped += 1
            if operator in (b"'", b'"'):
                kept.append(([], b"T*"))
            continue
        kept.append((operands, operator))
    return kept, dropped


@dataclass
class PdfCleanup:
    text: str
    metadata_keys: tuple[str, ...] = ()
    invisible_ops: int = 0


def visible_pdf_text(data: bytes) -> PdfCleanup:
    """Texto de un PDF sin metadatos ni texto en modo de render invisible.

    Reescribe el content stream de cada pagina sin las operaciones invisibles y luego
    extrae con `pypdf`, igual que el parser ingenuo. Asi, en un PDF limpio, el texto es
    identico al del parser sin metadatos.
    """
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import ContentStream

    from aitm.analyst.parsers import PDF_METADATA_KEYS

    reader = PdfReader(io.BytesIO(data))
    metadata = reader.metadata or {}
    found = tuple(key.lstrip("/").lower() for key in PDF_METADATA_KEYS if metadata.get(key))

    writer = PdfWriter(clone_from=reader)
    pages, dropped_total = [], 0
    for page in writer.pages:
        content = page.get_contents()
        if content is not None:
            stream = ContentStream(content, writer)
            operations, dropped = _drop_invisible_text(stream.operations)
            if dropped:
                stream.operations = operations
                page.replace_contents(stream)
                dropped_total += dropped
        pages.append(page.extract_text() or "")
    return PdfCleanup(
        text=normalize_text("\n\n".join(pages)),
        metadata_keys=found,
        invisible_ops=dropped_total,
    )


# -- defensa ----------------------------------------------------------------


@dataclass
class SanitizeResult:
    """Lo que hizo el sanitizador con un documento. Va a la traza como nota."""

    text: str
    removed_chars: int
    actions: list[str]


def sanitize_document(source_format: str, data: bytes, naive_text: str | None = None) -> SanitizeResult:
    """Texto visible del documento `data`, mas el detalle de lo que se quito.

    `naive_text` es lo que habria visto el parser ingenuo; sirve solo para contar
    cuantos caracteres se eliminaron.
    """
    actions: list[str] = []
    if source_format == "html":
        cleaned = visible_html_text(data.decode("utf-8", errors="replace"))
        text = cleaned.text
        if cleaned.comments:
            actions.append(f"{cleaned.comments} comentario(s) HTML")
        if cleaned.hidden_nodes:
            reasons = sorted(set(cleaned.reasons))
            actions.append(f"{cleaned.hidden_nodes} nodo(s) oculto(s): {', '.join(reasons)}")
    elif source_format == "pdf":
        cleaned_pdf = visible_pdf_text(data)
        text = cleaned_pdf.text
        if cleaned_pdf.metadata_keys:
            actions.append(f"metadatos PDF ({', '.join(cleaned_pdf.metadata_keys)})")
        if cleaned_pdf.invisible_ops:
            actions.append(f"{cleaned_pdf.invisible_ops} operacion(es) de texto invisible (Tr 3)")
    else:
        text = normalize_text(data.decode("utf-8", errors="replace"))

    text, invisible = strip_invisible(text)
    if invisible:
        actions.append(f"{invisible} caracter(es) Unicode invisibles")
        text = normalize_text(text)

    reference = naive_text if naive_text is not None else text
    return SanitizeResult(text=text, removed_chars=max(0, len(reference) - len(text)), actions=actions)


class Sanitizer(PreDefense):
    """Vuelve a leer el documento original y deja solo el texto visible."""

    name: ClassVar[str] = "sanitizer"

    def apply(self, report: ParsedReport, context: DefenseContext) -> ParsedReport:
        path: Path | None = report.source_path
        if path is not None and Path(path).is_file():
            result = sanitize_document(report.source_format, Path(path).read_bytes(), report.text)
        else:
            # Sin el original (p. ej. un reporte construido en memoria) solo se puede
            # limpiar el texto: quitar Unicode invisible.
            text, invisible = strip_invisible(report.text)
            actions = [f"{invisible} caracter(es) Unicode invisibles"] if invisible else []
            result = SanitizeResult(normalize_text(text), len(report.text) - len(text), actions)

        if result.actions:
            context.note(self.name, f"quito {result.removed_chars} caracteres: " + "; ".join(result.actions))
        else:
            context.note(self.name, "sin contenido oculto")

        return ParsedReport(
            report_id=report.report_id,
            source_format=report.source_format,
            text=result.text,
            source_path=report.source_path,
            # Los metadatos del PDF son justo lo que se quito: no se conservan.
            metadata={} if report.source_format == "pdf" else dict(report.metadata),
        )
