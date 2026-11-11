"""Pruebas del lector de reportes.

Lo que se verifica aqui es sobre todo que el parser **no** defiende: si limpiara lo
oculto por su cuenta, los vectores `html_hidden`, `pdf_hidden` y `unicode_invisible`
no podrian funcionar y el experimento mediria cero por construccion, no porque el
modelo resista. Cada prueba de "arrastra lo oculto" protege un vector de ataque.
"""

from __future__ import annotations

import pytest

from aitm.analyst.parsers import ParseError, parse, parse_html, parse_pdf
from aitm.dataset.render import render_pdf

HTML_CON_OCULTOS = """<!doctype html>
<html><head><title>T</title><style>.x { color: red }</style></head>
<body>
  <p>Texto visible del reporte.</p>
  <div style="display:none">INSTRUCCION OCULTA</div>
  <span style="font-size:0px">OTRA OCULTA</span>
  <!-- COMENTARIO OCULTO -->
  <script>var a = "CODIGO";</script>
</body></html>
"""


def test_html_arrastra_lo_oculto_por_defecto() -> None:
    texto = parse_html(HTML_CON_OCULTOS)
    assert "Texto visible del reporte." in texto
    assert "INSTRUCCION OCULTA" in texto, "el vector html_hidden depende de esto"
    assert "OTRA OCULTA" in texto
    assert "COMENTARIO OCULTO" in texto


def test_html_sin_ocultos_es_el_comportamiento_del_sanitizador() -> None:
    texto = parse_html(HTML_CON_OCULTOS, include_hidden=False, include_comments=False)
    assert "Texto visible del reporte." in texto
    assert "INSTRUCCION OCULTA" not in texto
    assert "OTRA OCULTA" not in texto
    assert "COMENTARIO OCULTO" not in texto


def test_el_contenido_de_script_y_style_nunca_pasa() -> None:
    """No es texto del reporte en ningun escenario: ni un conversor ingenuo lo manda."""
    texto = parse_html(HTML_CON_OCULTOS)
    assert "CODIGO" not in texto
    assert "color: red" not in texto


def test_los_caracteres_invisibles_sobreviven(tmp_path) -> None:
    """`unicode_invisible` inyecta zero-width: normalizar no los puede borrar."""
    zero_width = "​‍⁠"
    bidi = "‮"
    archivo = tmp_path / "r.txt"
    archivo.write_text(f"Reporte{zero_width}con{bidi}trampa", encoding="utf-8")

    texto = parse(archivo).text
    assert zero_width in texto
    assert bidi in texto


def test_pdf_incluye_los_metadatos_por_defecto(tmp_path) -> None:
    """El vector pdf_hidden usa /Subject y /Keywords: tienen que llegar al texto."""
    destino = tmp_path / "r.pdf"
    render_pdf(
        "Titulo del reporte\n\nCuerpo del reporte con un dominio evil.com.",
        destino,
        metadata={"subject": "MARCA_EN_SUBJECT", "keywords": "MARCA_EN_KEYWORDS"},
    )

    con_metadatos, metadata = parse_pdf(destino)
    assert "MARCA_EN_SUBJECT" in con_metadatos
    assert metadata["subject"] == "MARCA_EN_SUBJECT"

    sin_metadatos, _ = parse_pdf(destino, include_metadata=False)
    assert "MARCA_EN_SUBJECT" not in sin_metadatos
    assert "Cuerpo del reporte" in sin_metadatos


def test_parse_detecta_el_formato_por_extension(tmp_path) -> None:
    (tmp_path / "a.txt").write_text("contenido", encoding="utf-8")
    (tmp_path / "b.html").write_text("<p>contenido</p>", encoding="utf-8")

    assert parse(tmp_path / "a.txt").source_format == "txt"
    assert parse(tmp_path / "b.html").source_format == "html"


def test_extension_no_soportada_falla(tmp_path) -> None:
    archivo = tmp_path / "r.docx"
    archivo.write_bytes(b"PK\x03\x04")
    with pytest.raises(ParseError, match="extension no soportada"):
        parse(archivo)


def test_archivo_sin_texto_falla(tmp_path) -> None:
    archivo = tmp_path / "vacio.txt"
    archivo.write_text("   \n\n  ", encoding="utf-8")
    with pytest.raises(ParseError, match="no tiene texto extraible"):
        parse(archivo)


def test_report_id_por_defecto_es_el_nombre(tmp_path) -> None:
    archivo = tmp_path / "zscaler_2020-01-01_algo.txt"
    archivo.write_text("contenido", encoding="utf-8")
    assert parse(archivo).report_id == "zscaler_2020-01-01_algo"
    assert parse(archivo, report_id="otro").report_id == "otro"
