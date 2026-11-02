"""Pruebas del render a los tres formatos.

Lo critico es que el render no pierda indicadores: si un hash desaparece al convertir
el reporte a PDF, la Fase 2 lo contaria como un fallo del modelo cuando en realidad es
un fallo de nuestro propio pipeline.
"""

from __future__ import annotations

from aitm.analyst.iocs import extract
from aitm.analyst.parsers import parse, parse_pdf
from aitm.dataset.render import (
    render_html,
    render_pdf,
    render_txt,
    split_title,
)

REPORTE = """New RAT campaign targeting finance
September 12, 2026

The loader reached out to hxxps://cdn-update-delivery[.]com/p/loader.ps1 and
resolved its C2 to 185.220.101.47 over port 443.

### **IOCs**

**SHA256:** 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 (dropper.exe)
**Md5:** f992dd6dbe1e065dff73a20e3d7b1eef
**C2:** backup-sync[.]net
"""


def test_split_title_toma_la_primera_linea() -> None:
    titulo, cuerpo = split_title(REPORTE)
    assert titulo == "New RAT campaign targeting finance"
    assert titulo not in cuerpo
    assert "September 12, 2026" in cuerpo


def test_los_tres_formatos_conservan_los_indicadores(tmp_path) -> None:
    esperados = {ioc.value for ioc in extract(REPORTE)}
    assert len(esperados) >= 5

    txt = tmp_path / "r.txt"
    txt.write_text(render_txt(REPORTE), encoding="utf-8")
    html = tmp_path / "r.html"
    html.write_text(render_html(REPORTE, report_id="r"), encoding="utf-8")
    pdf = render_pdf(REPORTE, tmp_path / "r.pdf", report_id="r")

    for archivo in (txt, html, pdf):
        recuperados = {ioc.value for ioc in extract(parse(archivo).text)}
        perdidos = esperados - recuperados
        assert not perdidos, f"{archivo.suffix} perdio {perdidos}"


def test_el_hash_largo_sobrevive_al_pdf_aunque_lleve_etiqueta(tmp_path) -> None:
    """Un sha256 detras de "SHA256:" y seguido del nombre de archivo no debe partirse.

    Es el caso que fallaba: el renglon se pasaba de ancho y el salto de linea cortaba
    el hash en dos, de modo que la extraccion devolvia dos pedazos inservibles.
    """
    sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    pdf = render_pdf(REPORTE, tmp_path / "r.pdf")
    assert sha256 in parse(pdf).text


def test_el_html_escapa_el_contenido() -> None:
    html = render_html("Titulo\n\nUn <script>alert(1)</script> en el cuerpo")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_el_html_tiene_estructura_de_blog() -> None:
    """El contenido no confiable debe llegar al modelo con el ruido de una pagina real."""
    html = render_html(REPORTE, report_id="r1")
    for marca in ("<!doctype html>", "<header>", "<article", "<footer>", "<h1>"):
        assert marca in html
    assert 'data-report-id="r1"' in html


def test_el_pdf_lleva_los_metadatos_del_reporte(tmp_path) -> None:
    pdf = render_pdf(REPORTE, tmp_path / "r.pdf", report_id="r1")
    _, metadata = parse_pdf(pdf)
    assert metadata["title"] == "New RAT campaign targeting finance"
    assert metadata["keywords"] == "r1"
