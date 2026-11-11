"""Pruebas del acuerdo entre revisores.

La prueba que importa de verdad es la ultima: con un dataset tan desbalanceado como el
nuestro, el porcentaje de acuerdo crudo se infla y kappa es lo unico que lo delata. Si
esa distincion se rompiera, el informe reportaria un acuerdo que no existe.
"""

from __future__ import annotations

import pytest

from aitm.evaluation.agreement import cohen_kappa, compare_labels, jaccard
from aitm.evaluation.labels import ReportLabel

BASE = {
    "report_id": "vendor_2026-01-01_caso",
    "source": {
        "corpus": "AnnoCTR",
        "file": "AnnoCTR/all/text/vendor_2026-01-01_caso.txt",
        "license": "CC-BY-SA-4.0",
    },
    "formats": ["txt"],
    "severity": "high",
    "iocs": [
        {"value": "evil.com", "type": "domain", "verdict": "malicious"},
        {"value": "evil2.com", "type": "domain", "verdict": "malicious"},
        {"value": "8.8.8.8", "type": "ipv4", "verdict": "benign"},
    ],
}


def etiqueta(**cambios) -> ReportLabel:
    return ReportLabel.model_validate({**BASE, **cambios})


def test_jaccard() -> None:
    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert jaccard({"a", "b"}, {"a"}) == 0.5
    assert jaccard(set(), set()) == 1.0, "dos listas vacias estan de acuerdo"
    assert jaccard({"a"}, {"b"}) == 0.0


def test_acuerdo_total() -> None:
    result = compare_labels(etiqueta(), etiqueta())
    assert result.jaccard == 1.0
    assert result.verdict_match == 1.0
    assert result.severity_match
    assert result.discrepancies == []


def test_detecta_omision() -> None:
    otra = etiqueta(iocs=BASE["iocs"][:2])
    result = compare_labels(etiqueta(), otra)

    assert result.iocs_a == 3 and result.iocs_b == 2
    assert result.common == 2
    assert result.verdict_match == 1.0, "en los comunes siguen de acuerdo"
    assert any("solo en A: 8.8.8.8" in linea for linea in result.discrepancies)


def test_detecta_desacuerdo_de_veredicto_y_severidad() -> None:
    cambiados = [{**BASE["iocs"][0], "verdict": "benign"}, *BASE["iocs"][1:]]
    result = compare_labels(etiqueta(), etiqueta(iocs=cambiados, severity="low"))

    assert result.verdict_match == pytest.approx(2 / 3)
    assert not result.severity_match
    assert any("veredicto: evil.com" in linea for linea in result.discrepancies)
    assert any("severidad: A=high  B=low" in linea for linea in result.discrepancies)


def test_no_compara_reportes_distintos() -> None:
    with pytest.raises(ValueError, match="no son el mismo reporte"):
        compare_labels(etiqueta(), etiqueta(report_id="otro_2026-01-01_caso"))


def test_kappa_castiga_el_acuerdo_por_azar() -> None:
    """Dos anotadores que casi siempre dicen `malicious` coinciden mucho por azar."""
    pairs = [("malicious", "malicious")] * 95 + [("malicious", "benign")] * 5
    crudo = sum(1 for a, b in pairs if a == b) / len(pairs)
    kappa = cohen_kappa(pairs)

    assert crudo == 0.95
    assert kappa is not None
    assert kappa < 0.5, "el 95 % crudo no debe leerse como acuerdo fuerte"


def test_kappa_no_definido_con_una_sola_categoria() -> None:
    """Si ambos usaron solo `malicious`, kappa no existe: no es cero."""
    assert cohen_kappa([("malicious", "malicious")] * 10) is None
    assert cohen_kappa([]) is None


def test_kappa_perfecto_con_clases_balanceadas() -> None:
    pairs = [("malicious", "malicious")] * 5 + [("benign", "benign")] * 5
    assert cohen_kappa(pairs) == pytest.approx(1.0)
