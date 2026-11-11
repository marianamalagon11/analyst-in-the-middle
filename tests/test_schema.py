"""Pruebas del contrato de salida del analista.

Lo importante: que un elemento mal formado se pierda solo, sin llevarse el analisis
entero, y que el esquema que se manda a Ollama diga lo mismo que Pydantic.
"""

from __future__ import annotations

from typing import get_args

import pytest

from aitm.analyst.iocs import IoCType
from aitm.analyst.schema import (
    EVIDENCE_MAX,
    SEVERITY_ORDER,
    AnalystOutput,
    OutputError,
    ollama_schema,
    severity_rank,
    validate_output,
)
from aitm.evaluation.labels import Severity, Verdict


def salida(**cambios) -> dict:
    base = {
        "summary": "Campana de phishing que entrega LimeRAT.",
        "severity": "high",
        "iocs": [
            {
                "value": "santiagonasar.duckdns[.]org",
                "type": "domain",
                "verdict": "malicious",
                "confidence": 0.9,
                "evidence": "C2 del RAT",
            }
        ],
        "mitre_attack": [
            {"technique_id": "t1566", "technique_name": "Phishing", "confidence": 0.8}
        ],
        "threat_actor": "APT-C-36",
        "notes": [],
    }
    base.update(cambios)
    return base


def test_salida_valida() -> None:
    resultado = validate_output(salida())
    assert resultado.warnings == []
    assert resultado.output.severity == "high"
    assert resultado.output.mitre_attack[0].technique_id == "T1566", "se normaliza a mayusculas"


def test_un_ioc_invalido_se_descarta_sin_perder_el_resto() -> None:
    iocs = salida()["iocs"] + [
        {"value": "x", "type": "hash", "verdict": "malicious", "confidence": 1, "evidence": ""}
    ]
    resultado = validate_output(salida(iocs=iocs))
    assert len(resultado.output.iocs) == 1
    assert len(resultado.warnings) == 1
    assert "iocs[1]" in resultado.warnings[0]


def test_una_tecnica_mal_escrita_se_descarta() -> None:
    tecnicas = [
        {"technique_id": "T15", "technique_name": "?", "confidence": 0.5},
        {"technique_id": "T1059.001", "technique_name": "PowerShell", "confidence": 0.5},
    ]
    resultado = validate_output(salida(mitre_attack=tecnicas))
    assert [t.technique_id for t in resultado.output.mitre_attack] == ["T1059.001"]
    assert resultado.warnings


@pytest.mark.parametrize("mala", ["extreme", None, 3])
def test_severidad_invalida_invalida_todo(mala) -> None:
    with pytest.raises(OutputError):
        validate_output(salida(severity=mala))


def test_lo_que_no_es_objeto_falla() -> None:
    with pytest.raises(OutputError):
        validate_output([salida()])


def test_confianza_fuera_de_rango_se_acota() -> None:
    iocs = [dict(salida()["iocs"][0], confidence=1.7)]
    assert validate_output(salida(iocs=iocs)).output.iocs[0].confidence == 1.0


def test_evidencia_larga_se_recorta() -> None:
    iocs = [dict(salida()["iocs"][0], evidence="x" * 1000)]
    assert len(validate_output(salida(iocs=iocs)).output.iocs[0].evidence) == EVIDENCE_MAX


def test_actor_desconocido_es_none() -> None:
    assert validate_output(salida(threat_actor="Unknown")).output.threat_actor is None


def test_report_id_no_lo_pone_el_modelo() -> None:
    """El esquema no se lo pide; el pipeline lo rellena despues."""
    assert "report_id" not in ollama_schema()["properties"]
    assert AnalystOutput.model_validate(salida()).report_id == ""


def test_el_esquema_de_ollama_usa_los_mismos_enums() -> None:
    schema = ollama_schema()
    assert schema["properties"]["severity"]["enum"] == list(SEVERITY_ORDER)
    assert set(SEVERITY_ORDER) == set(get_args(Severity))
    ioc = schema["properties"]["iocs"]["items"]["properties"]
    assert ioc["type"]["enum"] == list(get_args(IoCType))
    assert ioc["verdict"]["enum"] == list(get_args(Verdict))


def test_el_esquema_no_pide_campos_que_pydantic_no_conoce() -> None:
    schema = ollama_schema()
    assert set(schema["properties"]) <= set(AnalystOutput.model_fields)
    assert set(schema["required"]) == set(schema["properties"])


def test_las_listas_tienen_tope() -> None:
    """Sin tope, un bucle greedy enumerando tecnicas agota num_predict y corta el JSON."""
    from aitm.analyst.schema import MAX_TECHNIQUES

    schema = ollama_schema()["properties"]
    assert schema["mitre_attack"]["maxItems"] == MAX_TECHNIQUES
    assert schema["iocs"]["maxItems"] >= 26, "nunca por debajo del maximo del ground truth"

    muchas = [
        {"technique_id": f"T1{i:03d}", "technique_name": "x", "confidence": 0.5}
        for i in range(MAX_TECHNIQUES + 10)
    ]
    resultado = validate_output(salida(mitre_attack=muchas))
    assert len(resultado.output.mitre_attack) == MAX_TECHNIQUES
    assert any("se conservan" in w for w in resultado.warnings)


def test_orden_de_severidad() -> None:
    assert severity_rank("critical") > severity_rank("high") > severity_rank("info")
