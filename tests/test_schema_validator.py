"""Pruebas del validador estricto (`schema_validation`).

Lo que se protege: que descarte los IoC que no estan en el texto (alucinados o
inyectados) sin perder los que si estan aunque el modelo los haya desofuscado, que
descarte los de tipo equivocado y los duplicados, que nunca bloquee y que todo lo
descartado quede anotado.
"""

from __future__ import annotations

import json

import pytest

from aitm.analyst.parsers import ParsedReport
from aitm.analyst.pipeline import Environment
from aitm.analyst.schema import validate_output
from aitm.config import load_config
from aitm.defenses.base import DefenseContext
from aitm.defenses.registry import build_analyst
from aitm.defenses.schema_validator import SchemaValidator, type_matches
from aitm.llm.ollama_client import ChatResponse

SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
TEXTO = f"""El loader descarga hxxps://evil-cdn[.]com/p/loader.ps1 y su C2 es 185.220.101[.]47:443.
Hash {SHA256}. Persistencia en HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.
Explota CVE-2021-40444. Contacto: ops@evil-mail[.]ru. Tecnica T1566.001.
"""
REPORTE = ParsedReport(report_id="r1", source_format="txt", text=TEXTO)


def ioc(value, type_, verdict="malicious"):
    return {"value": value, "type": type_, "verdict": verdict, "confidence": 0.9, "evidence": ""}


def salida(iocs, tecnicas=()):
    return validate_output(
        {
            "summary": "s",
            "severity": "high",
            "iocs": list(iocs),
            "mitre_attack": [{"technique_id": t, "technique_name": "", "confidence": 0.8} for t in tecnicas],
            "threat_actor": None,
            "notes": [],
        }
    )


def aplicar(validated):
    contexto = DefenseContext()
    resultado = SchemaValidator().apply(validated, REPORTE, contexto)
    return resultado, contexto


def test_conserva_los_iocs_del_texto_aunque_esten_desofuscados():
    entrada = salida(
        [
            ioc("https://evil-cdn.com/p/loader.ps1", "url"),
            ioc("185.220.101.47:443", "ipv4"),
            ioc(SHA256.upper(), "sha256"),
            ioc("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "registry_key", "benign"),
            ioc("CVE-2021-40444", "cve"),
            ioc("ops@evil-mail.ru", "email"),
            ioc("evil-cdn.com", "domain"),
        ]
    )
    resultado, contexto = aplicar(entrada)
    assert len(resultado.output.iocs) == 7
    assert contexto.notes == ["schema_validation: salida coherente con el texto"]
    assert not contexto.blocked


def test_descarta_iocs_que_no_estan_en_el_texto():
    entrada = salida([ioc("evil-cdn.com", "domain"), ioc("inyectado-por-payload.com", "domain")])
    resultado, contexto = aplicar(entrada)
    assert [i.value for i in resultado.output.iocs] == ["evil-cdn.com"]
    assert any("inyectado-por-payload.com" in w for w in resultado.warnings)
    assert "1 ausente" in contexto.notes[0]


def test_descarta_el_refang_mal_hecho():
    """`evil-cdn.[.]com` no esta en el texto: se pierde (costo de ser estricto)."""
    resultado, _ = aplicar(salida([ioc("evil-cdn.[.]com", "domain")]))
    assert resultado.output.iocs == []


def test_descarta_tipo_equivocado():
    resultado, contexto = aplicar(salida([ioc(SHA256, "md5"), ioc("evil-cdn.com", "ipv4")]))
    assert resultado.output.iocs == []
    assert "2 tipo" in contexto.notes[0]


def test_descarta_duplicados_de_iocs_y_tecnicas():
    entrada = salida(
        [ioc("evil-cdn.com", "domain"), ioc("EVIL-CDN[.]com", "domain")],
        tecnicas=["T1566.001", "T1566.001", "T1059"],
    )
    resultado, contexto = aplicar(entrada)
    assert len(resultado.output.iocs) == 1
    assert [t.technique_id for t in resultado.output.mitre_attack] == ["T1566.001", "T1059"]
    assert "2 duplicado" in contexto.notes[0]


def test_no_toca_veredicto_ni_severidad():
    """Un `flip_to_benign` exitoso es coherente con el texto: el validador no lo ve."""
    entrada = salida([ioc("evil-cdn.com", "domain", verdict="benign")])
    resultado, contexto = aplicar(entrada)
    assert resultado.output.iocs[0].verdict == "benign"
    assert resultado.output.severity == "high"
    assert not contexto.blocked


def test_sin_salida_devuelve_none():
    resultado, contexto = aplicar(None)
    assert resultado is None
    assert contexto.notes == ["schema_validation: sin salida que validar"]


@pytest.mark.parametrize(
    "tipo,valor,ok",
    [
        ("md5", "d41d8cd98f00b204e9800998ecf8427e", True),
        ("md5", SHA256, False),
        ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709", True),
        ("sha256", SHA256, True),
        ("ipv4", "185.220.101[.]47", True),
        ("ipv4", "185.220.101.47:8080", True),
        ("ipv4", "999.1.1.1", False),
        ("ipv6", "2001:db8::1", True),
        ("domain", "evil-cdn[.]com", True),
        ("domain", "1.2.3.4", False),
        ("domain", "loader", False),
        ("url", "hxxps://evil[.]com/a?b=1", True),
        ("url", "evil.com/a", False),
        ("email", "a[@]b[.]ru", True),
        ("cve", "cve-2021-40444", True),
        ("cve", "CVE-21-1", False),
        ("registry_key", "HKLM\\Software\\X", True),
        ("registry_key", "C:\\Windows", False),
        ("file_path", "C:\\Users\\Public\\a.exe", True),
        ("file_path", "%APPDATA%\\x.dll", True),
        ("file_path", "a.exe", False),
    ],
)
def test_type_matches(tipo, valor, ok):
    assert type_matches(tipo, valor) is ok


class _Cliente:
    def __init__(self, respuesta):
        self.respuesta = respuesta

    def chat(self, messages, *, model=None, response_format=None, options=None):
        return ChatResponse(content=json.dumps(self.respuesta), model=model, latency_ms=1, prompt_tokens=1,
                            completion_tokens=1, raw={"done_reason": "stop"})


def test_en_el_pipeline_las_advertencias_llegan_a_la_traza(tmp_path):
    documento = tmp_path / "r1.txt"
    documento.write_text(TEXTO, encoding="utf-8")
    respuesta = {
        "summary": "s", "severity": "high", "threat_actor": None, "notes": [], "mitre_attack": [],
        "iocs": [ioc("evil-cdn.com", "domain"), ioc("no-esta.com", "domain")],
    }
    analista = build_analyst(load_config(), _Cliente(respuesta), defenses=["schema_validation"],
                             environment=Environment())
    record = analista.analyze(documento)
    assert [i.value for i in record.output.iocs] == ["evil-cdn.com"]
    assert any("no-esta.com" in w for w in record.validation_warnings)
    assert record.defense_notes and record.defense_notes[0].startswith("schema_validation")
    assert record.blocked is False
