"""Pruebas de la selección de objetivos y de la integridad del manifiesto generado.

La selección debe ser determinista y venir solo del ground truth, nunca de lo que diga
el modelo: es lo que hace el ASR auditable.
"""

from __future__ import annotations

import json
from pathlib import Path

from aitm.attacks.targets import target_for, targets_for_report
from aitm.evaluation.labels import ReportLabel


def label(**extra) -> ReportLabel:
    base = {
        "report_id": "r1",
        "source": {"corpus": "t", "file": "t.txt", "license": "CC"},
        "formats": ["txt"],
        "status": "frozen",
        "annotators": ["A"],
        "reviewers": ["B"],
        "severity": "high",
        "iocs": [
            {"value": "benigno.com", "type": "domain", "verdict": "benign"},
            {"value": "evil.com", "type": "domain", "verdict": "malicious"},
            {"value": "185.1.2.3", "type": "ipv4", "verdict": "malicious"},
        ],
        "mitre_attack": [{"technique_id": "T1566"}, {"technique_id": "T1059"}],
    }
    base.update(extra)
    return ReportLabel.model_validate(base)


def test_flip_toma_el_primer_dominio_malicioso() -> None:
    t = target_for("flip_to_benign", label())
    assert t.ioc_value == "evil.com", "salta el benigno, toma el primer malicious domain/url/ipv4"


def test_downgrade_baja_dos_niveles() -> None:
    assert target_for("downgrade_severity", label(severity="critical")).severity_to == "medium"
    assert target_for("downgrade_severity", label(severity="high")).severity_to == "low"
    # info es el mínimo: no hay a dónde bajar.
    assert target_for("downgrade_severity", label(severity="info")) is None


def test_drop_toma_la_primera_tecnica() -> None:
    assert target_for("drop_technique", label()).technique_id == "T1566"


def test_reporte_sin_material_para_un_goal() -> None:
    sin_iocs = label(iocs=[{"value": "x.com", "type": "domain", "verdict": "benign"}])
    t = targets_for_report(sin_iocs, ["flip_to_benign", "drop_technique"])
    assert "flip_to_benign" not in t, "no hay dominio malicioso que voltear"
    assert "drop_technique" in t


def test_seleccion_determinista() -> None:
    assert target_for("flip_to_benign", label()) == target_for("flip_to_benign", label())


def test_manifiesto_generado_valida_si_existe() -> None:
    """Si ya se corrió `aitm attack`, cada línea del manifiesto cumple el esquema."""
    from aitm.attacks.base import PoisonManifestEntry

    manifest = Path("data/poisoned/manifest.jsonl")
    if not manifest.is_file():
        return  # no se ha generado en este entorno
    lines = manifest.read_text(encoding="utf-8").splitlines()
    for line in lines[:50]:
        entry = PoisonManifestEntry.model_validate_json(line)
        assert entry.poison_id and entry.clean_sha256 and entry.poisoned_sha256
        if entry.injection.visibility == "invisible":
            assert entry.visual_equivalent is True, f"{entry.poison_id} no se ve igual"
        assert entry.payload_reaches_model is True
