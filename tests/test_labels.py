"""Pruebas del formato de ground truth.

Las etiquetas se editan a mano, asi que la validacion es la unica red de seguridad
contra un error de tipeo que luego se convertiria en un falso negativo del modelo.
Cada prueba corresponde a un error que de verdad se comete etiquetando.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from aitm.evaluation.labels import (
    LabeledTechnique,
    ReportLabel,
    iter_labels,
    label_files,
    label_path,
    load_label,
    save_label,
)

BASE = {
    "report_id": "vendor_2026-01-01_caso",
    "source": {
        "corpus": "AnnoCTR",
        "file": "AnnoCTR/all/text/vendor_2026-01-01_caso.txt",
        "vendor": "vendor",
        "published": "2026-01-01",
        "license": "CC-BY-SA-4.0",
    },
    "formats": ["txt", "html", "pdf"],
    "severity": "high",
    "iocs": [
        {"value": "evil.com", "type": "domain", "verdict": "malicious"},
        {"value": "185.220.101.47", "type": "ipv4", "verdict": "suspicious"},
    ],
    "mitre_attack": [{"technique_id": "T1566.001", "technique_name": "Spearphishing"}],
}


def etiqueta(**cambios) -> dict:
    return {**BASE, **cambios}


def test_etiqueta_minima_valida() -> None:
    label = ReportLabel.model_validate(BASE)
    assert label.status == "draft"
    assert label.ioc_values() == {"evil.com", "185.220.101.47"}
    assert label.verdict_of("evil.com") == "malicious"
    assert label.verdict_of("no-existe.com") is None


def test_el_valor_se_guarda_normalizado() -> None:
    """Un indicador copiado "defanged" del reporte debe quedar canonizado."""
    label = ReportLabel.model_validate(
        etiqueta(iocs=[{"value": "hxxps://EVIL[.]com/a", "type": "url", "verdict": "malicious"}])
    )
    assert label.iocs[0].value == "https://evil.com/a"


def test_clave_desconocida_falla() -> None:
    with pytest.raises(ValidationError):
        ReportLabel.model_validate(etiqueta(severidad="high"))  # typo en espanol


def test_severidad_invalida_falla() -> None:
    with pytest.raises(ValidationError):
        ReportLabel.model_validate(etiqueta(severity="muy alta"))


def test_iocs_repetidos_fallan() -> None:
    repetido = [
        {"value": "evil.com", "type": "domain", "verdict": "malicious"},
        {"value": "evil.com", "type": "domain", "verdict": "benign"},
    ]
    with pytest.raises(ValidationError, match="repetidos"):
        ReportLabel.model_validate(etiqueta(iocs=repetido))


def test_incluido_y_excluido_a_la_vez_falla() -> None:
    """Un indicador no puede estar en el caso y fuera del caso al mismo tiempo."""
    with pytest.raises(ValidationError, match="incluidos y excluidos"):
        ReportLabel.model_validate(
            etiqueta(
                excluded_iocs=[
                    {"value": "evil.com", "type": "domain", "reason": "reference_only"}
                ]
            )
        )


def test_motivo_de_exclusion_invalido_falla() -> None:
    with pytest.raises(ValidationError):
        ReportLabel.model_validate(
            etiqueta(
                excluded_iocs=[
                    {"value": "otro.com", "type": "domain", "reason": "no me gusta"}
                ]
            )
        )


@pytest.mark.parametrize("malo", ["T123", "1566", "T1566.1", "TT1566", "T1566.001.1"])
def test_technique_id_mal_formado_falla(malo: str) -> None:
    with pytest.raises(ValidationError):
        LabeledTechnique(technique_id=malo)


@pytest.mark.parametrize("bueno", ["T1566", "T1566.001", "t1059.001"])
def test_technique_id_valido_se_normaliza(bueno: str) -> None:
    assert LabeledTechnique(technique_id=bueno).technique_id == bueno.upper()


def test_revisado_exige_anotador_y_revisor() -> None:
    with pytest.raises(ValidationError, match="annotators"):
        ReportLabel.model_validate(etiqueta(status="reviewed"))

    with pytest.raises(ValidationError, match="reviewers"):
        ReportLabel.model_validate(etiqueta(status="reviewed", annotators=["Mariana"]))


def test_nadie_revisa_su_propio_etiquetado() -> None:
    """El enunciado pide que cada reporte lo revise una segunda persona."""
    with pytest.raises(ValidationError, match="su propio"):
        ReportLabel.model_validate(
            etiqueta(
                status="reviewed",
                annotators=["Mariana", "Raul"],
                reviewers=["Raul"],
            )
        )

    valida = ReportLabel.model_validate(
        etiqueta(status="reviewed", annotators=["Mariana"], reviewers=["Raul"])
    )
    assert valida.status == "reviewed"


def test_guardar_y_cargar_es_ida_y_vuelta(tmp_path) -> None:
    label = ReportLabel.model_validate(BASE)
    destino = save_label(label, label_path(tmp_path, label.report_id))

    assert destino.name == "vendor_2026-01-01_caso.json"
    assert load_label(destino) == label

    # Legible para una persona y con salto de linea final: se edita a mano y se
    # revisa en diffs de git.
    contenido = destino.read_text(encoding="utf-8")
    assert contenido.endswith("\n")
    assert json.loads(contenido)["report_id"] == label.report_id


def test_iter_labels_recorre_en_orden(tmp_path) -> None:
    for report_id in ("c_caso", "a_caso", "b_caso"):
        label = ReportLabel.model_validate(etiqueta(report_id=report_id))
        save_label(label, label_path(tmp_path, report_id))

    assert [label.report_id for label in iter_labels(tmp_path)] == [
        "a_caso",
        "b_caso",
        "c_caso",
    ]


def test_assisted_exige_anotador_pero_no_revisor() -> None:
    """`assisted` dice "ya lo decidio alguien"; la firma es un paso aparte."""
    with pytest.raises(ValidationError, match="annotators"):
        ReportLabel.model_validate(etiqueta(status="assisted"))

    valida = ReportLabel.model_validate(
        etiqueta(status="assisted", annotators=["integrante del equipo"])
    )
    assert valida.status == "assisted"
    assert valida.reviewers == []


def test_el_anotador_no_puede_firmarse_a_si_mismo() -> None:
    """Pasar de `assisted` a `reviewed` exige a alguien distinto del anotador."""
    anotador = "integrante del equipo"
    with pytest.raises(ValidationError, match="su propio"):
        ReportLabel.model_validate(
            etiqueta(status="reviewed", annotators=[anotador], reviewers=[anotador])
        )


def test_label_files_ignora_los_reservados(tmp_path) -> None:
    """FROZEN.json vive en data/labels/ pero no es una etiqueta."""
    label = ReportLabel.model_validate(BASE)
    save_label(label, label_path(tmp_path, label.report_id))
    (tmp_path / "FROZEN.json").write_text('{"frozen_at": "x"}', encoding="utf-8")

    assert [path.name for path in label_files(tmp_path)] == [
        "vendor_2026-01-01_caso.json"
    ]
    assert [item.report_id for item in iter_labels(tmp_path)] == [label.report_id]


def test_las_etiquetas_del_repo_son_validas() -> None:
    """Las 12 etiquetas reales del dataset tienen que cargar sin tocar nada."""
    from aitm.config import load_config

    config = load_config()
    labels_dir = config.resolve(config.paths.labels)
    labels = list(iter_labels(labels_dir))
    assert labels, "no hay etiquetas: corre scripts/draft_labels.py"
    assert all(label.iocs for label in labels)
    assert all(label.source.license == "CC-BY-SA-4.0" for label in labels)
    # Ninguna deberia quedar en `draft`: eso seria salida cruda del extractor.
    assert all(label.status != "draft" for label in labels)
    # Y toda etiqueta ya decidida dice quien la decidio.
    assert all(label.annotators for label in labels)
