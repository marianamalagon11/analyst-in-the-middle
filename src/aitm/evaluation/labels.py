"""Ground truth de un reporte: formato, validacion y carga.

Un archivo por reporte en `data/labels/<report_id>.json`. Es el contrato entre el
etiquetado manual (Fase 1) y las metricas (Fase 2+), asi que se valida con Pydantic y
no se acepta nada fuera del esquema: una clave mal escrita en una etiqueta hecha a
mano tiene que fallar ruidosamente, no colarse hasta las graficas del informe.

Diferencias deliberadas con el JSON que devuelve el analista
(`docs/ARCHITECTURE.md`, seccion 5):

- **No hay `confidence`.** Una persona no produce confianzas calibradas; pedirlas solo
  genera numeros inventados. El modelo si las da, y se evaluan aparte.
- **Hay `excluded_iocs`.** Son los indicadores que el texto menciona pero que no son
  del caso (el dominio del propio vendor, una IP interna de ejemplo). Tenerlos
  explicitos permite distinguir "el modelo invento un IoC" de "el modelo reporto algo
  que estaba ahi pero no tocaba", que son dos errores distintos.
- **Hay `status` y revisores.** El enunciado pide que cada reporte lo revise una
  segunda persona; el estado vive en el propio archivo para que se pueda auditar.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aitm.analyst.iocs import IoCType, normalize_value

Severity = Literal["critical", "high", "medium", "low", "info"]
Verdict = Literal["malicious", "suspicious", "benign"]

#: Ciclo de vida de una etiqueta:
#:
#: - `draft`: salida cruda del extractor. Los veredictos son propuestas mecanicas y la
#:   severidad es un valor por defecto. **No sirve para medir.**
#: - `assisted`: un integrante del equipo ya paso por el reporte entero decidiendo
#:   veredicto por indicador y severidad. Queda constancia en `annotators`. Sigue
#:   faltando la revision independiente de un segundo revisor.
#: - `reviewed`: una segunda persona, distinta del anotador, la reviso y firmo.
#: - `frozen`: congelada; a partir de aqui las metricas son comparables entre corridas.
LabelStatus = Literal["draft", "assisted", "reviewed", "frozen"]

#: Razones por las que un indicador presente en el texto queda fuera del caso.
ExclusionReason = Literal[
    "vendor_infrastructure",  # dominio del propio vendor, redes sociales, sandboxes
    "internal_address",  # IP privada o reservada del entorno de la victima
    "legitimate_service",  # servicio abusado pero no malicioso en si (ipinfo.io)
    "reference_only",  # enlace a otro articulo, CVE citado de pasada
    "extraction_artifact",  # basura del parser: token partido, numero leido como IP
]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LabelSource(_Base):
    """Procedencia del reporte. Sin esto no podemos citar la fuente en el informe."""

    corpus: str
    file: str
    vendor: str | None = None
    published: str | None = None
    license: str
    url: str | None = None


class LabeledIoC(_Base):
    value: str
    type: IoCType
    verdict: Verdict
    notes: str = ""

    @field_validator("value")
    @classmethod
    def _not_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("el valor del IoC no puede estar vacio")
        return value.strip()

    @model_validator(mode="after")
    def _normalized(self) -> LabeledIoC:
        """El valor se guarda ya canonizado: el emparejamiento no debe adivinar.

        Asi un `hxxps://EVIL[.]com` escrito a mano en la etiqueta queda igual que lo
        que produce el extractor y que lo que se normalizara de la salida del modelo.
        """
        self.value = normalize_value(self.type, self.value)
        return self


class ExcludedIoC(_Base):
    value: str
    type: IoCType
    reason: ExclusionReason
    notes: str = ""


class LabeledTechnique(_Base):
    technique_id: str
    technique_name: str = ""

    @field_validator("technique_id")
    @classmethod
    def _valid_id(cls, value: str) -> str:
        value = value.strip().upper()
        parts = value.split(".")
        head = parts[0]
        if not (head.startswith("T") and head[1:].isdigit() and len(head) == 5):
            raise ValueError(f"technique_id invalido: {value!r} (se espera T#### o T####.###)")
        if len(parts) == 2 and not (len(parts[1]) == 3 and parts[1].isdigit()):
            raise ValueError(f"subtecnica invalida en {value!r} (se espera .###)")
        if len(parts) > 2:
            raise ValueError(f"technique_id invalido: {value!r}")
        return value


class ReportLabel(_Base):
    """Ground truth completo de un reporte."""

    report_id: str
    source: LabelSource
    formats: list[Literal["txt", "html", "pdf"]] = Field(min_length=1)
    status: LabelStatus = "draft"
    annotators: list[str] = Field(default_factory=list)
    reviewers: list[str] = Field(default_factory=list)
    severity: Severity
    threat_actor: str | None = None
    iocs: list[LabeledIoC] = Field(default_factory=list)
    excluded_iocs: list[ExcludedIoC] = Field(default_factory=list)
    mitre_attack: list[LabeledTechnique] = Field(default_factory=list)
    notes: str = ""

    @model_validator(mode="after")
    def _no_duplicates(self) -> ReportLabel:
        seen = [(ioc.type, ioc.value) for ioc in self.iocs]
        duplicates = {key for key in seen if seen.count(key) > 1}
        if duplicates:
            raise ValueError(f"IoCs repetidos en {self.report_id}: {sorted(duplicates)}")

        included = {ioc.value for ioc in self.iocs}
        collisions = sorted(included & {ioc.value for ioc in self.excluded_iocs})
        if collisions:
            raise ValueError(
                f"{self.report_id}: estos valores estan a la vez incluidos y excluidos: "
                f"{collisions}"
            )
        return self

    @model_validator(mode="after")
    def _review_rules(self) -> ReportLabel:
        """Una etiqueta no avanza de estado sin decir quien hizo cada cosa."""
        if self.status != "draft" and not self.annotators:
            raise ValueError(
                f"{self.report_id}: falta `annotators` para status={self.status}"
            )
        if self.status in ("reviewed", "frozen"):
            if not self.reviewers:
                raise ValueError(f"{self.report_id}: falta `reviewers` para status={self.status}")
            overlap = set(self.annotators) & set(self.reviewers)
            if overlap:
                raise ValueError(
                    f"{self.report_id}: {sorted(overlap)} no puede revisar su propio "
                    "etiquetado (el enunciado pide una segunda persona)"
                )
        return self

    def ioc_values(self) -> set[str]:
        return {ioc.value for ioc in self.iocs}

    def verdict_of(self, value: str) -> Verdict | None:
        for ioc in self.iocs:
            if ioc.value == value:
                return ioc.verdict
        return None


#: Archivos de `data/labels/` que no son etiquetas y hay que saltar al recorrer la
#: carpeta. `FROZEN.json` lo escribe scripts/freeze_dataset.py con las huellas sha256.
RESERVED_FILES = frozenset({"FROZEN.json"})


def label_path(labels_dir: Path, report_id: str) -> Path:
    return Path(labels_dir) / f"{report_id}.json"


def label_files(labels_dir: Path | str) -> list[Path]:
    """Archivos de etiqueta de la carpeta, en orden alfabetico y sin los reservados."""
    return sorted(
        path
        for path in Path(labels_dir).glob("*.json")
        if path.name not in RESERVED_FILES
    )


def load_label(path: Path | str) -> ReportLabel:
    path = Path(path)
    with path.open(encoding="utf-8") as handle:
        return ReportLabel.model_validate(json.load(handle))


def save_label(label: ReportLabel, path: Path | str) -> Path:
    """Escribe el JSON con claves en orden estable: los diffs tienen que leerse bien."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = label.model_dump(mode="json")
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return path


def iter_labels(labels_dir: Path | str) -> Iterator[ReportLabel]:
    """Recorre las etiquetas en orden alfabetico, fallando en la primera invalida."""
    for path in label_files(labels_dir):
        yield load_label(path)
