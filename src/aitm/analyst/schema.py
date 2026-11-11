"""Contrato del JSON que devuelve el analista (docs/ARCHITECTURE.md, seccion 5).

Dos piezas que tienen que decir lo mismo:

1. **Los modelos Pydantic**, que validan lo que respondio el LLM.
2. **`ollama_schema()`**, el JSON Schema que se manda en `format` para que Ollama
   restrinja la generacion. Se construye a partir de los mismos tipos cerrados
   (`Severity`, `Verdict`, `IoCType`) para que no se desincronicen.

Decisiones que vale la pena tener presentes al leer las metricas:

- **El modelo no escribe `report_id`.** Lo pone el pipeline. Pedirselo al modelo
  gasta tokens y abre una puerta mas a la manipulacion.
- **Validacion tolerante por elemento.** Un IoC con un tipo inventado o una tecnica
  mal escrita se descarta solo y queda anotado en `warnings`; el resto del analisis
  se conserva. Un fallo en el nivel superior (severidad invalida, JSON que no es un
  objeto) si invalida la respuesta y dispara un reintento. Es el comportamiento de un
  pipeline razonable *sin* defensas: la validacion estricta, incluida la regla de que
  todo IoC exista en el texto, es la defensa `schema_validation` de la Fase 4.
- **Textos acotados.** Generar es el cuello de botella (results/setup_report.md): se
  limita `evidence` y `summary` en el esquema y se recorta aqui por si el modelo se
  pasa.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, get_args

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aitm.analyst.iocs import IoCType
from aitm.evaluation.labels import Severity, Verdict

#: De menor a mayor. Sirve para comparar severidades (acierto a +-1 nivel, ataques
#: `downgrade_severity`).
SEVERITY_ORDER: tuple[Severity, ...] = ("info", "low", "medium", "high", "critical")

#: Longitudes maximas. Se piden en el prompt, se imponen en el esquema de Ollama y se
#: recortan al validar.
EVIDENCE_MAX = 160
SUMMARY_MAX = 400
NOTE_MAX = 200

#: Topes de las listas. Con decodificacion greedy (temperatura 0, top_k 1) un modelo
#: que empieza a enumerar tecnicas inventadas (`T1086.038`, `.039`, `.040`...) no sale
#: del bucle hasta agotar `num_predict` y el JSON queda cortado: lo vimos con mistral
#: y llama3.1 en la Fase 2. `maxItems` hace que la gramatica de Ollama obligue a cerrar
#: la lista. Los topes estan por encima del maximo del ground truth (26 IoCs y 20
#: tecnicas en un reporte), asi que nunca recortan un acierto posible.
MAX_IOCS = 50
MAX_TECHNIQUES = 25
MAX_NOTES = 5

TECHNIQUE_PATTERN = r"^T[0-9]{4}(\.[0-9]{3})?$"
_TECHNIQUE = re.compile(TECHNIQUE_PATTERN)


class OutputError(ValueError):
    """La respuesta del modelo no se puede usar como analisis (dispara un reintento)."""


def _clip(value: Any, limit: int) -> Any:
    return value[:limit] if isinstance(value, str) else value


def _clamp_confidence(value: Any) -> Any:
    """Una confianza de 1.2 no justifica perder el indicador: se lleva a [0, 1]."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return min(1.0, max(0.0, float(value)))
    return value


class _Base(BaseModel):
    # Las claves de mas se ignoran: con `format` no deberian aparecer, y si aparecen
    # no son motivo para perder el analisis.
    model_config = ConfigDict(extra="ignore")


class IoCFinding(_Base):
    value: str = Field(min_length=1)
    type: IoCType
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str = ""

    @field_validator("value", mode="before")
    @classmethod
    def _strip(cls, value: Any) -> Any:
        return value.strip() if isinstance(value, str) else value

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Any:
        return _clamp_confidence(value)

    @field_validator("evidence", mode="before")
    @classmethod
    def _evidence(cls, value: Any) -> Any:
        return _clip(value, EVIDENCE_MAX)


class TechniqueFinding(_Base):
    technique_id: str
    technique_name: str = ""
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("technique_id", mode="before")
    @classmethod
    def _technique_id(cls, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        value = value.strip().upper()
        if not _TECHNIQUE.match(value):
            raise ValueError(f"technique_id invalido: {value!r} (se espera T#### o T####.###)")
        return value

    @field_validator("confidence", mode="before")
    @classmethod
    def _confidence(cls, value: Any) -> Any:
        return _clamp_confidence(value)


class AnalystOutput(_Base):
    """Analisis de un reporte, ya validado."""

    report_id: str = ""
    summary: str = ""
    severity: Severity
    iocs: list[IoCFinding] = Field(default_factory=list)
    mitre_attack: list[TechniqueFinding] = Field(default_factory=list)
    threat_actor: str | None = None
    notes: list[str] = Field(default_factory=list)

    @field_validator("summary", mode="before")
    @classmethod
    def _summary(cls, value: Any) -> Any:
        return _clip(value, SUMMARY_MAX)

    @field_validator("threat_actor", mode="before")
    @classmethod
    def _actor(cls, value: Any) -> Any:
        # "", "unknown", "N/A": el modelo dice "no se" de muchas formas.
        if isinstance(value, str) and value.strip().lower() in {
            "", "unknown", "desconocido", "n/a", "none", "null", "ninguno",
        }:
            return None
        return value

    @field_validator("notes", mode="before")
    @classmethod
    def _notes(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [_clip(note, NOTE_MAX) for note in value if isinstance(note, str)][:MAX_NOTES]
        return value


@dataclass
class ValidatedOutput:
    output: AnalystOutput
    warnings: list[str] = field(default_factory=list)


def _short(error: ValidationError) -> str:
    """Resumen de una linea del primer error, para las trazas y el reintento."""
    first = error.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    return f"{location}: {first.get('msg', 'invalido')}" if location else first["msg"]


def validate_output(data: Any) -> ValidatedOutput:
    """Valida el objeto que devolvio el modelo, descartando elementos invalidos.

    Lanza `OutputError` si el problema es del objeto entero (no es un objeto, falta la
    severidad o no es valida, `iocs` no es una lista).
    """
    if not isinstance(data, dict):
        raise OutputError(f"se esperaba un objeto JSON y llego {type(data).__name__}")

    warnings: list[str] = []
    collected: dict[str, list[BaseModel]] = {}
    for key, model, limit in (
        ("iocs", IoCFinding, MAX_IOCS),
        ("mitre_attack", TechniqueFinding, MAX_TECHNIQUES),
    ):
        items = data.get(key, [])
        if items is None:
            items = []
        if not isinstance(items, list):
            raise OutputError(f"`{key}` debe ser una lista")
        if len(items) > limit:
            # Sin `format` (structured_output: false) el tope no lo impone Ollama.
            warnings.append(f"{key}: {len(items)} elementos, se conservan los {limit} primeros")
            items = items[:limit]
        valid: list[BaseModel] = []
        for index, item in enumerate(items):
            try:
                valid.append(model.model_validate(item))
            except ValidationError as error:
                warnings.append(f"{key}[{index}] descartado: {_short(error)}")
        collected[key] = valid

    top = {key: value for key, value in data.items() if key not in collected}
    try:
        output = AnalystOutput.model_validate({**top, **collected})
    except ValidationError as error:
        raise OutputError(_short(error)) from error
    return ValidatedOutput(output=output, warnings=warnings)


def ollama_schema() -> dict[str, Any]:
    """JSON Schema para el parametro `format` de Ollama.

    Se escribe plano (sin `$ref`) y con los mismos enums que los modelos Pydantic: la
    gramatica que Ollama deriva del esquema es mas fiable cuanto mas simple es. El
    orden de `properties` es el orden en que el modelo genera los campos.
    """
    confidence = {"type": "number", "minimum": 0, "maximum": 1}
    ioc = {
        "type": "object",
        "properties": {
            "value": {"type": "string"},
            "type": {"type": "string", "enum": list(get_args(IoCType))},
            "verdict": {"type": "string", "enum": list(get_args(Verdict))},
            "confidence": confidence,
            "evidence": {"type": "string", "maxLength": EVIDENCE_MAX},
        },
        "required": ["value", "type", "verdict", "confidence", "evidence"],
    }
    technique = {
        "type": "object",
        "properties": {
            "technique_id": {"type": "string", "pattern": TECHNIQUE_PATTERN},
            "technique_name": {"type": "string"},
            "confidence": confidence,
        },
        "required": ["technique_id", "technique_name", "confidence"],
    }
    return {
        "type": "object",
        "properties": {
            "summary": {"type": "string", "maxLength": SUMMARY_MAX},
            "severity": {"type": "string", "enum": list(SEVERITY_ORDER)},
            "iocs": {"type": "array", "items": ioc, "maxItems": MAX_IOCS},
            "mitre_attack": {
                "type": "array",
                "items": technique,
                "maxItems": MAX_TECHNIQUES,
            },
            "threat_actor": {"type": ["string", "null"]},
            "notes": {
                "type": "array",
                "items": {"type": "string", "maxLength": NOTE_MAX},
                "maxItems": MAX_NOTES,
            },
        },
        "required": [
            "summary",
            "severity",
            "iocs",
            "mitre_attack",
            "threat_actor",
            "notes",
        ],
    }


def severity_rank(severity: Severity) -> int:
    return SEVERITY_ORDER.index(severity)
