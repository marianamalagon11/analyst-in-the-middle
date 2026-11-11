"""Trazas de cada analisis: el sobre de docs/ARCHITECTURE.md (seccion 5) en JSONL.

Cada corrida del analista produce un `RunRecord` con todo lo necesario para
reconstruirla y volver a evaluarla **sin llamar al LLM**: la configuracion (hash), el
modelo exacto (digest), el prompt (sha256 de su contenido, que el hash de la
configuracion no cubre porque solo guarda la ruta), el documento (sha256 del archivo
y del texto extraido), la respuesta cruda de cada intento y la salida validada.

Una carpeta de corrida es `results/runs/<timestamp>/` con:

- `runs.jsonl`: un `RunRecord` por linea, en orden de ejecucion.
- `meta.json`: la configuracion completa y el comando que la lanzo.

Se escribe en modo *append* y linea a linea: si la corrida se corta a las 3 horas,
lo hecho no se pierde y `completed_keys()` permite retomarla.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal

from pydantic import BaseModel, ConfigDict, Field

from aitm.analyst.schema import AnalystOutput

RUNS_FILE = "runs.jsonl"
META_FILE = "meta.json"

RunStatus = Literal["ok", "parse_failed", "truncated", "error"]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PromptInfo(_Base):
    system_path: str
    system_sha256: str
    user_template_sha256: str


class Attempt(_Base):
    """Un intento de generacion: lo que devolvio Ollama, tal cual."""

    content: str
    done_reason: str | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    latency_ms: int
    error: str | None = None


class RunRecord(_Base):
    run_id: str
    created_at: str
    config_hash: str
    model: str
    model_digest: str | None = None
    ollama_version: str | None = None
    host: str = ""

    report_id: str
    source_path: str
    source_format: Literal["txt", "html", "pdf"]
    source_sha256: str
    text_sha256: str
    text_chars: int
    parser: dict[str, bool]

    #: Que ataque lleva el documento. `None` en un reporte limpio. La Fase 3 lo llena
    #: con la entrada del manifiesto de envenenamiento.
    attack: dict[str, Any] | None = None
    #: Defensas activas. Vacio en la linea base.
    defenses: list[str] = Field(default_factory=list)
    #: Veredicto del juez (Fase 4).
    judge: dict[str, Any] | None = None
    #: Alguna defensa detuvo la corrida. La salida del analista se conserva igual: la
    #: Fase 5 mide tanto la deteccion como lo que habria pasado sin el bloqueo.
    blocked: bool = False
    #: Que hizo cada defensa activa ("sanitizer: quito 312 caracteres: ...").
    defense_notes: list[str] = Field(default_factory=list)

    prompt: PromptInfo
    status: RunStatus
    error: str | None = None
    parse_retries: int = 0
    validation_warnings: list[str] = Field(default_factory=list)
    context_warning: str | None = None
    latency_ms: dict[str, int] = Field(default_factory=dict)
    tokens: dict[str, int] = Field(default_factory=dict)
    messages: list[dict[str, str]] = Field(default_factory=list)
    attempts: list[Attempt] = Field(default_factory=list)
    output: AnalystOutput | None = None

    @property
    def key(self) -> str:
        return run_key(
            model=self.model,
            report_id=self.report_id,
            source_format=self.source_format,
            source_sha256=self.source_sha256,
            defenses=self.defenses,
            config_hash=self.config_hash,
        )


def run_key(
    *,
    model: str,
    report_id: str,
    source_format: str,
    source_sha256: str,
    defenses: list[str],
    config_hash: str,
) -> str:
    """Identidad de una celda del experimento, para no repetirla al reanudar.

    Se usa el sha256 del documento y no su nombre: dos reportes envenenados distintos
    del mismo reporte limpio son celdas distintas, y el mismo archivo es la misma celda.
    """
    return "|".join(
        [model, report_id, source_format, source_sha256, ",".join(defenses), config_hash]
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_run_dir(runs_root: Path) -> Path:
    """Carpeta nueva `results/runs/<timestamp>/`. No pisa una existente."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    candidate = Path(runs_root) / stamp
    suffix = 1
    while candidate.exists():
        candidate = Path(runs_root) / f"{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir(parents=True)
    return candidate


class RunLog:
    """Escritura y lectura de `runs.jsonl` dentro de una carpeta de corrida."""

    def __init__(self, run_dir: Path | str) -> None:
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / RUNS_FILE

    def append(self, record: RunRecord) -> None:
        line = record.model_dump_json()
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()

    def records(self) -> Iterator[RunRecord]:
        yield from iter_records(self.path)

    def completed_keys(self) -> set[str]:
        """Celdas ya hechas. Una corrida con `error` (Ollama caido) se reintenta."""
        return {record.key for record in self.records() if record.status != "error"}

    def write_meta(self, meta: dict[str, Any]) -> None:
        (self.run_dir / META_FILE).write_text(
            json.dumps(meta, indent=2, ensure_ascii=False, default=str) + "\n",
            encoding="utf-8",
        )


def iter_records(path: Path | str) -> Iterator[RunRecord]:
    """Lee un `runs.jsonl`. Una ultima linea cortada (corrida interrumpida) se salta."""
    path = Path(path)
    if not path.is_file():
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            yield RunRecord.model_validate_json(line)
        except ValueError:
            if number == len(lines):
                # Escritura interrumpida a mitad de linea: se descarta y se rehace.
                return
            raise
