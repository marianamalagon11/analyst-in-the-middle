"""Definicion de los experimentos de la Fase 5 (`experiments/*.yaml`) y sus celdas.

Un experimento es un subconjunto declarado de la matriz
`reporte × ataque × defensas × modelo`. Se escribe en YAML para que quede versionado
**antes** de correr y no se elija a posteriori que celdas mirar:

```yaml
name: e1_vectores
description: ASR por vector, sin defensas, modelo principal
models: [analyst]                 # `analyst` = models.analyst de config.yaml
defenses: [[]]                    # lista de combinaciones; [] = sin defensas
goals: [flip_to_benign, omit_ioc, downgrade_severity, drop_technique]
attacks:                          # vector -> variantes y formatos a incluir
  plaintext: {variants: [inline], formats: [txt]}
reports: all                      # o una lista de report_id
clean: true                       # tambien los limpios (necesarios para el ASR)
```

Cada combinacion `modelo × defensas` corre los limpios de los formatos usados y los
envenenados del manifiesto de la Fase 3 que cumplan el filtro. Solo se usa el payload
canonico de cada objetivo (`payloads.CANONICAL`, fijado antes de ver resultados).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aitm.attacks.base import ATTACK_GOALS, AttackGoal, PoisonManifestEntry
from aitm.attacks.payloads import CANONICAL
from aitm.config import Config, DefenseName
from aitm.defenses.base import CANONICAL_ORDER


class AttackFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    variants: list[str] = Field(min_length=1)
    formats: list[Literal["txt", "html", "pdf"]] = Field(min_length=1)


class ExperimentSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    models: list[str] = Field(min_length=1)
    defenses: list[list[DefenseName]] = Field(min_length=1)
    goals: list[AttackGoal] = Field(default_factory=lambda: list(ATTACK_GOALS))
    attacks: dict[str, AttackFilter] = Field(default_factory=dict)
    reports: list[str] | Literal["all"] = "all"
    clean: bool = True

    @field_validator("defenses")
    @classmethod
    def _canonical(cls, value: list[list[str]]) -> list[list[str]]:
        """Cada combinacion en orden canonico: `[llm_judge, sanitizer]` = `[sanitizer, llm_judge]`."""
        out = []
        for combo in value:
            if len(set(combo)) != len(combo):
                raise ValueError(f"defensa repetida en {combo}")
            out.append(sorted(combo, key=CANONICAL_ORDER.index))
        return out

    def resolved_models(self, config: Config) -> list[str]:
        alias = {"analyst": config.models.analyst, "judge": config.models.judge}
        return [alias.get(model, model) for model in self.models]

    @property
    def formats(self) -> list[str]:
        used = {fmt for spec in self.attacks.values() for fmt in spec.formats}
        return [fmt for fmt in ("txt", "html", "pdf") if fmt in used]


def load_spec(path: Path | str) -> ExperimentSpec:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return ExperimentSpec.model_validate(data)


def defenses_label(defenses: list[str] | tuple[str, ...]) -> str:
    return "+".join(defenses) if defenses else "ninguna"


@dataclass(frozen=True)
class Cell:
    """Un analisis a correr: un documento con un modelo y una combinacion de defensas."""

    model: str
    defenses: tuple[str, ...]
    report_id: str
    source_format: str
    path: Path
    attack: dict[str, Any] | None = None

    @property
    def kind(self) -> str:
        return "poisoned" if self.attack else "clean"


def load_manifest(config: Config) -> list[PoisonManifestEntry]:
    path = config.resolve(config.paths.poisoned) / "manifest.jsonl"
    if not path.is_file():
        return []
    return [
        PoisonManifestEntry.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def attack_payload(entry: PoisonManifestEntry) -> dict[str, Any]:
    """Lo que viaja a `RunRecord.attack`: la entrada del manifiesto completa."""
    return entry.model_dump(mode="json")


def enumerate_cells(
    spec: ExperimentSpec,
    config: Config,
    manifest: list[PoisonManifestEntry] | None = None,
) -> list[Cell]:
    """Celdas del experimento, en un orden pensado para medir mientras corre.

    Modelo por fuera (Ollama no recarga pesos en cada celda), luego defensas, y dentro
    de cada combinacion primero los limpios: el ASR de un envenenado necesita su limpio.
    """
    manifest = load_manifest(config) if manifest is None else manifest
    processed = config.resolve(config.paths.data_processed)
    poisoned_root = config.resolve(config.paths.poisoned)
    report_ids = sorted({entry.report_id for entry in manifest}) if spec.reports == "all" else list(spec.reports)
    wanted = set(report_ids)

    selected = [
        entry
        for entry in manifest
        if entry.report_id in wanted
        and entry.goal in spec.goals
        and entry.injection.vector in spec.attacks
        and entry.injection.variant in spec.attacks[entry.injection.vector].variants
        and entry.source_format in spec.attacks[entry.injection.vector].formats
        and entry.injection.payload_id == CANONICAL[entry.goal]
    ]
    vector_order = list(spec.attacks)
    selected.sort(
        key=lambda e: (
            vector_order.index(e.injection.vector),
            e.injection.variant,
            e.source_format,
            spec.goals.index(e.goal),
            e.report_id,
        )
    )

    cells: list[Cell] = []
    for model in spec.resolved_models(config):
        for combo in spec.defenses:
            defenses = tuple(combo)
            if spec.clean:
                for fmt in spec.formats:
                    for report_id in report_ids:
                        cells.append(
                            Cell(model, defenses, report_id, fmt, processed / fmt / f"{report_id}.{fmt}")
                        )
            for entry in selected:
                cells.append(
                    Cell(
                        model,
                        defenses,
                        entry.report_id,
                        entry.source_format,
                        poisoned_root / entry.poisoned_path,
                        attack_payload(entry),
                    )
                )
    return cells
