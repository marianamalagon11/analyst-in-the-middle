"""Carga y validacion de config.yaml.

El hash de la configuracion viaja con cada corrida para que un resultado
siempre se pueda rastrear hasta los parametros que lo produjeron.
"""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

DefenseName = Literal["sanitizer", "spotlighting", "schema_validation", "llm_judge"]

CONFIG_FILENAME = "config.yaml"


class _Base(BaseModel):
    """Rechaza claves desconocidas: un typo en el YAML debe fallar, no ignorarse."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class OllamaConfig(_Base):
    host: str = "http://localhost:11434"
    timeout_s: int = Field(300, gt=0)
    keep_alive: str = "15m"
    max_retries: int = Field(2, ge=0)


class ModelsConfig(_Base):
    analyst: str
    judge: str
    compare: list[str] = Field(min_length=1)


class GenerationConfig(_Base):
    temperature: float = Field(0.0, ge=0.0)
    top_p: float = Field(1.0, gt=0.0, le=1.0)
    top_k: int = Field(1, ge=1)
    repeat_penalty: float = Field(1.0, gt=0.0)
    num_ctx: int = Field(8192, gt=0)
    num_predict: int = Field(2048, gt=0)


class AnalystConfig(_Base):
    system_prompt: Path
    max_parse_retries: int = Field(2, ge=0)
    structured_output: bool = True


class JudgeConfig(_Base):
    system_prompt: Path
    threshold: float = Field(0.5, ge=0.0, le=1.0)


class DefensesConfig(_Base):
    enabled: list[DefenseName] = Field(default_factory=list)

    @field_validator("enabled")
    @classmethod
    def _no_duplicates(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("hay defensas repetidas en defenses.enabled")
        return value


class AttacksConfig(_Base):
    vectors: list[str] = Field(min_length=1)
    goals: list[str] = Field(min_length=1)


class PathsConfig(_Base):
    data_raw: Path
    data_processed: Path
    labels: Path
    poisoned: Path
    runs: Path
    tables: Path
    figures: Path


class Config(_Base):
    project: str
    seed: int
    ollama: OllamaConfig
    models: ModelsConfig
    generation: GenerationConfig
    analyst: AnalystConfig
    judge: JudgeConfig
    defenses: DefensesConfig
    attacks: AttacksConfig
    paths: PathsConfig

    @property
    def config_hash(self) -> str:
        """Huella estable de la configuracion (12 hex)."""
        payload = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, ensure_ascii=False
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]

    def resolve(self, path: Path) -> Path:
        """Convierte una ruta del YAML en absoluta, relativa a la raiz del repo."""
        return path if path.is_absolute() else project_root() / path


def project_root(start: Path | None = None) -> Path:
    """Sube desde `start` hasta encontrar la carpeta que contiene config.yaml."""
    current = (start or Path(__file__)).resolve()
    for candidate in [current, *current.parents]:
        if (candidate / CONFIG_FILENAME).is_file():
            return candidate
    raise FileNotFoundError(
        f"no se encontro {CONFIG_FILENAME} subiendo desde {current}"
    )


def load_config(path: Path | str | None = None) -> Config:
    """Lee y valida config.yaml. Sin argumento usa el de la raiz del repo."""
    config_path = Path(path) if path else project_root() / CONFIG_FILENAME
    with config_path.open(encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    if not isinstance(raw, dict):
        raise ValueError(f"{config_path} no contiene un mapeo YAML")
    return Config.model_validate(raw)


@lru_cache(maxsize=1)
def get_config() -> Config:
    """Configuracion por defecto, cacheada para el resto del programa."""
    return load_config()
