"""Pruebas de la carga de configuracion."""

from __future__ import annotations

import pytest
import yaml
from pydantic import ValidationError

from aitm.config import Config, load_config, project_root


def test_config_del_repo_es_valida() -> None:
    config = load_config()
    assert config.project == "analyst-in-the-middle"
    assert config.generation.temperature == 0.0, "los experimentos exigen temperatura 0"
    assert config.models.analyst in config.models.compare


def test_hash_estable_y_sensible_al_cambio() -> None:
    config = load_config()
    assert config.config_hash == load_config().config_hash

    otra = config.model_copy(update={"seed": config.seed + 1})
    assert otra.config_hash != config.config_hash


def test_clave_desconocida_falla(tmp_path) -> None:
    raw = yaml.safe_load((project_root() / "config.yaml").read_text(encoding="utf-8"))
    raw["ollama"]["puerto"] = 11434  # typo tipico

    with pytest.raises(ValidationError):
        Config.model_validate(raw)


def test_defensa_invalida_falla() -> None:
    raw = yaml.safe_load((project_root() / "config.yaml").read_text(encoding="utf-8"))
    raw["defenses"]["enabled"] = ["sanitizador"]  # nombre que no existe

    with pytest.raises(ValidationError):
        Config.model_validate(raw)


def test_rutas_se_resuelven_contra_la_raiz() -> None:
    config = load_config()
    resuelta = config.resolve(config.paths.runs)
    assert resuelta.is_absolute()
    assert resuelta.parent.name == "results"
