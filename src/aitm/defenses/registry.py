"""Registro de defensas: nombre -> fabrica, y construccion del analista defendido.

Agregar una defensa es registrarla aqui; el resto del sistema (CLI, runner de la
Fase 5) la descubre sola. Los nombres son los de `config.yaml` (`defenses.enabled`) y
los valida `aitm.config.DefenseName`.

```python
from aitm.defenses.registry import build_analyst

analyst = build_analyst(config, client)                       # las de config.yaml
analyst = build_analyst(config, client, defenses=["sanitizer"])  # override explicito
analyst = build_analyst(config, client, defenses=[])          # sin defensas
```
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from aitm.config import Config
from aitm.defenses.base import CANONICAL_ORDER, Composition, Defense, compose
from aitm.defenses.sanitizer import Sanitizer
from aitm.defenses.schema_validator import SchemaValidator
from aitm.defenses.spotlighting import Spotlighting

#: Cada fabrica recibe la configuracion y el cliente de Ollama (el juez lo necesita).
Factory = Callable[[Config, Any], Defense]

_FACTORIES: dict[str, Factory] = {
    "sanitizer": lambda config, client: Sanitizer(),
    "spotlighting": lambda config, client: Spotlighting(config),
    "schema_validation": lambda config, client: SchemaValidator(),
}


def available() -> list[str]:
    """Defensas implementadas, en orden canonico."""
    return [name for name in CANONICAL_ORDER if name in _FACTORIES] + sorted(
        name for name in _FACTORIES if name not in CANONICAL_ORDER
    )


def parse_names(spec: str | None) -> list[str] | None:
    """`"sanitizer,llm_judge"` -> lista; `"none"` o `""` -> []; `None` -> `None` (usar config)."""
    if spec is None:
        return None
    if spec.strip().lower() in ("", "none", "ninguna"):
        return []
    return [name.strip() for name in spec.split(",") if name.strip()]


def build_defenses(names: Iterable[str], config: Config, client: Any = None) -> list[Defense]:
    defenses = []
    for name in names:
        try:
            factory = _FACTORIES[name]
        except KeyError:
            raise KeyError(f"defensa desconocida: {name!r}. Implementadas: {available()}") from None
        defenses.append(factory(config, client))
    return defenses


def composition_for(
    config: Config, client: Any = None, defenses: Iterable[str] | None = None
) -> Composition:
    """Las defensas pedidas (o las de `config.yaml`) ya compuestas en orden canonico."""
    names = list(config.defenses.enabled if defenses is None else defenses)
    return compose(build_defenses(names, config, client))


def build_analyst(
    config: Config,
    client: Any,
    *,
    model: str | None = None,
    defenses: Iterable[str] | None = None,
    **kwargs: Any,
):
    """Un `Analyst` con las defensas activas enchufadas en sus ganchos."""
    from aitm.analyst.pipeline import Analyst

    composition = composition_for(config, client, defenses)
    return Analyst(config=config, client=client, model=model, **composition.analyst_kwargs(), **kwargs)
