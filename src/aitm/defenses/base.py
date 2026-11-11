"""Interfaz comun de las defensas y su composicion en el pipeline del analista.

Una defensa actua en una de tres **etapas** del pipeline (`src/aitm/analyst/pipeline.py`):

```
archivo ─► parse ─► [pre] ─► [prompt] ─► Ollama ─► validacion ─► [post] ─► traza
```

| Etapa | Recibe | Devuelve | Defensas |
|---|---|---|---|
| `pre` | el reporte ya leido (`ParsedReport`) | el reporte, posiblemente limpio | `sanitizer` |
| `prompt` | system prompt + reporte | los mensajes para el modelo | `spotlighting` |
| `post` | la salida validada (o `None`) + el reporte | la salida, posiblemente filtrada | `schema_validation`, `llm_judge` |

Decisiones que importan para medir:

- **La composicion no depende del orden en que se declaren.** `compose()` ordena por
  etapa y, dentro de la etapa, por un orden canonico fijo. `[llm_judge, sanitizer]` y
  `[sanitizer, llm_judge]` producen exactamente el mismo pipeline y la misma clave de
  celda en las trazas: la Fase 5 no puede contar dos veces la misma combinacion.
- **Solo una defensa de etapa `prompt`.** Dos constructores de mensajes no se pueden
  encadenar (cada uno arma la conversacion entera), asi que pedir dos es un error.
- **Las defensas no ocultan lo que hicieron.** Todo lo que eliminan, filtran o bloquean
  queda en el `DefenseContext` y de ahi pasa a la traza (`defense_notes`, `blocked`,
  `judge`). Bloquear no borra la salida del analista: la Fase 5 necesita saber que
  habria pasado si la corrida no se hubiera detenido.
- **El analista sigue sin saber si lo atacan.** Ninguna defensa recibe el manifiesto
  del ataque; solo ven lo mismo que veria el pipeline en produccion.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, ClassVar, Literal

from aitm.analyst.parsers import ParsedReport
from aitm.analyst.schema import ValidatedOutput

Stage = Literal["pre", "prompt", "post"]

#: Orden de las etapas en el pipeline.
STAGES: tuple[Stage, ...] = ("pre", "prompt", "post")

#: Orden canonico de las defensas dentro de su etapa. Es el de la arquitectura
#: (sanitizador -> spotlighting -> validacion -> juez) y el que aparece en las trazas.
CANONICAL_ORDER: tuple[str, ...] = ("sanitizer", "spotlighting", "schema_validation", "llm_judge")


@dataclass
class DefenseContext:
    """Estado de las defensas durante UN analisis. Se crea nuevo en cada `analyze()`.

    Es el canal por el que una defensa deja constancia de lo que hizo sin tocar el
    reporte ni la salida: las notas, el bloqueo y el veredicto del juez terminan en la
    traza tal cual.
    """

    notes: list[str] = field(default_factory=list)
    blocked: bool = False
    block_reasons: list[str] = field(default_factory=list)
    judge: dict[str, Any] | None = None
    #: Latencia de las defensas que llaman a un modelo (p. ej. `{"judge": 2410}`).
    latency_ms: dict[str, int] = field(default_factory=dict)

    def note(self, defense: str, message: str) -> None:
        self.notes.append(f"{defense}: {message}")

    def block(self, defense: str, reason: str) -> None:
        self.blocked = True
        self.block_reasons.append(f"{defense}: {reason}")
        self.note(defense, f"BLOQUEADO: {reason}")


PreHook = Callable[[ParsedReport, DefenseContext], ParsedReport]
MessageBuilder = Callable[[str, ParsedReport], list[dict[str, str]]]
PostHook = Callable[[ValidatedOutput | None, ParsedReport, DefenseContext], ValidatedOutput | None]


class Defense(ABC):
    """Contrato comun. Cada defensa concreta hereda de una de las tres subclases."""

    #: Nombre con el que se activa en `config.yaml` (`defenses.enabled`).
    name: ClassVar[str]
    stage: ClassVar[Stage]

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name} ({self.stage})>"


class PreDefense(Defense):
    """Actua sobre el reporte antes de construir el prompt."""

    stage: ClassVar[Stage] = "pre"

    @abstractmethod
    def apply(self, report: ParsedReport, context: DefenseContext) -> ParsedReport:
        raise NotImplementedError


class PromptDefense(Defense):
    """Decide como se presenta el reporte al modelo (mensajes y system prompt)."""

    stage: ClassVar[Stage] = "prompt"

    #: System prompt que reemplaza al base, o `None` para conservar el de la config.
    system_prompt_path: Path | None = None

    @abstractmethod
    def build_messages(self, system_prompt: str, report: ParsedReport) -> list[dict[str, str]]:
        raise NotImplementedError

    def template_fingerprint(self) -> str:
        """Texto que identifica la plantilla de usuario; su sha256 va a la traza."""
        return type(self).__name__


class PostDefense(Defense):
    """Actua sobre la salida ya validada. Recibe `None` si el analista fallo.

    Corre aunque la salida sea `None`: el juez evalua el documento, no la respuesta, y
    su veredicto sirve igual para medir deteccion.
    """

    stage: ClassVar[Stage] = "post"

    @abstractmethod
    def apply(
        self,
        validated: ValidatedOutput | None,
        report: ParsedReport,
        context: DefenseContext,
    ) -> ValidatedOutput | None:
        raise NotImplementedError


@dataclass(frozen=True)
class Composition:
    """Las defensas ya ordenadas y convertidas en los ganchos del `Analyst`."""

    names: tuple[str, ...]
    pre_hooks: tuple[PreHook, ...]
    post_hooks: tuple[PostHook, ...]
    prompt: PromptDefense | None = None

    def analyst_kwargs(self) -> dict[str, Any]:
        """Argumentos para construir un `Analyst` con esta composicion."""
        kwargs: dict[str, Any] = {
            "pre_hooks": list(self.pre_hooks),
            "post_hooks": list(self.post_hooks),
            "defenses": list(self.names),
        }
        if self.prompt is not None:
            kwargs["message_builder"] = self.prompt.build_messages
            kwargs["user_template_fingerprint"] = self.prompt.template_fingerprint()
            if self.prompt.system_prompt_path is not None:
                kwargs["system_prompt_path"] = self.prompt.system_prompt_path
        return kwargs


def _sort_key(defense: Defense) -> tuple[int, int, str]:
    stage = STAGES.index(defense.stage)
    try:
        canonical = CANONICAL_ORDER.index(defense.name)
    except ValueError:
        canonical = len(CANONICAL_ORDER)
    return stage, canonical, defense.name


def compose(defenses: list[Defense] | tuple[Defense, ...]) -> Composition:
    """Ordena las defensas por etapa y orden canonico, y arma los ganchos.

    Lanza `ValueError` si hay nombres repetidos o mas de una defensa de etapa `prompt`.
    """
    names = [defense.name for defense in defenses]
    if len(set(names)) != len(names):
        raise ValueError(f"defensas repetidas: {names}")
    ordered = sorted(defenses, key=_sort_key)

    prompts = [d for d in ordered if isinstance(d, PromptDefense)]
    if len(prompts) > 1:
        raise ValueError(
            "solo puede haber una defensa de etapa `prompt`; llegaron "
            f"{[d.name for d in prompts]}"
        )
    return Composition(
        names=tuple(d.name for d in ordered),
        pre_hooks=tuple(d.apply for d in ordered if isinstance(d, PreDefense)),
        post_hooks=tuple(d.apply for d in ordered if isinstance(d, PostDefense)),
        prompt=prompts[0] if prompts else None,
    )
