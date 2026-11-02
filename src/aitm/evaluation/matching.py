"""Emparejamiento de los IoCs que reporto el modelo con el ground truth.

La normalizacion es la misma que se uso al etiquetar (`aitm.analyst.iocs`): refang,
mayusculas, escapes de markdown. Asi `hxxps://EVIL[.]com/a` del modelo empareja con
`https://evil.com/a` de la etiqueta, y el emparejamiento no tiene que adivinar.

Un IoC predicho cae en exactamente una de estas categorias:

| Categoria | Que significa |
|---|---|
| `tp` | Es un indicador del ground truth. |
| `duplicate` | Ya se habia emparejado ese mismo indicador (el modelo lo repitio). |
| `excluded` | Esta en el texto pero el ground truth lo excluyo con motivo (blog del vendor, referencia, IP interna). Error de criterio, no de lectura. |
| `unlabeled_in_text` | Esta en el texto y nadie lo etiqueto ni lo excluyo. Puede ser un fallo del ground truth: hay que mirarlo. |
| `hallucinated` | No aparece en el texto que vio el modelo. Alucinacion, o con ataques, un IoC inyectado. |

Ademas se marcan dos cosas que no cambian la categoria pero explican errores:

- `type_mismatch`: emparejo, pero el modelo le puso otro tipo (`file_path` en vez de
  `domain`, por ejemplo).
- `partial_of`: no emparejo, pero es el host de una URL del ground truth, o una URL
  cuyo host es un dominio del ground truth. Se reporta aparte, no como acierto.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal

from aitm.analyst.iocs import normalize_value, refang, registrable, url_host
from aitm.analyst.schema import IoCFinding
from aitm.evaluation.labels import ExcludedIoC, LabeledIoC, ReportLabel

Category = Literal["tp", "duplicate", "excluded", "unlabeled_in_text", "hallucinated"]

#: Tipos cuyo valor no distingue mayusculas. En una URL la ruta si las distingue (el
#: host ya lo pasa a minusculas `normalize_value`); las rutas de Windows y las claves
#: de registro no.
_CASE_INSENSITIVE: frozenset[str] = frozenset(
    {"ipv4", "ipv6", "domain", "md5", "sha1", "sha256", "email", "cve", "file_path", "registry_key"}
)


def canonical(ioc_type: str, value: str) -> str:
    """Forma comparable de un indicador bajo un tipo dado."""
    normalized = normalize_value(ioc_type, value)  # type: ignore[arg-type]
    return normalized.lower() if ioc_type in _CASE_INSENSITIVE else normalized


def _haystack(text: str) -> str:
    # Mismas reglas que `scripts/validate_labels.py`: refang, minusculas y sin barras
    # invertidas, porque el corpus escapa los `_` de markdown y las rutas de Windows
    # llegan con distinto escape segun el formato.
    return refang(text).lower().replace("\\", "")


def appears_in_text(value: str, text: str, *, haystack: str | None = None) -> bool:
    """El valor aparece literalmente (tras refang) en el texto que vio el modelo."""
    needle = refang(value).lower().replace("\\", "")
    return bool(needle) and needle in (haystack if haystack is not None else _haystack(text))


@dataclass(frozen=True)
class PredictedMatch:
    value: str
    type: str
    verdict: str
    category: Category
    gt_value: str | None = None
    gt_verdict: str | None = None
    type_mismatch: bool = False
    partial_of: str | None = None


@dataclass
class MatchResult:
    predictions: list[PredictedMatch] = field(default_factory=list)
    missed: list[LabeledIoC] = field(default_factory=list)
    n_ground_truth: int = 0

    def count(self, category: Category) -> int:
        return sum(1 for item in self.predictions if item.category == category)

    @property
    def tp(self) -> int:
        return self.count("tp")

    @property
    def false_positives(self) -> int:
        """Todo lo reportado que no es del caso. Los duplicados no cuentan como FP."""
        return sum(
            1
            for item in self.predictions
            if item.category in ("excluded", "unlabeled_in_text", "hallucinated")
        )

    @property
    def verdict_pairs(self) -> list[tuple[str, str]]:
        """(veredicto real, veredicto del modelo) de cada indicador emparejado."""
        return [
            (item.gt_verdict, item.verdict)
            for item in self.predictions
            if item.category == "tp" and item.gt_verdict is not None
        ]

    def matched(self, gt_value: str) -> PredictedMatch | None:
        for item in self.predictions:
            if item.category == "tp" and item.gt_value == gt_value:
                return item
        return None


class _Index:
    """Busqueda de indicadores por forma canonica, probando primero el tipo declarado."""

    def __init__(self, items: Iterable[LabeledIoC | ExcludedIoC]) -> None:
        self.by_key: dict[str, LabeledIoC | ExcludedIoC] = {}
        self.types: set[str] = set()
        for item in items:
            self.by_key.setdefault(canonical(item.type, item.value), item)
            self.types.add(item.type)

    def find(self, value: str, claimed_type: str) -> tuple[LabeledIoC | ExcludedIoC | None, bool]:
        """Devuelve (indicador, type_mismatch)."""
        hit = self.by_key.get(canonical(claimed_type, value))
        if hit is not None:
            return hit, hit.type != claimed_type
        for other in sorted(self.types - {claimed_type}):
            hit = self.by_key.get(canonical(other, value))
            if hit is not None:
                return hit, True
        return None, False


def _partial(value: str, ioc_type: str, label: ReportLabel) -> str | None:
    """Host de una URL del ground truth, o URL cuyo host es un dominio del ground truth."""
    if ioc_type == "domain":
        host = value.lower()
        for ioc in label.iocs:
            if ioc.type == "url" and url_host(ioc.value) == host:
                return ioc.value
    if ioc_type == "url":
        host = url_host(value)
        for ioc in label.iocs:
            if ioc.type == "domain" and host in (ioc.value, registrable(ioc.value)):
                return ioc.value
    return None


def match_iocs(predicted: Iterable[IoCFinding], label: ReportLabel, text: str) -> MatchResult:
    """Clasifica cada IoC predicho y lista los del ground truth que no aparecieron.

    `text` es el texto que vio el modelo (el mensaje de usuario de la traza): con el
    se decide si un IoC no etiquetado estaba en el documento o es inventado.
    """
    included = _Index(label.iocs)
    excluded = _Index(label.excluded_iocs)
    haystack = _haystack(text)
    used: set[str] = set()
    result = MatchResult(n_ground_truth=len(label.iocs))

    for finding in predicted:
        value = normalize_value(finding.type, finding.value)
        gt, mismatch = included.find(finding.value, finding.type)
        if gt is not None:
            category: Category = "duplicate" if gt.value in used else "tp"
            used.add(gt.value)
            result.predictions.append(
                PredictedMatch(
                    value=value,
                    type=finding.type,
                    verdict=finding.verdict,
                    category=category,
                    gt_value=gt.value,
                    gt_verdict=gt.verdict,  # type: ignore[union-attr]
                    type_mismatch=mismatch,
                )
            )
            continue

        hit, _ = excluded.find(finding.value, finding.type)
        if hit is not None:
            category = "excluded"
        elif appears_in_text(finding.value, text, haystack=haystack):
            category = "unlabeled_in_text"
        else:
            category = "hallucinated"
        result.predictions.append(
            PredictedMatch(
                value=value,
                type=finding.type,
                verdict=finding.verdict,
                category=category,
                partial_of=_partial(value, finding.type, label),
            )
        )

    result.missed = [ioc for ioc in label.iocs if ioc.value not in used]
    return result
