"""Selección determinista del objetivo de cada ataque, desde el ground truth congelado.

El objetivo (qué IoC voltear, qué técnica quitar, a qué severidad bajar) **no** se elige
mirando lo que responde el modelo: sería acomodar el ataque a su resultado. Se fija por
una regla sobre las etiquetas, antes de atacar, y queda escrito en `data/poisoned/
targets.json`. Así el experimento es reproducible y auditable.

Reglas:

- `flip_to_benign`, `omit_ioc`: el primer IoC `malicious` de tipo `domain`, `url` o
  `ipv4` en el orden del ground truth. Son los tipos que el modelo reproduce de forma
  estable y que un atacante querría esconder.
- `downgrade_severity`: bajar dos niveles desde la severidad del ground truth (acotado
  al mínimo). El éxito se mide contra lo que diga el modelo en limpio, no contra esto.
- `drop_technique`: la primera técnica del ground truth.
"""

from __future__ import annotations

from aitm.analyst.schema import SEVERITY_ORDER
from aitm.attacks.base import AttackGoal, AttackTarget
from aitm.evaluation.labels import ReportLabel

_IOC_TYPES = ("domain", "url", "ipv4")


def _first_ioc(label: ReportLabel) -> AttackTarget | None:
    for ioc_type in _IOC_TYPES:
        for ioc in label.iocs:
            if ioc.type == ioc_type and ioc.verdict == "malicious":
                return AttackTarget(ioc_value=ioc.value, ioc_type=ioc.type)
    return None


def _lower_severity(severity: str, levels: int = 2) -> str:
    index = SEVERITY_ORDER.index(severity)  # type: ignore[arg-type]
    return SEVERITY_ORDER[max(0, index - levels)]


def target_for(goal: AttackGoal, label: ReportLabel) -> AttackTarget | None:
    """Objetivo para (goal, reporte), o None si el reporte no da material para ese goal."""
    if goal in ("flip_to_benign", "omit_ioc"):
        return _first_ioc(label)
    if goal == "downgrade_severity":
        lowered = _lower_severity(label.severity)
        if lowered == label.severity:
            return None
        return AttackTarget(severity_to=lowered)
    if goal == "drop_technique":
        if not label.mitre_attack:
            return None
        return AttackTarget(technique_id=label.mitre_attack[0].technique_id)
    return None


def targets_for_report(label: ReportLabel, goals) -> dict[str, AttackTarget]:
    """Objetivos de un reporte, uno por goal que aplique."""
    result: dict[str, AttackTarget] = {}
    for goal in goals:
        target = target_for(goal, label)
        if target is not None:
            result[goal] = target
    return result
