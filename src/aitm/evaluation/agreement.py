"""Acuerdo entre dos etiquetados independientes del mismo reporte.

Vive aqui y no en el script porque es una metrica, se prueba como tal, y la Fase 5
necesitara comparar conjuntos de indicadores con la misma logica.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aitm.evaluation.labels import ReportLabel, Verdict

VERDICTS: tuple[Verdict, ...] = ("malicious", "suspicious", "benign")


def jaccard(left: set[str], right: set[str]) -> float:
    """Interseccion sobre union. Dos conjuntos vacios se consideran de acuerdo."""
    union = left | right
    return len(left & right) / len(union) if union else 1.0


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    """Kappa de Cohen para dos anotadores sobre categorias nominales.

    Devuelve `None` cuando no esta definido: sin datos, o cuando el acuerdo esperado
    por azar es 1 porque ambos anotadores usaron una sola categoria. Es justo el caso
    que puede pasar en este dataset, donde casi todos los indicadores son `malicious`,
    y por eso hay que distinguirlo de "kappa = 0".
    """
    total = len(pairs)
    if total == 0:
        return None

    observed = sum(1 for first, second in pairs if first == second) / total

    expected = 0.0
    for verdict in VERDICTS:
        first_rate = sum(1 for first, _ in pairs if first == verdict) / total
        second_rate = sum(1 for _, second in pairs if second == verdict) / total
        expected += first_rate * second_rate

    if expected >= 1.0:
        return None
    return (observed - expected) / (1 - expected)


@dataclass
class ReportAgreement:
    """Acuerdo sobre un reporte, con las discrepancias ya redactadas."""

    report_id: str
    iocs_a: int
    iocs_b: int
    common: int
    jaccard: float
    verdict_match: float | None
    severity_match: bool
    pairs: list[tuple[str, str]] = field(default_factory=list)
    discrepancies: list[str] = field(default_factory=list)


def compare_labels(first: ReportLabel, second: ReportLabel) -> ReportAgreement:
    """Compara dos etiquetas del mismo reporte.

    Las discrepancias se separan en tres clases porque se resuelven distinto: una
    omision (un indicador que solo vio una persona) suele ser descuido, un veredicto
    distinto es un desacuerdo de criterio, y la severidad es un juicio global.
    """
    if first.report_id != second.report_id:
        raise ValueError(
            f"no son el mismo reporte: {first.report_id} vs {second.report_id}"
        )

    left = {ioc.value: ioc.verdict for ioc in first.iocs}
    right = {ioc.value: ioc.verdict for ioc in second.iocs}
    common = sorted(left.keys() & right.keys())
    pairs = [(left[value], right[value]) for value in common]

    discrepancies: list[str] = []
    for value in sorted(left.keys() - right.keys()):
        discrepancies.append(f"solo en A: {value}  ({left[value]})")
    for value in sorted(right.keys() - left.keys()):
        discrepancies.append(f"solo en B: {value}  ({right[value]})")
    for value in common:
        if left[value] != right[value]:
            discrepancies.append(
                f"veredicto: {value}  A={left[value]}  B={right[value]}"
            )
    if first.severity != second.severity:
        discrepancies.append(f"severidad: A={first.severity}  B={second.severity}")

    matching = sum(1 for a, b in pairs if a == b)
    return ReportAgreement(
        report_id=first.report_id,
        iocs_a=len(left),
        iocs_b=len(right),
        common=len(common),
        jaccard=jaccard(set(left), set(right)),
        verdict_match=matching / len(common) if common else None,
        severity_match=first.severity == second.severity,
        pairs=pairs,
        discrepancies=discrepancies,
    )
