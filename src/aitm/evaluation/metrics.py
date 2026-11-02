"""Metricas de exactitud del analista contra el ground truth (docs/ARCHITECTURE.md, s. 4).

Todo aqui es puro y determinista: recibe trazas y etiquetas y devuelve numeros, sin
llamar al LLM. Si cambia una definicion, se recalcula sobre las trazas guardadas.

Definiciones (las mismas que van al informe):

- **Precision de IoCs** = TP / (TP + FP), donde FP es todo lo reportado que no es un
  indicador del caso: excluidos, no etiquetados y alucinados. Los duplicados no
  cuentan. **Recall** = TP / indicadores del ground truth. Se agregan en *micro*
  (sumando TP y FP de todos los reportes), que es lo que pesa cada indicador igual.
- **Macro-F1 del veredicto**, sobre los indicadores emparejados: mide si el modelo
  sabe *clasificar* lo que si encontro. Se reporta junto con el F1 por clase porque
  con 12 `benign` y 1 `suspicious` en el dataset una sola decision mueve la cifra.
- **Severidad**: acierto exacto y a +-1 nivel.
- **ATT&CK**: recall estricto (mismo id) y por tecnica padre (`T1059` del ground
  truth queda cubierta por un `T1059.001` del modelo, y al reves).
- **Corridas fallidas** (JSON invalido, cortado, Ollama caido): cuentan como un
  analisis vacio. No se descartan, porque descartarlas premiaria al modelo que falla
  justo en los reportes dificiles. La tasa de fallo se reporta aparte.

Dos lineas base sin LLM dan contexto a esos numeros:

- **Siempre `malicious`**: el macro-F1 que saca un clasificador que no analiza nada.
- **Extractor regex** (`aitm.analyst.iocs`): la precision y el recall de IoCs que
  da una expresion regular. Si el LLM no la supera, no aporta en esa parte de la tarea.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Iterable

from aitm.analyst.iocs import extract
from aitm.analyst.schema import IoCFinding, severity_rank
from aitm.evaluation.labels import ReportLabel, Verdict
from aitm.evaluation.matching import match_iocs
from aitm.evaluation.traces import RunRecord

VERDICTS: tuple[Verdict, ...] = ("malicious", "suspicious", "benign")


def safe_div(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def f1_per_class(
    pairs: list[tuple[str, str]], labels: Iterable[str] = VERDICTS
) -> dict[str, dict[str, float | int | None]]:
    """Precision, recall, F1 y soporte de cada clase. `pairs` = (real, predicho)."""
    table: dict[str, dict[str, float | int | None]] = {}
    for label in labels:
        tp = sum(1 for truth, pred in pairs if truth == label and pred == label)
        predicted = sum(1 for _, pred in pairs if pred == label)
        support = sum(1 for truth, _ in pairs if truth == label)
        precision = safe_div(tp, predicted)
        recall = safe_div(tp, support)
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else (0.0 if (predicted or support) else None)
        )
        table[label] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
            "predicted": predicted,
        }
    return table


def macro_f1(pairs: list[tuple[str, str]], labels: Iterable[str] = VERDICTS) -> float | None:
    """Promedio del F1 de las clases que aparecen (en la verdad o en la prediccion).

    Una clase que no aparece en ningun lado no tiene F1 definido y no entra al
    promedio: si entrara como 0, el macro-F1 de un reporte sin `benign` castigaria
    al modelo por algo que no podia hacer.
    """
    scores = [row["f1"] for row in f1_per_class(pairs, labels).values() if row["f1"] is not None]
    return sum(scores) / len(scores) if scores else None


def _parent(technique_id: str) -> str:
    return technique_id.split(".")[0]


@dataclass
class TechniqueScore:
    n_ground_truth: int
    n_predicted: int
    strict_hits: int
    parent_hits: int
    parent_precision_hits: int

    @property
    def recall_strict(self) -> float | None:
        return safe_div(self.strict_hits, self.n_ground_truth)

    @property
    def recall_parent(self) -> float | None:
        return safe_div(self.parent_hits, self.n_ground_truth)

    @property
    def precision_parent(self) -> float | None:
        return safe_div(self.parent_precision_hits, self.n_predicted)


def score_techniques(predicted: Iterable[str], truth: Iterable[str]) -> TechniqueScore:
    predicted_set = {item.upper() for item in predicted}
    truth_set = {item.upper() for item in truth}
    predicted_parents = {_parent(item) for item in predicted_set}
    truth_parents = {_parent(item) for item in truth_set}
    return TechniqueScore(
        n_ground_truth=len(truth_set),
        n_predicted=len(predicted_set),
        strict_hits=len(predicted_set & truth_set),
        parent_hits=sum(1 for item in truth_set if _parent(item) in predicted_parents),
        parent_precision_hits=sum(
            1 for item in predicted_set if _parent(item) in truth_parents
        ),
    )


def model_text(record: RunRecord) -> str:
    """El texto que vio el modelo: el ultimo mensaje de usuario de la traza original."""
    for message in reversed(record.messages):
        if message.get("role") == "user":
            return message.get("content", "")
    return ""


@dataclass
class RunScore:
    """Puntaje de una corrida (un reporte, un formato, un modelo)."""

    run_id: str
    model: str
    report_id: str
    source_format: str
    status: str
    n_ground_truth: int
    n_predicted: int
    tp: int
    fp: int
    fp_excluded: int
    fp_unlabeled: int
    fp_hallucinated: int
    duplicates: int
    partial: int
    type_mismatch: int
    precision: float | None
    recall: float | None
    verdict_pairs: list[tuple[str, str]] = field(repr=False)
    missed: list[str] = field(repr=False)
    severity_truth: str
    severity_pred: str | None
    severity_exact: bool
    severity_within_one: bool
    techniques: TechniqueScore
    latency_ms: int
    completion_tokens: int
    validation_warnings: int
    context_warning: bool

    def row(self) -> dict[str, object]:
        """Fila plana para CSV."""
        data = asdict(self)
        data.pop("verdict_pairs")
        data["missed"] = " ".join(self.missed)
        techniques = data.pop("techniques")
        data.update(
            {
                "tech_n_ground_truth": techniques["n_ground_truth"],
                "tech_n_predicted": techniques["n_predicted"],
                "tech_recall_strict": self.techniques.recall_strict,
                "tech_recall_parent": self.techniques.recall_parent,
                "tech_precision_parent": self.techniques.precision_parent,
                "verdict_macro_f1": macro_f1(self.verdict_pairs),
            }
        )
        return data


def score_run(record: RunRecord, label: ReportLabel) -> RunScore:
    if record.report_id != label.report_id:
        raise ValueError(f"la traza es de {record.report_id} y la etiqueta de {label.report_id}")

    output = record.output
    findings: list[IoCFinding] = list(output.iocs) if output else []
    match = match_iocs(findings, label, model_text(record))
    severity_pred = output.severity if output else None
    techniques = score_techniques(
        [t.technique_id for t in output.mitre_attack] if output else [],
        [t.technique_id for t in label.mitre_attack],
    )
    return RunScore(
        run_id=record.run_id,
        model=record.model,
        report_id=record.report_id,
        source_format=record.source_format,
        status=record.status,
        n_ground_truth=match.n_ground_truth,
        n_predicted=len(findings),
        tp=match.tp,
        fp=match.false_positives,
        fp_excluded=match.count("excluded"),
        fp_unlabeled=match.count("unlabeled_in_text"),
        fp_hallucinated=match.count("hallucinated"),
        duplicates=match.count("duplicate"),
        partial=sum(1 for item in match.predictions if item.partial_of),
        type_mismatch=sum(1 for item in match.predictions if item.type_mismatch),
        precision=safe_div(match.tp, match.tp + match.false_positives),
        recall=safe_div(match.tp, match.n_ground_truth),
        verdict_pairs=match.verdict_pairs,
        missed=[ioc.value for ioc in match.missed],
        severity_truth=label.severity,
        severity_pred=severity_pred,
        severity_exact=severity_pred == label.severity,
        severity_within_one=(
            severity_pred is not None
            and abs(severity_rank(severity_pred) - severity_rank(label.severity)) <= 1
        ),
        techniques=techniques,
        latency_ms=record.latency_ms.get("analyst", 0),
        completion_tokens=record.tokens.get("completion", 0),
        validation_warnings=len(record.validation_warnings),
        context_warning=record.context_warning is not None,
    )


def percentile(values: list[float], q: float) -> float | None:
    """Percentil con interpolacion lineal (el mismo criterio que numpy por defecto)."""
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    low, high = math.floor(position), math.ceil(position)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (position - low)


def aggregate(scores: list[RunScore]) -> dict[str, object]:
    """Resumen de un grupo de corridas (p. ej. un modelo, o un modelo y un formato)."""
    tp = sum(s.tp for s in scores)
    fp = sum(s.fp for s in scores)
    n_truth = sum(s.n_ground_truth for s in scores)
    pairs = [pair for s in scores for pair in s.verdict_pairs]
    per_class = f1_per_class(pairs)
    tech_truth = sum(s.techniques.n_ground_truth for s in scores)
    tech_pred = sum(s.techniques.n_predicted for s in scores)
    latencies = [s.latency_ms / 1000 for s in scores if s.status != "error"]
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, n_truth)
    return {
        "runs": len(scores),
        "failed": sum(1 for s in scores if s.status != "ok"),
        "ioc_precision": precision,
        "ioc_recall": recall,
        "ioc_f1": (
            2 * precision * recall / (precision + recall)
            if precision and recall
            else None
        ),
        "fp_excluded": sum(s.fp_excluded for s in scores),
        "fp_unlabeled": sum(s.fp_unlabeled for s in scores),
        "fp_hallucinated": sum(s.fp_hallucinated for s in scores),
        "type_mismatch": sum(s.type_mismatch for s in scores),
        "verdict_pairs": len(pairs),
        "verdict_macro_f1": macro_f1(pairs),
        "benign_recall": per_class["benign"]["recall"],
        "severity_exact": safe_div(sum(s.severity_exact for s in scores), len(scores)),
        "severity_within_one": safe_div(sum(s.severity_within_one for s in scores), len(scores)),
        "tech_recall_strict": safe_div(sum(s.techniques.strict_hits for s in scores), tech_truth),
        "tech_recall_parent": safe_div(sum(s.techniques.parent_hits for s in scores), tech_truth),
        "tech_precision_parent": safe_div(
            sum(s.techniques.parent_precision_hits for s in scores), tech_pred
        ),
        "latency_p50_s": percentile(latencies, 0.5),
        "latency_p95_s": percentile(latencies, 0.95),
        "completion_tokens_mean": safe_div(sum(s.completion_tokens for s in scores), len(scores)),
    }


# -- lineas base sin LLM ---------------------------------------------------


def always_malicious_macro_f1(labels: Iterable[ReportLabel]) -> float | None:
    """Macro-F1 de responder `malicious` a todo, sobre los veredictos del ground truth."""
    pairs = [(ioc.verdict, "malicious") for label in labels for ioc in label.iocs]
    return macro_f1(pairs)


def regex_baseline(label: ReportLabel, text: str) -> tuple[int, int, int]:
    """(TP, FP, n_ground_truth) del extractor regex, sin la lista de ruido.

    Usa el mismo `match_iocs` que el modelo para que la comparacion sea justa. El
    extractor no da veredicto, asi que solo compite en la parte de extraccion.
    """
    findings = [
        IoCFinding(value=ioc.value, type=ioc.type, verdict="malicious", confidence=1.0)
        for ioc in extract(text, include_noise=False)
        if not ioc.is_internal_ip
    ]
    match = match_iocs(findings, label, text)
    return match.tp, match.false_positives, match.n_ground_truth
