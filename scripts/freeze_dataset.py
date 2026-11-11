"""Congela el ground truth y escribe la composicion final del dataset.

Congelar es la ultima casilla de la Fase 1 y la precondicion de la Fase 2: a partir de
aqui las metricas de distintas corridas son comparables porque el ground truth no se
mueve. El script:

1. Exige que **todas** las etiquetas esten en `reviewed` (firmadas por una persona
   distinta de quien anoto). Una etiqueta en `draft` o `assisted` no entra.
2. Las pasa a `frozen`.
3. Escribe `data/labels/FROZEN.json` con el sha256 de cada etiqueta, de modo que
   cualquier cambio posterior sea detectable.
4. Escribe `results/tables/dataset_composition.md`: reportes por formato, indicadores
   por tipo y veredicto, distribucion de severidad y tecnicas ATT&CK. Esa tabla va al
   informe.

Uso:
    python scripts/freeze_dataset.py --check    # dice si se puede congelar, sin tocar
    python scripts/freeze_dataset.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aitm.config import load_config  # noqa: E402
from aitm.evaluation.labels import (  # noqa: E402
    ReportLabel,
    iter_labels,
    label_path,
    save_label,
)

FROZEN_FILE = "FROZEN.json"


def composition(labels: list[ReportLabel], formats: list[str]) -> str:
    """Tabla de composicion del dataset etiquetado, en markdown."""
    severities = Counter(label.severity for label in labels)
    verdicts = Counter(ioc.verdict for label in labels for ioc in label.iocs)
    types = Counter(ioc.type for label in labels for ioc in label.iocs)
    exclusions = Counter(
        excluded.reason for label in labels for excluded in label.excluded_iocs
    )
    vendors = Counter(label.source.vendor or "?" for label in labels)
    actors = sorted({label.threat_actor for label in labels if label.threat_actor})
    techniques = Counter(
        technique.technique_id for label in labels for technique in label.mitre_attack
    )

    def table(title: str, counter: Counter, header: str) -> str:
        rows = "".join(
            f"| {key} | {value} |\n" for key, value in counter.most_common()
        )
        return f"\n### {title}\n\n| {header} | n |\n|---|---|\n{rows}"

    total_iocs = sum(verdicts.values())
    lines = [
        "# Composicion del dataset etiquetado",
        "",
        f"Congelado: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        f"- **Reportes:** {len(labels)}, cada uno en {len(formats)} formatos "
        f"({', '.join(formats)}) = {len(labels) * len(formats)} archivos",
        f"- **Indicadores etiquetados:** {total_iocs}",
        f"- **Indicadores excluidos** (presentes en el texto pero fuera del caso): "
        f"{sum(exclusions.values())}",
        f"- **Tecnicas ATT&CK:** {sum(techniques.values())} menciones, "
        f"{len(techniques)} tecnicas distintas",
        f"- **Actores identificados:** {', '.join(actors) if actors else 'ninguno'}",
        "",
        table("Severidad por reporte", severities, "Severidad"),
        table("Veredicto de los indicadores", verdicts, "Veredicto"),
        table("Tipo de indicador", types, "Tipo"),
        table("Motivo de exclusion", exclusions, "Motivo"),
        table("Reportes por vendor", vendors, "Vendor"),
    ]

    mayoria = verdicts.most_common(1)[0] if verdicts else ("", 0)
    if total_iocs:
        lines += [
            "",
            "### Nota sobre el desbalance",
            "",
            f"El {mayoria[1] / total_iocs:.0%} de los indicadores son "
            f"`{mayoria[0]}`. Un modelo que respondiera siempre `{mayoria[0]}` "
            "acertaria esa fraccion sin analizar nada, asi que la exactitud cruda del "
            "veredicto no es una metrica informativa: hay que reportar **macro-F1**, "
            "que pondera igual las tres clases, y comparar contra esa linea base "
            "trivial.",
        ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Congela el ground truth")
    parser.add_argument(
        "--check", action="store_true", help="solo verifica, no modifica nada"
    )
    args = parser.parse_args()

    config = load_config()
    labels_dir = config.resolve(config.paths.labels)
    processed = config.resolve(config.paths.data_processed)

    dataset_path = processed / "dataset.json"
    if not dataset_path.is_file():
        print(f"[--] falta {dataset_path}")
        return 1
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    expected = {entry["report_id"] for entry in dataset["reports"]}

    labels = list(iter_labels(labels_dir))
    by_id = {label.report_id: label for label in labels}

    missing = sorted(expected - by_id.keys())
    if missing:
        print(f"[--] faltan etiquetas de {len(missing)} reportes: {missing[:3]}")
        return 1

    pending = sorted(
        f"{label.report_id} ({label.status})"
        for label in labels
        if label.status not in ("reviewed", "frozen")
    )
    if pending:
        print(f"[--] {len(pending)} etiquetas no las ha firmado un segundo revisor:")
        for item in pending:
            print(f"  - {item}")
        print(
            "\n     Congelar sin esa firma haria que el ground truth no sea\n"
            "     auditable. Revisa cada archivo, agregate en `reviewers` y pon\n"
            "     `status` en `reviewed`."
        )
        return 1

    already = sum(1 for label in labels if label.status == "frozen")
    if args.check:
        print(f"[ok] las {len(labels)} etiquetas estan firmadas y se pueden congelar")
        print(f"     ({already} ya estaban congeladas)")
        return 0

    digests = {}
    for label in labels:
        if label.status != "frozen":
            label.status = "frozen"
            save_label(label, label_path(labels_dir, label.report_id))
        path = label_path(labels_dir, label.report_id)
        digests[label.report_id] = hashlib.sha256(path.read_bytes()).hexdigest()

    frozen = {
        "frozen_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config_hash": config.config_hash,
        "corpus_commit": dataset["corpus"]["commit"],
        "n_reports": len(labels),
        "labels_sha256": dict(sorted(digests.items())),
    }
    (labels_dir / FROZEN_FILE).write_text(
        json.dumps(frozen, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    destination = config.resolve(config.paths.tables) / "dataset_composition.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        composition(labels, list(dataset["formats"])), encoding="utf-8"
    )

    print(f"[ok] {len(labels)} etiquetas congeladas")
    print(f"[ok] huellas en {labels_dir / FROZEN_FILE}")
    print(f"[ok] composicion en {destination}")
    print("\nFase 1 cerrada. La Fase 2 ya puede medir sobre un ground truth estable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
