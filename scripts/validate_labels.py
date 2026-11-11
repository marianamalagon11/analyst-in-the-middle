"""Valida el ground truth etiquetado a mano y reporta el estado de la Fase 1.

El equipo edita los JSON de `data/labels/` a mano, asi que hace falta un chequeo que
corra antes de cada commit. Comprueba cuatro cosas:

1. **Esquema.** Cada archivo valida contra `ReportLabel` (tipos cerrados, ids de
   tecnica bien formados, sin IoCs repetidos, revisor distinto del anotador).
2. **Cobertura.** Hay una etiqueta por cada reporte de `data/processed/dataset.json`,
   y ninguna etiqueta huerfana.
3. **Consistencia con el texto.** Cada indicador etiquetado aparece de verdad en el
   reporte. Es el chequeo que atrapa los errores de tipeo al copiar un hash a mano,
   que de otro modo se convierten en un falso negativo del modelo en la Fase 2.
4. **Progreso de la revision.** Cuantos reportes van en `draft`, `reviewed` y
   `frozen`, y quien ha anotado y revisado cada cual.

Salida distinta de cero si algo esta mal, para poder usarlo en un hook o en CI.

Uso:
    python scripts/validate_labels.py
    python scripts/validate_labels.py --require-frozen   # antes de correr la Fase 2
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pydantic import ValidationError  # noqa: E402

from aitm.analyst.iocs import refang  # noqa: E402
from aitm.config import load_config  # noqa: E402
from aitm.evaluation.labels import ReportLabel, label_files, load_label  # noqa: E402


def check_in_text(label: ReportLabel, text: str) -> list[str]:
    """Indicadores etiquetados que no aparecen en el reporte."""
    haystack = refang(text).lower()
    missing: list[str] = []
    for ioc in label.iocs:
        needle = ioc.value.lower()
        if needle in haystack:
            continue
        # Las rutas y claves de registro se escriben con barras invertidas que el
        # texto puede traer escapadas; se compara tambien sin ellas.
        if needle.replace("\\", "") in haystack.replace("\\", ""):
            continue
        missing.append(ioc.value)
    return missing


def main() -> int:
    parser = argparse.ArgumentParser(description="Valida el ground truth")
    parser.add_argument(
        "--require-frozen",
        action="store_true",
        help="exige que todas las etiquetas esten congeladas",
    )
    args = parser.parse_args()

    config = load_config()
    labels_dir = config.resolve(config.paths.labels)
    processed = config.resolve(config.paths.data_processed)
    data_raw = config.resolve(config.paths.data_raw)

    dataset_path = processed / "dataset.json"
    if not dataset_path.is_file():
        print(f"[--] falta {dataset_path}. Corre: python scripts/build_dataset.py")
        return 1
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    expected = {entry["report_id"] for entry in dataset["reports"]}

    problems: list[str] = []
    labels: dict[str, ReportLabel] = {}

    for path in label_files(labels_dir):
        try:
            label = load_label(path)
        except ValidationError as error:
            problems.append(f"{path.name}: esquema invalido\n{error}")
            continue
        except json.JSONDecodeError as error:
            problems.append(f"{path.name}: JSON mal formado ({error})")
            continue
        if label.report_id != path.stem:
            problems.append(
                f"{path.name}: report_id={label.report_id!r} no coincide con el nombre"
            )
        labels[label.report_id] = label

    missing_labels = sorted(expected - labels.keys())
    orphans = sorted(labels.keys() - expected)
    for report_id in missing_labels:
        problems.append(f"falta la etiqueta de {report_id}")
    for report_id in orphans:
        problems.append(f"{report_id}.json no corresponde a ningun reporte del dataset")

    for report_id, label in labels.items():
        source = data_raw / "annoctr" / label.source.file
        if not source.is_file():
            problems.append(f"{report_id}: no se encontro el texto fuente en {source}")
            continue
        absent = check_in_text(label, source.read_text(encoding="utf-8", errors="replace"))
        if absent:
            problems.append(
                f"{report_id}: {len(absent)} indicadores etiquetados no aparecen en el "
                f"texto: {absent[:5]}"
            )

    statuses = Counter(label.status for label in labels.values())
    total_iocs = sum(len(label.iocs) for label in labels.values())
    total_techniques = sum(len(label.mitre_attack) for label in labels.values())
    verdicts = Counter(ioc.verdict for label in labels.values() for ioc in label.iocs)
    # La severidad de un borrador es un valor por defecto, no un dato: contarla con
    # las revisadas daria una distribucion falsa en el informe.
    severities = Counter(
        label.severity for label in labels.values() if label.status != "draft"
    )

    print(f"etiquetas: {len(labels)} de {len(expected)} reportes esperados")
    print(f"estado:    {dict(statuses)}")
    print(f"IoCs:      {total_iocs} ({dict(verdicts)})")
    print(f"ATT&CK:    {total_techniques} tecnicas")
    if severities:
        print(f"severidad (etiquetas ya decididas): {dict(severities)}")

    drafts = sorted(
        report_id for report_id, label in labels.items() if label.status == "draft"
    )
    if drafts:
        print(f"\nsin etiquetar, solo salida del extractor ({len(drafts)}):")
        for report_id in drafts:
            print(f"  - {report_id}")

    unsigned = sorted(
        report_id for report_id, label in labels.items() if label.status == "assisted"
    )
    if unsigned:
        print(f"\netiquetadas pero SIN firma de un segundo revisor ({len(unsigned)}):")
        for report_id in unsigned:
            print(f"  - {report_id}  [{', '.join(labels[report_id].annotators)}]")
        print(
            "  Para firmar una: revisa el archivo, agregate en `reviewers` y pon\n"
            "  `status` en `reviewed`. El esquema no permite que el revisor sea la\n"
            "  misma persona que el anotador."
        )

    signed = {
        report_id: (label.annotators, label.reviewers)
        for report_id, label in labels.items()
        if label.status in ("reviewed", "frozen")
    }
    if signed:
        print("\nfirmadas:")
        for report_id, (annotators, reviewers) in sorted(signed.items()):
            print(f"  - {report_id}: anoto {annotators}, reviso {reviewers}")

    if problems:
        print(f"\n[--] {len(problems)} problemas:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    if args.require_frozen:
        not_frozen = sorted(
            report_id for report_id, label in labels.items() if label.status != "frozen"
        )
        if not_frozen:
            print(
                f"\n[--] {len(not_frozen)} etiquetas no estan congeladas: "
                f"{not_frozen[:5]}"
            )
            return 1

    print("\n[ok] todo valido")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
