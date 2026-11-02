"""Mide el acuerdo entre dos etiquetados independientes del mismo dataset.

El enunciado pide que cada reporte lo revise una segunda persona y que se mida el
acuerdo. Para que ese numero signifique algo, los dos etiquetados tienen que hacerse
**sin verse**: si una persona corrige el archivo de la otra, el acuerdo que salga es
una tautologia.

Flujo:

```bash
# El segundo etiquetado parte del BORRADOR del extractor, no de una copia de
# data/labels/: copiar las decisiones del primer anotador ancla al segundo y el
# acuerdo sale inflado.
python scripts/draft_labels.py --out data/labels_b --report-id X --report-id Y ...
# la segunda persona decide en data/labels_b/ sin abrir data/labels/ de esos reportes
python scripts/agreement.py --other data/labels_b   # compara solo los compartidos
```

`--sample N` toma los N primeros en orden alfabetico, que en este dataset son casi
todos del mismo vendor; para una muestra representativa conviene elegir los reportes
con `--report-id` al generar los borradores.

Que se mide (la logica esta en `src/aitm/evaluation/agreement.py`):

- **Acuerdo de conjunto de IoCs** (Jaccard): si ambas personas senalaron los mismos
  indicadores como "del caso". Captura las discrepancias por omision, que el acuerdo
  de veredictos no ve porque solo mira los indicadores comunes.
- **Acuerdo de veredicto**: porcentaje y **kappa de Cohen**, que descuenta el acuerdo
  que se habria dado por azar. Importa aqui porque la gran mayoria de los indicadores
  del dataset son `malicious`: un acuerdo del 95 % puede ser puro desbalance.
- **Acuerdo de severidad** por reporte.

La tabla queda en `results/tables/agreement.md` para el informe, y las discrepancias
se listan en consola para resolverlas una por una.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aitm.config import load_config  # noqa: E402
from aitm.evaluation.agreement import cohen_kappa, compare_labels  # noqa: E402
from aitm.evaluation.labels import iter_labels  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Acuerdo entre dos etiquetados")
    parser.add_argument(
        "--other", required=True, type=Path, help="carpeta del segundo etiquetado"
    )
    parser.add_argument(
        "--sample",
        type=int,
        help="comparar solo los primeros N reportes en orden alfabetico",
    )
    args = parser.parse_args()

    config = load_config()
    labels_dir = config.resolve(config.paths.labels)
    other_dir = args.other if args.other.is_absolute() else config.resolve(args.other)
    if not other_dir.is_dir():
        print(f"[--] no existe {other_dir}")
        return 1
    if other_dir.resolve() == labels_dir.resolve():
        print("[--] las dos carpetas son la misma: el acuerdo seria trivialmente 100 %")
        return 1

    first = {label.report_id: label for label in iter_labels(labels_dir)}
    second = {label.report_id: label for label in iter_labels(other_dir)}
    shared = sorted(first.keys() & second.keys())
    if args.sample:
        shared = shared[: args.sample]
    if not shared:
        print("[--] los dos etiquetados no comparten ningun reporte")
        return 1

    only_a = sorted(first.keys() - second.keys())
    only_b = sorted(second.keys() - first.keys())
    if only_a or only_b:
        print(f"[!!] reportes no comparados: solo en A {only_a}, solo en B {only_b}\n")

    results = []
    all_pairs: list[tuple[str, str]] = []
    for report_id in shared:
        result = compare_labels(first[report_id], second[report_id])
        results.append(result)
        all_pairs.extend(result.pairs)
        if result.discrepancies:
            print(f"{report_id} ({len(result.discrepancies)} discrepancias)")
            for line in result.discrepancies:
                print(f"  {line}")
            print()

    kappa = cohen_kappa(all_pairs)
    verdict_match = (
        sum(1 for a, b in all_pairs if a == b) / len(all_pairs) if all_pairs else 0.0
    )
    mean_jaccard = sum(result.jaccard for result in results) / len(results)
    severity_matches = sum(1 for result in results if result.severity_match)

    header = (
        "| Reporte | IoCs A | IoCs B | Jaccard | Comunes | Veredicto | Severidad |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    body = ""
    for result in results:
        verdict_text = (
            f"{result.verdict_match:.0%}" if result.verdict_match is not None else "-"
        )
        body += (
            f"| {result.report_id} | {result.iocs_a} | {result.iocs_b} | "
            f"{result.jaccard:.2f} | {result.common} | {verdict_text} | "
            f"{'si' if result.severity_match else 'NO'} |\n"
        )

    kappa_text = f"{kappa:.3f}" if kappa is not None else "no definido"
    summary = (
        f"\n**Resumen** ({len(shared)} reportes comparados)\n\n"
        f"- Acuerdo de conjunto de IoCs (Jaccard medio): **{mean_jaccard:.2f}**\n"
        f"- Acuerdo de veredicto sobre los {len(all_pairs)} indicadores comunes: "
        f"**{verdict_match:.1%}**\n"
        f"- Kappa de Cohen del veredicto: **{kappa_text}**\n"
        f"- Acuerdo de severidad: **{severity_matches}/{len(shared)}** reportes\n"
    )

    print(header + body + summary)

    destination = config.resolve(config.paths.tables) / "agreement.md"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        "# Acuerdo entre revisores\n\n"
        f"Etiquetado A: `{labels_dir.name}`  \nEtiquetado B: `{other_dir.name}`\n\n"
        + header
        + body
        + summary
        + "\n> Kappa de Cohen descuenta el acuerdo por azar. En un dataset donde la\n"
        "> mayoria de los indicadores son `malicious`, el porcentaje crudo se infla y\n"
        "> kappa es la cifra que hay que reportar.\n",
        encoding="utf-8",
    )
    print(f"[ok] tabla en {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
