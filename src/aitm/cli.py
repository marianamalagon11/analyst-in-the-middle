"""Linea de comandos del laboratorio: `aitm analyze | evaluate | attack | sanitize-check | judge | run | report`.

```bash
aitm analyze data/processed/html/<reporte>.html            # un reporte, modelo analista
aitm analyze data/processed --model mistral:7b-instruct     # todo el dataset limpio
aitm analyze data/processed --run-dir results/runs/<ts>     # reanuda una corrida cortada
aitm analyze data/processed --defenses sanitizer,llm_judge  # con defensas (Fase 4)
aitm evaluate results/runs/<ts>                              # metricas sobre las trazas
```

`analyze` escribe una traza por analisis en `results/runs/<timestamp>/runs.jsonl` a
medida que avanza, asi que se puede cortar con Ctrl+C y retomar con `--run-dir`: las
celdas ya hechas se saltan. `evaluate` no llama al LLM: lee las trazas y las compara
con el ground truth de `data/labels/`.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from collections import defaultdict
from pathlib import Path
from typing import Sequence

from aitm.analyst.parsers import EXTENSIONS, detect_format
from aitm.config import Config, load_config
from aitm.evaluation import metrics
from aitm.evaluation.labels import iter_labels
from aitm.evaluation.traces import META_FILE, RunLog, iter_records, new_run_dir, utc_now

OK, FAIL, WARN = "[ok]", "[--]", "[!!]"


# -- analyze -----------------------------------------------------------------


def collect_documents(paths: Sequence[Path], formats: set[str] | None) -> list[Path]:
    """Archivos de reporte bajo las rutas dadas, en orden estable."""
    found: list[Path] = []
    for path in paths:
        if path.is_dir():
            candidates = sorted(
                item for item in path.rglob("*") if item.suffix.lower() in EXTENSIONS
            )
        elif path.is_file():
            candidates = [path]
        else:
            raise FileNotFoundError(f"no existe {path}")
        for candidate in candidates:
            if formats is None or detect_format(candidate) in formats:
                found.append(candidate)
    return list(dict.fromkeys(found))


def _open_run(config: Config, run_dir: Path | None, argv: Sequence[str]) -> RunLog:
    if run_dir is None:
        log = RunLog(new_run_dir(config.resolve(config.paths.runs)))
    else:
        log = RunLog(run_dir)
    meta_path = log.run_dir / META_FILE
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("config_hash") != config.config_hash:
            raise SystemExit(
                f"{FAIL} {log.run_dir} se hizo con la config {meta.get('config_hash')} y la "
                f"actual es {config.config_hash}. No se mezclan configuraciones en una corrida."
            )
    else:
        log.write_meta(
            {
                "created_at": utc_now(),
                "config_hash": config.config_hash,
                "command": ["aitm", *argv],
                "config": config.model_dump(mode="json"),
            }
        )
    return log


def cmd_analyze(args: argparse.Namespace, argv: Sequence[str]) -> int:
    from aitm.defenses.registry import available, build_analyst, parse_names
    from aitm.llm.ollama_client import OllamaClient

    config = load_config()
    defenses = parse_names(args.defenses)
    if defenses is None:
        defenses = list(config.defenses.enabled)
    unknown = [name for name in defenses if name not in available()]
    if unknown:
        print(f"{FAIL} defensas desconocidas: {unknown}. Implementadas: {available()}")
        return 1
    formats = set(args.formats.split(",")) if args.formats else None
    documents = collect_documents([Path(p) for p in args.paths], formats)
    if not documents:
        print(f"{FAIL} no hay reportes en {args.paths}")
        return 1

    client = OllamaClient(config)
    if not client.is_up():
        print(f"{FAIL} Ollama no responde en {config.ollama.host} (`ollama serve`)")
        return 1
    models = args.model or [config.models.analyst]
    needed = models + ([config.models.judge] if "llm_judge" in defenses else [])
    missing = [model for model in needed if not client.has_model(model)]
    if missing:
        print(f"{FAIL} modelos no descargados: {missing}  ->  ollama pull <modelo>")
        return 1

    log = _open_run(config, Path(args.run_dir) if args.run_dir else None, argv)
    done = log.completed_keys()
    print(f"{OK} corrida en {log.run_dir}  (config {config.config_hash})")
    print(f"     defensas: {', '.join(defenses) or 'ninguna'}")
    print(f"     {len(documents)} documentos x {len(models)} modelos; {len(done)} ya hechos\n")

    failures = 0
    for model in models:
        analyst = build_analyst(config, client, model=model, defenses=defenses)
        pending = [doc for doc in documents if analyst.cell_key(doc) not in done]
        if args.limit:
            pending = pending[: args.limit]
        for index, document in enumerate(pending, start=1):
            record = analyst.analyze(document)
            log.append(record)
            n_iocs = len(record.output.iocs) if record.output else 0
            severity = record.output.severity if record.output else "-"
            mark = OK if record.status == "ok" else WARN
            failures += record.status != "ok"
            print(
                f"{mark} [{index}/{len(pending)}] {model:28} {record.report_id[:44]:44} "
                f"{record.source_format:4} {record.status:12} "
                f"{record.latency_ms.get('analyst', 0) / 1000:6.1f} s  "
                f"{n_iocs:3} IoCs  sev={severity}"
                + ("  BLOQUEADO" if record.blocked else "")
            )
            if record.context_warning:
                print(f"     {WARN} {record.context_warning}")
            if record.status != "ok" and record.error:
                print(f"     {record.error[:160]}")

    print(f"\n{OK} trazas en {log.path}")
    print(f"     evalua con: aitm evaluate {log.run_dir}")
    return 0 if failures == 0 else 2


# -- evaluate ----------------------------------------------------------------

_SUMMARY_COLUMNS: list[tuple[str, str, str]] = [
    ("runs", "Corridas", "{}"),
    ("failed", "Fallidas", "{}"),
    ("ioc_precision", "Precision IoC", "{:.2f}"),
    ("ioc_recall", "Recall IoC", "{:.2f}"),
    ("ioc_f1", "F1 IoC", "{:.2f}"),
    ("fp_hallucinated", "Alucinados", "{}"),
    ("fp_excluded", "Excluidos reportados", "{}"),
    ("defang_errors", "Defang mal hecho", "{}"),
    ("verdict_macro_f1", "Macro-F1 veredicto", "{:.2f}"),
    ("benign_recall", "Recall benign", "{:.2f}"),
    ("severity_exact", "Severidad exacta", "{:.0%}"),
    ("severity_within_one", "Severidad +-1", "{:.0%}"),
    ("tech_recall_parent", "Recall ATT&CK (padre)", "{:.2f}"),
    ("tech_recall_strict", "Recall ATT&CK (estricto)", "{:.2f}"),
    ("latency_p50_s", "Latencia p50 (s)", "{:.0f}"),
    ("latency_p95_s", "Latencia p95 (s)", "{:.0f}"),
]


def _fmt(value: object, pattern: str) -> str:
    if value is None:
        return "-"
    return pattern.format(value)


def summary_table(groups: dict[str, list[metrics.RunScore]], header: str) -> str:
    lines = [
        f"| {header} | " + " | ".join(title for _, title, _ in _SUMMARY_COLUMNS) + " |",
        "|---|" + "---|" * len(_SUMMARY_COLUMNS),
    ]
    for name, scores in groups.items():
        summary = metrics.aggregate(scores)
        cells = [_fmt(summary[key], pattern) for key, _, pattern in _SUMMARY_COLUMNS]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def cmd_evaluate(args: argparse.Namespace, argv: Sequence[str]) -> int:
    config = load_config()
    run_dir = Path(args.run_dir)
    records = list(iter_records(run_dir / "runs.jsonl"))
    if not records:
        print(f"{FAIL} no hay trazas en {run_dir}")
        return 1

    labels = {label.report_id: label for label in iter_labels(config.resolve(config.paths.labels))}
    frozen = all(label.status == "frozen" for label in labels.values())
    if not frozen:
        print(
            f"{WARN} el ground truth no esta congelado: estas metricas son PROVISIONALES\n"
            "     (sirven para depurar el pipeline, no para el informe).\n"
        )

    scores: list[metrics.RunScore] = []
    skipped = 0
    for record in records:
        if args.clean_only and record.attack is not None:
            continue
        label = labels.get(record.report_id)
        if label is None:
            skipped += 1
            continue
        scores.append(metrics.score_run(record, label))
    if skipped:
        print(f"{WARN} {skipped} trazas sin etiqueta en {config.paths.labels}: no se evaluan")
    if not scores:
        print(f"{FAIL} ninguna traza se pudo evaluar")
        return 1

    by_model: dict[str, list[metrics.RunScore]] = defaultdict(list)
    by_model_format: dict[str, list[metrics.RunScore]] = defaultdict(list)
    for score in scores:
        by_model[score.model].append(score)
        by_model_format[f"{score.model} · {score.source_format}"].append(score)

    # Lineas base sin LLM, sobre el mismo texto que vio el modelo en cada formato.
    regex: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    seen: set[tuple[str, str]] = set()
    for record in records:
        key = (record.report_id, record.source_format)
        if key in seen or record.report_id not in labels or record.attack is not None:
            continue
        seen.add(key)
        tp, fp, total = metrics.regex_baseline(labels[record.report_id], metrics.model_text(record))
        for bucket in (record.source_format, "todos"):
            regex[bucket][0] += tp
            regex[bucket][1] += fp
            regex[bucket][2] += total
    evaluated_labels = [labels[rid] for rid in sorted({s.report_id for s in scores})]
    trivial = metrics.always_malicious_macro_f1(evaluated_labels)

    regex_lines = ["| Formato | Precision IoC | Recall IoC |", "|---|---|---|"]
    for bucket, (tp, fp, total) in sorted(regex.items()):
        regex_lines.append(
            f"| {bucket} | {_fmt(metrics.safe_div(tp, tp + fp), '{:.2f}')} | "
            f"{_fmt(metrics.safe_div(tp, total), '{:.2f}')} |"
        )

    status = "congelado" if frozen else "**SIN CONGELAR: metricas provisionales**"
    report = "\n".join(
        [
            f"# Evaluacion de `{run_dir.name}`",
            "",
            f"Generado: {utc_now()} · ground truth: {status} · "
            f"config: `{', '.join(sorted({r.config_hash for r in records}))}`",
            "",
            "## Por modelo",
            "",
            summary_table(dict(sorted(by_model.items())), "Modelo"),
            "",
            "## Por modelo y formato",
            "",
            summary_table(dict(sorted(by_model_format.items())), "Modelo · formato"),
            "",
            "## Lineas base sin LLM",
            "",
            f"- Macro-F1 de responder siempre `malicious`: **{_fmt(trivial, '{:.2f}')}**",
            "- Extractor regex (`aitm.analyst.iocs`, sin la lista de ruido):",
            "",
            *regex_lines,
            "",
            "Precision y recall de IoCs en *micro* (sumando todos los reportes). Las corridas",
            "fallidas cuentan como analisis vacio. Definiciones en `src/aitm/evaluation/metrics.py`.",
            "",
        ]
    )

    (run_dir / "summary.md").write_text(report, encoding="utf-8")
    rows = [score.row() for score in scores]
    with (run_dir / "scores.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    print(report)
    print(f"{OK} {run_dir / 'summary.md'}")
    print(f"{OK} {run_dir / 'scores.csv'}")
    if args.table:
        destination = config.resolve(Path(args.table))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report, encoding="utf-8")
        (destination.with_suffix(".csv")).write_text(
            (run_dir / "scores.csv").read_text(encoding="utf-8"), encoding="utf-8"
        )
        print(f"{OK} {destination} (+ .csv)")
    return 0


# -- main --------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aitm", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="analiza reportes con el LLM")
    analyze.add_argument("paths", nargs="+", help="archivos o carpetas de reportes")
    analyze.add_argument(
        "--model", action="append", help="modelo (repetible); por defecto models.analyst"
    )
    analyze.add_argument("--formats", help="filtrar por formato, p. ej. txt,html")
    analyze.add_argument("--run-dir", help="carpeta de una corrida a reanudar")
    analyze.add_argument("--limit", type=int, help="maximo de analisis nuevos por modelo")
    analyze.add_argument(
        "--defenses",
        help="defensas separadas por coma (sanitizer,spotlighting,schema_validation,llm_judge) "
        "o 'none'; por defecto defenses.enabled de config.yaml. No cambia el hash de la config",
    )
    analyze.set_defaults(handler=cmd_analyze)

    evaluate = sub.add_parser("evaluate", help="metricas sobre las trazas de una corrida")
    evaluate.add_argument("run_dir", help="carpeta results/runs/<timestamp>")
    evaluate.add_argument("--table", help="copia el resumen a esta ruta (y el CSV al lado)")
    evaluate.add_argument(
        "--clean-only", action="store_true", help="ignora las trazas de reportes envenenados"
    )
    evaluate.set_defaults(handler=cmd_evaluate)

    from aitm.attacks.cli import register as register_attack  # Fase 3

    register_attack(sub)

    from aitm.defenses.cli import register as register_defenses  # Fase 4

    register_defenses(sub)

    from aitm.evaluation.phase5_cli import register as register_phase5  # Fase 5

    register_phase5(sub)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    return args.handler(args, argv)


if __name__ == "__main__":
    raise SystemExit(main())
