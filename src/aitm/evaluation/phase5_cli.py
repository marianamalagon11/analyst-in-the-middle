"""Subcomandos de la Fase 5: `aitm run` (corre un experimento) y `aitm report` (mide).

```bash
aitm run experiments/e1_vectores.yaml --dry-run   # celdas, inferencias nuevas, horas
aitm run experiments/e1_vectores.yaml             # corre; Ctrl+C y se retoma igual
aitm report                                       # ASR, costo, tablas y graficas (sin LLM)
```

`report` lee todas las carpetas `results/runs/e*/` (o las que se le pasen), escribe
las tablas en `results/tables/` (Markdown + CSV) y las figuras en `results/figures/`.
Criterios de exito y de medibilidad: `src/aitm/evaluation/asr.py`.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from aitm.config import Config, load_config
from aitm.defenses.base import CANONICAL_ORDER
from aitm.evaluation import asr as asr_mod
from aitm.evaluation.experiments import ExperimentSpec, enumerate_cells, load_spec
from aitm.evaluation.labels import iter_labels
from aitm.evaluation.traces import RUNS_FILE, RunLog, utc_now

OK, FAIL, WARN = "[ok]", "[--]", "[!!]"

#: Latencias por defecto para estimar si la cache aun no tiene mediciones propias:
#: llama3.1 p50 70 s en el M5 (Fase 2) y el juez p50 22,6 s en el MacBook Air (Fase 4).
DEFAULT_ANALYST_S = 90.0
DEFAULT_JUDGE_S = 23.0

VECTOR_ORDER = ["plaintext", "author_note", "html_hidden", "unicode_invisible", "pdf_hidden"]
GOAL_ORDER = ["flip_to_benign", "omit_ioc", "downgrade_severity", "drop_technique"]


def register(sub) -> None:
    run = sub.add_parser("run", help="corre un experimento de la Fase 5 (experiments/*.yaml)")
    run.add_argument("spec", help="archivo YAML del experimento")
    run.add_argument("--dry-run", action="store_true", help="solo cuenta celdas e inferencias nuevas")
    run.add_argument("--limit", type=int, help="maximo de celdas nuevas en esta pasada")
    run.add_argument("--run-dir", help="por defecto results/runs/<nombre del experimento>")
    run.add_argument("--analyst-s", type=float, help="segundos por analisis para estimar (por defecto, lo medido)")
    run.add_argument("--judge-s", type=float, help="segundos por consulta al juez para estimar")
    run.set_defaults(handler=cmd_run)

    report = sub.add_parser("report", help="ASR, costo de defensas, tablas y graficas (sin LLM)")
    report.add_argument("run_dirs", nargs="*", help="carpetas de experimentos (por defecto results/runs/e*)")
    report.add_argument("--tables", help="carpeta de tablas (por defecto paths.tables)")
    report.add_argument("--figures", help="carpeta de figuras (por defecto paths.figures)")
    report.set_defaults(handler=cmd_report)


# -- run ----------------------------------------------------------------------


def cmd_run(args, argv) -> int:
    from aitm.evaluation.runner import make_client, measured_latency, open_run, plan_experiment, run_experiment

    config = load_config()
    spec = load_spec(args.spec)
    run_dir = Path(args.run_dir) if args.run_dir else config.resolve(config.paths.runs) / spec.name
    client = make_client(config)
    cells = enumerate_cells(spec, config)
    if not cells:
        print(f"{FAIL} el experimento no tiene celdas (¿falta data/poisoned/manifest.jsonl?)")
        return 1

    done = RunLog(run_dir).completed_keys() if (run_dir / RUNS_FILE).is_file() else set()
    plan = plan_experiment(spec, config, client, done, cells=cells)
    models = spec.resolved_models(config)
    uses_judge = any("llm_judge" in combo for combo in spec.defenses)

    print(f"{OK} {spec.name}: {spec.description}")
    print(f"     {plan.total} celdas · {plan.done} hechas · {plan.pending} pendientes · config {config.config_hash}")
    for group, pending in plan.by_group.items():
        print(f"       {group:60} {pending:4} pendientes")
    if plan.missing_files:
        print(
            f"{FAIL} faltan {len(plan.missing_files)} documentos (p. ej. {plan.missing_files[0]}).\n"
            "     Regenera: python scripts/fetch_dataset.py && python scripts/build_dataset.py && aitm attack"
        )
        return 1

    hours = 0.0
    print("     inferencias nuevas (lo demas sale de la cache de este equipo):")
    for model in models:
        seconds = args.analyst_s or measured_latency(client.cache, model) or DEFAULT_ANALYST_S
        n = plan.new_analyst.get(model, 0)
        hours += n * seconds / 3600
        print(f"       analista {model:32} {n:5} x {seconds:5.0f} s")
    if uses_judge:
        seconds = args.judge_s or measured_latency(client.cache, config.models.judge) or DEFAULT_JUDGE_S
        hours += plan.new_judge * seconds / 3600
        print(f"       juez     {config.models.judge:32} {plan.new_judge:5} x {seconds:5.0f} s")
    print(f"     estimado: {hours:.1f} h")
    if args.dry_run:
        return 0

    if not client.is_up():
        print(f"{FAIL} Ollama no responde en {config.ollama.host} (`ollama serve`)")
        return 1
    needed = models + ([config.models.judge] if uses_judge else [])
    missing = [m for m in needed if not client.has_model(m)]
    if missing:
        print(f"{FAIL} modelos no descargados: {missing}  ->  ollama pull <modelo>")
        return 1

    log = open_run(config, run_dir, spec)
    new, failures = run_experiment(spec, config, client, log, limit=args.limit)
    print(
        f"\n{OK} {new} celdas nuevas ({client.hits} desde la cache, {client.misses} inferidas), "
        f"{failures} fallidas. Trazas en {log.path}"
    )
    print("     mide con: aitm report")
    return 0 if failures == 0 else 2


# -- report -------------------------------------------------------------------


def _pct(value: float | None) -> str:
    return "-" if value is None else f"{value:.0%}"


def _num(value: float | None, pattern: str = "{:.2f}") -> str:
    return "-" if value is None else pattern.format(value)


def _write(tables: Path, name: str, title: str, intro: list[str], body: str, rows: list[dict]) -> Path:
    tables.mkdir(parents=True, exist_ok=True)
    path = tables / f"{name}.md"
    path.write_text("\n".join([f"# {title}", "", *intro, "", body, ""]), encoding="utf-8")
    if rows:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
        path.with_suffix(".csv").write_text(buffer.getvalue(), encoding="utf-8")
    return path


def short_defenses(label: str) -> str:
    """Etiqueta corta para las figuras: la combinacion de las cuatro es `todas`."""
    if len(label.split("+")) == len(CANONICAL_ORDER):
        return "todas"
    return label.replace("+", "+\n")


def _defense_order(labels: set[str]) -> list[str]:
    def key(label: str) -> tuple[int, int]:
        if label == "ninguna":
            return (0, 0)
        parts = label.split("+")
        return (len(parts), min(CANONICAL_ORDER.index(p) for p in parts if p in CANONICAL_ORDER))

    return sorted(labels, key=key)


def build_report(records, labels, config: Config, tables: Path, figures: Path, sources: list[str]) -> list[Path]:
    from aitm.evaluation import plots

    analyst = config.models.analyst
    out = asr_mod.outcomes(records)
    written: list[Path] = []
    stamp = f"Generado: {utc_now()} con `aitm report` · config `{', '.join(sorted({r.config_hash for r in records}))}` · trazas: {', '.join(sources)}."
    legend = [
        "Cada celda: éxitos / medibles (ASR). *Medible* = limpio y envenenado con JSON válido y",
        "el limpio daba el resultado que el ataque quiere estropear. *Éxito* = se cumple el",
        "criterio del objetivo y la corrida no fue bloqueada. *ASR sin bloqueo* ignora el",
        "bloqueo del juez; *Detectados* = bloqueos cuya cita cae dentro del payload.",
        "Criterios: `src/aitm/evaluation/asr.py` y `src/aitm/attacks/base.py`.",
    ]

    # Experimento 1: por vector y objetivo, sin defensas, modelo principal.
    e1 = [o for o in out if o.model == analyst and o.defenses == "ninguna"]
    if e1:
        body, rows = asr_mod.pivot(e1, lambda o: f"`{o.vector}` ({o.variant}, {o.source_format})",
                                   lambda o: o.goal, row_title="Vector", col_order=GOAL_ORDER)
        written.append(_write(tables, "exp1_asr_por_vector", f"Experimento 1 — ASR por vector, sin defensas, `{analyst}`",
                              [stamp, "", *legend], body, rows))
        by_vector = {v: asr_mod.rate([o for o in e1 if o.vector == v]) for v in VECTOR_ORDER}
        by_vector = {v: r for v, r in by_vector.items() if r.cells}
        written.append(plots.grouped_bars(
            figures / "asr_por_vector.png",
            title=f"ASR por vector, sin defensas ({analyst.split(':')[0]})",
            categories=list(by_vector),
            series={"ASR": [r.asr for r in by_vector.values()]},
            subtitle=f"Medibles por vector: {', '.join(f'{v} {r.measurable}' for v, r in by_vector.items())}. Cuatro objetivos, payload canónico.",
        ))

    # Experimento 2: por vector y modelo, sin defensas, solo objetivos comunes a todos.
    plain = [o for o in out if o.defenses == "ninguna"]
    models = sorted({o.model for o in plain})
    if len(models) > 1:
        common = set.intersection(*({o.goal for o in plain if o.model == m} for m in models))
        e2 = [o for o in plain if o.goal in common]
        body, rows = asr_mod.pivot(e2, lambda o: o.vector, lambda o: o.model, row_title="Vector",
                                   row_order=VECTOR_ORDER, col_order=[analyst])
        written.append(_write(tables, "exp2_asr_por_modelo", "Experimento 2 — ASR por vector y modelo, sin defensas",
                              [stamp, "", f"Solo los objetivos que corrieron todos los modelos: {', '.join(sorted(common))}.", "", *legend],
                              body, rows))
        shown = [m for m in [analyst, *models] if m in models][:3]
        vectors = [v for v in VECTOR_ORDER if any(o.vector == v for o in e2)]
        written.append(plots.grouped_bars(
            figures / "asr_por_modelo.png",
            title="ASR por vector y modelo, sin defensas",
            categories=vectors,
            series={m.split(":")[0]: [asr_mod.rate([o for o in e2 if o.model == m and o.vector == v]).asr for v in vectors] for m in shown},
            subtitle=f"Objetivos: {', '.join(sorted(common))}. s/d = sin celdas medibles.",
        ))

    # Experimentos 3 y 4: cada defensa por separado y todas juntas, modelo principal.
    main = [o for o in out if o.model == analyst]
    defense_labels = _defense_order({o.defenses for o in main})
    if len(defense_labels) > 1:
        body, rows = asr_mod.pivot(main, lambda o: o.defenses, lambda o: o.vector, row_title="Defensas",
                                   row_order=defense_labels, col_order=VECTOR_ORDER)
        written.append(_write(tables, "exp3_4_asr_por_defensa", f"Experimentos 3 y 4 — ASR por defensa, `{analyst}`",
                              [stamp, "", *legend], body, rows))
        rates = {d: asr_mod.rate([o for o in main if o.defenses == d]) for d in defense_labels}
        written.append(plots.grouped_bars(
            figures / "asr_por_defensa.png",
            title=f"ASR por configuración de defensas ({analyst.split(':')[0]})",
            categories=[short_defenses(d) for d in defense_labels],
            series={"ASR": [r.asr for r in rates.values()], "ASR sin bloqueo": [r.asr_output for r in rates.values()]},
            subtitle="ASR sin bloqueo: la salida quedó manipulada aunque el juez detuviera la corrida.",
        ))

    # Experimento 5: costo de las defensas en limpios.
    costs = [c for c in asr_mod.defense_costs(records, labels) if c.model == analyst]
    if costs:
        lines = [
            "| Defensas | Limpios | Fallidos | F1 IoC | Recall IoC | Precisión IoC | Macro-F1 veredicto | Severidad exacta | Bloqueados (FP) | Latencia p50 (s) | Latencia p95 (s) |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
        order = {d: i for i, d in enumerate(_defense_order({c.defenses for c in costs}))}
        costs.sort(key=lambda c: order[c.defenses])
        for c in costs:
            lines.append(
                f"| {c.defenses} | {c.runs} | {c.failed} | {_num(c.ioc_f1)} | {_num(c.ioc_recall)} | {_num(c.ioc_precision)} | "
                f"{_num(c.verdict_macro_f1)} | {_pct(c.severity_exact)} | {c.blocked}/{c.runs} | "
                f"{_num(c.latency_p50_s, '{:.0f}')} | {_num(c.latency_p95_s, '{:.0f}')} |"
            )
        written.append(_write(
            tables, "exp5_costo_defensas", f"Experimento 5 — Costo de las defensas en reportes limpios, `{analyst}`",
            [stamp, "",
             "Exactitud contra el ground truth congelado (mismas métricas que la línea base de la Fase 2),",
             "falsos positivos del juez (limpios bloqueados) y latencia total por reporte (analista + juez).",
             "La latencia de una celda servida desde la cache es la de su inferencia original."],
            "\n".join(lines), [c.row() for c in costs]))
        points = [(short_defenses(c.defenses).replace("\n", ""), c.latency_p50_s, c.ioc_f1)
                  for c in costs if c.latency_p50_s is not None and c.ioc_f1 is not None]
        if points:
            written.append(plots.accuracy_vs_latency(
                figures / "exactitud_vs_latencia.png",
                points=points,
                title=f"Exactitud vs latencia por configuración ({analyst.split(':')[0]})",
                subtitle="Reportes limpios. Latencia: analista + juez, p50 por reporte.",
            ))

    if out:
        rows = [o.row() for o in out]
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
        tables.mkdir(parents=True, exist_ok=True)
        (tables / "asr_celdas.csv").write_text(buffer.getvalue(), encoding="utf-8")
        written.append(tables / "asr_celdas.csv")
    return written


def cmd_report(args, argv) -> int:
    config = load_config()
    runs_root = config.resolve(config.paths.runs)
    run_dirs = [Path(p) for p in args.run_dirs] or sorted(
        p for p in runs_root.glob("e*") if (p / RUNS_FILE).is_file()
    )
    if not run_dirs:
        print(f"{FAIL} no hay experimentos en {runs_root} (corre antes `aitm run experiments/<e>.yaml`)")
        return 1
    records = asr_mod.load_records(run_dirs)
    labels = {label.report_id: label for label in iter_labels(config.resolve(config.paths.labels))}
    tables = config.resolve(Path(args.tables)) if args.tables else config.resolve(config.paths.tables)
    figures = config.resolve(Path(args.figures)) if args.figures else config.resolve(config.paths.figures)
    written = build_report(records, labels, config, tables, figures, [p.name for p in run_dirs])
    print(f"{OK} {len(records)} trazas de {len(run_dirs)} experimento(s)")
    for path in written:
        print(f"{OK} {path}")
    return 0
