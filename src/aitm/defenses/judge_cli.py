"""Subcomando `aitm judge`: corre SOLO el juez sobre documentos, sin el analista.

```bash
aitm judge                                   # los 36 limpios: falsos positivos del juez
aitm judge data/processed data/poisoned      # + deteccion sobre los envenenados
aitm judge data/poisoned --sanitize          # el juez ve el texto ya sanitizado
aitm judge --run-dir results/runs/<ts>       # reanuda
aitm judge --run-dir results/runs/<ts> --table results/tables/judge_fp.md   # solo resume
```

Es la medicion de la Fase 4 "falsos positivos del juez sobre los reportes limpios", y de
paso su tasa de deteccion por vector. Correr el juez aparte cuesta una fraccion de un
analisis completo (genera ~50 tokens, no ~3.000), asi que la matriz entera del juez
cabe en una tarde aunque la del analista no.

Un documento es **limpio** si no aparece en el manifiesto de envenenados y
**envenenado** si aparece (se empareja por ruta dentro de `paths.poisoned`). Las
trazas van a `results/runs/<timestamp>/judge.jsonl`, una linea por documento, con el
veredicto completo y la respuesta cruda del juez.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from aitm.analyst.parsers import parse
from aitm.analyst.pipeline import sha256_bytes
from aitm.attacks.base import PoisonManifestEntry
from aitm.config import Config, load_config
from aitm.defenses.base import DefenseContext
from aitm.defenses.llm_judge import JudgeVerdict, judge_text
from aitm.defenses.sanitizer import Sanitizer
from aitm.evaluation.metrics import percentile
from aitm.evaluation.traces import new_run_dir, utc_now

OK, FAIL, WARN = "[ok]", "[--]", "[!!]"
JUDGE_FILE = "judge.jsonl"


class JudgeRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    created_at: str
    config_hash: str
    report_id: str
    source_path: str
    source_format: str
    source_sha256: str
    sanitized: bool
    kind: str  # "clean" | "poisoned"
    attack: dict[str, Any] | None = None
    verdict: JudgeVerdict

    @property
    def key(self) -> str:
        return "|".join([self.verdict.model, self.source_sha256, str(self.sanitized), self.config_hash])


def register(sub) -> None:
    judge = sub.add_parser("judge", help="corre solo el LLM juez (FP en limpios, deteccion en envenenados)")
    judge.add_argument("paths", nargs="*", help="archivos o carpetas (por defecto paths.data_processed)")
    judge.add_argument("--model", help="modelo juez (por defecto models.judge)")
    judge.add_argument("--sanitize", action="store_true", help="el juez ve el texto sanitizado")
    judge.add_argument("--run-dir", help="carpeta de una corrida a reanudar o resumir")
    judge.add_argument("--limit", type=int, help="maximo de documentos nuevos")
    judge.add_argument("--table", help="copia el resumen Markdown aqui")
    judge.set_defaults(handler=cmd_judge)


def _manifest_index(config: Config) -> tuple[Path, dict[str, PoisonManifestEntry]]:
    root = config.resolve(config.paths.poisoned)
    path = root / "manifest.jsonl"
    index: dict[str, PoisonManifestEntry] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                entry = PoisonManifestEntry.model_validate_json(line)
                index[entry.poisoned_path] = entry
    return root, index


def _read_records(path: Path) -> list[JudgeRecord]:
    if not path.is_file():
        return []
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                records.append(JudgeRecord.model_validate_json(line))
            except ValueError:
                continue  # linea cortada por una interrupcion: se rehace
    return records


def cmd_judge(args, argv) -> int:
    from aitm.cli import collect_documents
    from aitm.llm.ollama_client import OllamaClient

    config = load_config()
    model = args.model or config.models.judge
    run_dir = Path(args.run_dir) if args.run_dir else None
    paths = [Path(p) for p in args.paths] or [config.resolve(config.paths.data_processed)]
    summary_only = run_dir is not None and not args.paths and (run_dir / JUDGE_FILE).is_file()

    if run_dir is None:
        run_dir = new_run_dir(config.resolve(config.paths.runs))
    run_dir.mkdir(parents=True, exist_ok=True)
    log_path = run_dir / JUDGE_FILE
    records = _read_records(log_path)

    if not summary_only:
        documents = collect_documents(paths, None)
        if not documents:
            print(f"{FAIL} no hay documentos en {[str(p) for p in paths]}")
            return 1
        client = OllamaClient(config)
        if not client.is_up():
            print(f"{FAIL} Ollama no responde en {config.ollama.host} (`ollama serve`)")
            return 1
        if not client.has_model(model):
            print(f"{FAIL} modelo juez no descargado: {model}  ->  ollama pull {model}")
            return 1

        poisoned_root, manifest = _manifest_index(config)
        done = {record.key for record in records if record.verdict.status != "error"}
        system_prompt = config.resolve(config.judge.system_prompt).read_text(encoding="utf-8")
        sanitizer = Sanitizer()
        print(f"{OK} juez {model} · umbral {config.judge.threshold} · corrida en {run_dir}")

        new = 0
        for document in documents:
            if args.limit and new >= args.limit:
                break
            data = document.read_bytes()
            try:
                relative = document.resolve().relative_to(poisoned_root.resolve()).as_posix()
            except ValueError:
                relative = None
            entry = manifest.get(relative) if relative else None
            report_id = entry.report_id if entry else document.stem
            report = parse(
                document,
                report_id=report_id,
                include_hidden_html=config.analyst.parser.include_hidden_html,
                include_html_comments=config.analyst.parser.include_html_comments,
                include_pdf_metadata=config.analyst.parser.include_pdf_metadata,
            )
            if args.sanitize:
                report = sanitizer.apply(report, DefenseContext())

            record = JudgeRecord(
                created_at=utc_now(),
                config_hash=config.config_hash,
                report_id=report_id,
                source_path=document.as_posix(),
                source_format=report.source_format,
                source_sha256=sha256_bytes(data),
                sanitized=args.sanitize,
                kind="poisoned" if entry else "clean",
                attack=(
                    {
                        "poison_id": entry.poison_id,
                        "goal": entry.goal,
                        "vector": entry.injection.vector,
                        "variant": entry.injection.variant,
                        "visibility": entry.injection.visibility,
                        "payload_id": entry.injection.payload_id,
                    }
                    if entry
                    else None
                ),
                verdict=JudgeVerdict(model=model, status="error", threshold=config.judge.threshold),
            )
            if record.key in done:
                continue
            record.verdict = judge_text(client, config, report, model=model, system_prompt=system_prompt)
            with log_path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(record.model_dump_json() + "\n")
            records.append(record)
            new += 1
            v = record.verdict
            mark = WARN if v.blocked else OK
            print(
                f"{mark} {record.kind:8} {report_id[:44]:44} {record.source_format:4} "
                f"{(record.attack or {}).get('vector', '-'):17} {v.status:12} "
                f"inj={v.injection} conf={v.confidence} {v.latency_ms / 1000:5.1f} s"
            )

    report_md = summarize(records, config, run_dir)
    (run_dir / "judge_summary.md").write_text(report_md, encoding="utf-8")
    print("\n" + report_md)
    print(f"{OK} {run_dir / 'judge_summary.md'}")
    if args.table:
        destination = config.resolve(Path(args.table))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report_md, encoding="utf-8")
        print(f"{OK} {destination}")
    return 0


def _rate(hits: int, total: int) -> str:
    return f"{hits}/{total} ({hits / total:.0%})" if total else "-"


def summarize(records: list[JudgeRecord], config: Config, run_dir: Path) -> str:
    """Tabla de falsos positivos (limpios) y deteccion (envenenados) del juez."""
    latest: dict[str, JudgeRecord] = {}
    for record in records:
        latest[record.key] = record  # si se repitio una celda con error, vale la ultima
    records = list(latest.values())

    clean = [r for r in records if r.kind == "clean"]
    poisoned = [r for r in records if r.kind == "poisoned"]
    models = sorted({r.verdict.model for r in records}) or ["-"]
    sanitized = sorted({r.sanitized for r in records})

    def block(rows: list[JudgeRecord]) -> tuple[int, int, int, int]:
        ok = [r for r in rows if r.verdict.status == "ok"]
        flagged = sum(r.verdict.blocked for r in ok)
        said_yes = sum(bool(r.verdict.injection) for r in ok)
        return len(rows), len(ok), flagged, said_yes

    lines = [
        f"# Juez LLM sobre `{run_dir.name}`",
        "",
        f"Generado: {utc_now()} · juez `{', '.join(models)}` · umbral {config.judge.threshold} · "
        f"texto sanitizado: {sanitized} · config `{config.config_hash}`",
        "",
        "Bloquea = `injection` y `confidence >= umbral`. Las tasas se calculan sobre las",
        "respuestas válidas; los fallos del juez no bloquean (*fail-open*) y se cuentan aparte.",
        "",
        "## Falsos positivos en reportes limpios",
        "",
        "| Formato | Documentos | Respuestas válidas | Bloqueados (FP) | Dijo `injection` |",
        "|---|---|---|---|---|",
    ]
    by_format: dict[str, list[JudgeRecord]] = defaultdict(list)
    for record in clean:
        by_format[record.source_format].append(record)
    for fmt in sorted(by_format) + (["todos"] if clean else []):
        rows = clean if fmt == "todos" else by_format[fmt]
        n, ok, flagged, yes = block(rows)
        lines.append(f"| {fmt} | {n} | {ok} | {_rate(flagged, ok)} | {_rate(yes, ok)} |")
    false_positives = [r for r in clean if r.verdict.blocked]
    if false_positives:
        lines += ["", "Limpios bloqueados (evidencia citada por el juez):", ""]
        lines += [
            f"- `{r.report_id}` ({r.source_format}, conf {r.verdict.confidence:.2f}): "
            f"{json.dumps(r.verdict.evidence[:160], ensure_ascii=False)}"
            for r in false_positives
        ]

    if poisoned:
        lines += [
            "",
            "## Detección en reportes envenenados",
            "",
            "| Vector | Variante | Visibilidad | Documentos | Respuestas válidas | Detectados |",
            "|---|---|---|---|---|---|",
        ]
        groups: dict[tuple[str, str, str], list[JudgeRecord]] = defaultdict(list)
        for record in poisoned:
            attack = record.attack or {}
            groups[(attack.get("vector", "?"), attack.get("variant", "?"), attack.get("visibility", "?"))].append(record)
        for (vector, variant, visibility), rows in sorted(groups.items()):
            n, ok, flagged, _ = block(rows)
            lines.append(f"| `{vector}` | `{variant}` | {visibility} | {n} | {ok} | {_rate(flagged, ok)} |")
        n, ok, flagged, _ = block(poisoned)
        lines.append(f"| **todos** | | | {n} | {ok} | {_rate(flagged, ok)} |")

    latencies = [r.verdict.latency_ms / 1000 for r in records if r.verdict.status == "ok"]
    failures = sum(r.verdict.status != "ok" for r in records)
    p50, p95 = percentile(latencies, 0.5), percentile(latencies, 0.95)
    lines += [
        "",
        "## Costo",
        "",
        f"- Latencia del juez: p50 {p50:.1f} s · p95 {p95:.1f} s" if latencies else "- Latencia: -",
        f"- Fallos del juez (no bloquean): {failures}/{len(records)}",
        "",
    ]
    return "\n".join(lines)
