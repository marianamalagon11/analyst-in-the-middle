"""Runner de la Fase 5: ejecuta un experimento (`experiments/*.yaml`) celda por celda.

```bash
aitm run experiments/e1_vectores.yaml --dry-run   # cuantas inferencias nuevas y cuanto tarda
aitm run experiments/e1_vectores.yaml             # corre (se puede cortar y retomar)
```

- **Reanudable.** Cada celda es una traza en `results/runs/<experimento>/runs.jsonl`
  con la clave de siempre (modelo, documento, defensas, config). Al volver a lanzar
  el mismo comando, lo hecho se salta. Una celda con `error` (Ollama caido) se repite.
- **Una sola config.** La carpeta guarda el hash de `config.yaml` y se niega a mezclar
  corridas con otra config. Las defensas no tocan la config: van por celda.
- **Cache de inferencia** (`aitm.llm.cache`): una peticion identica a una ya hecha en
  este equipo no se vuelve a calcular. El `--dry-run` construye los mensajes exactos de
  cada celda sin llamar al modelo y cuenta cuantas peticiones son de verdad nuevas,
  analista y juez por separado. Ese conteo, por la latencia medida, es el tiempo.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aitm.analyst.pipeline import Environment
from aitm.config import Config
from aitm.defenses.llm_judge import JUDGE_NUM_PREDICT, judge_messages, judge_schema
from aitm.defenses.registry import build_analyst
from aitm.evaluation.experiments import Cell, ExperimentSpec, defenses_label, enumerate_cells
from aitm.evaluation.traces import META_FILE, RunLog, utc_now
from aitm.hostinfo import hardware_summary
from aitm.llm.cache import CachingClient, InferenceCache

OK, FAIL, WARN = "[ok]", "[--]", "[!!]"


@dataclass
class Plan:
    """Lo que falta de un experimento y cuanto cuesta, sin haber llamado al modelo."""

    total: int = 0
    done: int = 0
    pending: int = 0
    missing_files: list[str] = field(default_factory=list)
    new_analyst: Counter = field(default_factory=Counter)  # modelo -> peticiones nuevas
    new_judge: int = 0
    by_group: dict[str, int] = field(default_factory=dict)

    def hours(self, analyst_s: float, judge_s: float) -> float:
        return (sum(self.new_analyst.values()) * analyst_s + self.new_judge * judge_s) / 3600


def open_run(config: Config, run_dir: Path, spec: ExperimentSpec) -> RunLog:
    log = RunLog(run_dir)
    meta_path = log.run_dir / META_FILE
    if meta_path.exists():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("config_hash") != config.config_hash:
            raise SystemExit(
                f"{FAIL} {log.run_dir} se hizo con la config {meta.get('config_hash')} y la actual "
                f"es {config.config_hash}. No se mezclan configuraciones en un experimento."
            )
    else:
        log.write_meta(
            {
                "created_at": utc_now(),
                "config_hash": config.config_hash,
                "experiment": spec.model_dump(mode="json"),
                "config": config.model_dump(mode="json"),
            }
        )
    return log


def _groups(cells: list[Cell]) -> dict[tuple[str, tuple[str, ...]], list[Cell]]:
    groups: dict[tuple[str, tuple[str, ...]], list[Cell]] = {}
    for cell in cells:
        groups.setdefault((cell.model, cell.defenses), []).append(cell)
    return groups


def plan_experiment(
    spec: ExperimentSpec,
    config: Config,
    client: CachingClient,
    done_keys: set[str],
    *,
    cells: list[Cell] | None = None,
) -> Plan:
    """Cuenta celdas hechas, pendientes y peticiones nuevas (analista y juez)."""
    cells = enumerate_cells(spec, config) if cells is None else cells
    plan = Plan(total=len(cells))
    planned: set[str] = set()
    judge_prompt = config.resolve(config.judge.system_prompt).read_text(encoding="utf-8")
    environment = Environment(host=client.host)

    for (model, defenses), group in _groups(cells).items():
        analyst = build_analyst(config, client, model=model, defenses=list(defenses), environment=environment)
        pending_here = 0
        for cell in group:
            if not cell.path.is_file():
                plan.missing_files.append(str(cell.path))
                continue
            if analyst.cell_key(cell.path, report_id=cell.report_id) in done_keys:
                plan.done += 1
                continue
            plan.pending += 1
            pending_here += 1
            report, messages, _ = analyst.prepare(cell.path, report_id=cell.report_id)
            key = client.key_for(messages, model=model, response_format=analyst.response_format())
            if key not in client.cache and key not in planned:
                planned.add(key)
                plan.new_analyst[model] += 1
            if "llm_judge" in defenses:
                judge_key = client.key_for(
                    judge_messages(judge_prompt, report, config.seed),
                    model=config.models.judge,
                    response_format=judge_schema(),
                    options={"num_predict": JUDGE_NUM_PREDICT},
                )
                if judge_key not in client.cache and judge_key not in planned:
                    planned.add(judge_key)
                    plan.new_judge += 1
        plan.by_group[f"{model} · {defenses_label(defenses)}"] = pending_here
    return plan


def run_experiment(
    spec: ExperimentSpec,
    config: Config,
    client: CachingClient,
    log: RunLog,
    *,
    limit: int | None = None,
    environments: dict[str, Environment] | None = None,
) -> tuple[int, int]:
    """Corre las celdas pendientes. Devuelve (corridas nuevas, fallidas)."""
    cells = enumerate_cells(spec, config)
    done_keys = log.completed_keys()
    environments = environments or {}
    new = failures = 0

    for (model, defenses), group in _groups(cells).items():
        if model not in environments:
            environments[model] = Environment(
                ollama_version=_safe(lambda: client.version()),
                model_digest=client.digest(model),
                host=client.host,
            )
        analyst = build_analyst(
            config, client, model=model, defenses=list(defenses), environment=environments[model]
        )
        pending = [
            c for c in group
            if c.path.is_file() and analyst.cell_key(c.path, report_id=c.report_id) not in done_keys
        ]
        if not pending:
            continue
        print(f"\n{OK} {model} · defensas: {defenses_label(defenses)} · {len(pending)} celdas pendientes")
        for index, cell in enumerate(pending, start=1):
            if limit is not None and new >= limit:
                return new, failures
            hits_before = client.hits
            record = analyst.analyze(cell.path, report_id=cell.report_id, attack=cell.attack)
            log.append(record)
            new += 1
            failures += record.status != "ok"
            cached = client.hits > hits_before
            attack = cell.attack or {}
            injection = attack.get("injection", {})
            label = f"{injection.get('vector', 'limpio')}/{injection.get('variant', '-')}/{attack.get('goal', '-')}"
            print(
                f"{OK if record.status == 'ok' else WARN} [{index}/{len(pending)}] "
                f"{cell.report_id[:36]:36} {cell.source_format:4} {label[:44]:44} {record.status:12} "
                f"{sum(record.latency_ms.values()) / 1000:6.1f} s"
                + (" (cache)" if cached else "")
                + ("  BLOQUEADO" if record.blocked else "")
            )
    return new, failures


def measured_latency(cache: InferenceCache, model: str) -> float | None:
    """Latencia p50 (s) de las inferencias de `model` ya guardadas en la cache de este equipo."""
    from aitm.evaluation.metrics import percentile

    values = [e["latency_ms"] / 1000 for e in cache.entries.values() if e.get("model") == model]
    return percentile(values, 0.5) if len(values) >= 3 else None


def _safe(fn) -> Any:
    try:
        return fn()
    except Exception:  # noqa: BLE001 - solo es metadato de la traza
        return None


def make_client(config: Config, inner: Any | None = None) -> CachingClient:
    from aitm.llm.ollama_client import OllamaClient

    cache = InferenceCache(config.resolve(config.paths.runs) / "_cache")
    return CachingClient(inner or OllamaClient(config), cache, host=hardware_summary())
