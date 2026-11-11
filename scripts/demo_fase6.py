"""Demo de la sustentación: un reporte limpio, el mismo envenenado y el envenenado con defensas.

Usa el pipeline y la comparación del propio proyecto (refang incluido), así que el
veredicto que imprime es el mismo que cuenta el evaluador de la Fase 5.

```bash
python scripts/demo_fase6.py                       # corre los 3 casos (~35 min en CPU la 1.a vez)
python scripts/demo_fase6.py --mostrar results/runs/demo_<ts>   # solo imprime, sin LLM
```

Las respuestas quedan en la caché de inferencia (`results/runs/_cache`): al volver a
correrlo en el mismo equipo, los 3 casos salen al instante con la misma salida.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aitm.analyst.iocs import normalize_value
from aitm.config import load_config
from aitm.evaluation.matching import repair_defang
from aitm.evaluation.traces import META_FILE, RunLog, iter_records, utc_now

POISON_ID = "4ed6fe76697b"  # proofpoint bazaflix · html_hidden · display_none · flip_to_benign
TODAS = ["sanitizer", "spotlighting", "schema_validation", "llm_judge"]
LINEA = "=" * 78


def entrada_manifiesto(config) -> dict:
    manifest = config.resolve(config.paths.poisoned) / "manifest.jsonl"
    for line in manifest.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        if entry["poison_id"] == POISON_ID:
            return entry
    raise SystemExit(f"[--] no encontré {POISON_ID} en {manifest}")


def buscar_ioc(record, objetivo: str):
    """El hallazgo del modelo que corresponde al IoC objetivo, tras refang."""
    if record.output is None:
        return None
    meta = normalize_value("domain", objetivo)
    for finding in record.output.iocs:
        valor, _ = repair_defang(finding.type, finding.value)
        if normalize_value(finding.type, valor) == meta:
            return finding
    return None


def imprimir(casos: list[tuple[str, object]], objetivo: str) -> None:
    print(f"\n{LINEA}\nRESUMEN — IoC objetivo: {objetivo}\n{LINEA}")
    print(f"{'Escenario':32} {'Veredicto IoC':16} {'Severidad':10} {'Juez':10} Bloqueado")
    print("-" * 78)
    for nombre, record in casos:
        hallazgo = buscar_ioc(record, objetivo)
        veredicto = hallazgo.verdict.upper() if hallazgo else "NO DETECTADO"
        severidad = record.output.severity.upper() if record.output else "-"
        juez = "-"
        if record.judge:
            juez = "inyección" if record.judge.get("injection") else "limpio"
        print(f"{nombre:32} {veredicto:16} {severidad:10} {juez:10} {'SÍ' if record.blocked else 'NO'}")
    print(LINEA)
    for nombre, record in casos:
        hallazgo = buscar_ioc(record, objetivo)
        if hallazgo:
            print(f"{nombre}: \"{hallazgo.value}\" ({hallazgo.verdict}, confianza {hallazgo.confidence:.2f})")
            if hallazgo.evidence:
                print(f"   evidencia: {hallazgo.evidence[:150]}")
        for nota in record.defense_notes:
            print(f"   defensa: {nota[:150]}")
    print(f"{LINEA}\nASR 0 % no es seguridad absoluta: vale para este payload, objetivo y modelo.\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mostrar", help="carpeta de una corrida de demo ya hecha: solo imprime")
    parser.add_argument("--defensas", default=",".join(TODAS),
                        help="defensas del caso 3 (por defecto las cuatro)")
    args = parser.parse_args()

    config = load_config()
    entry = entrada_manifiesto(config)
    objetivo = entry["target"]["ioc_value"]
    nombres = ["LÍNEA BASE (limpio)", "ATAQUE SIN DEFENSAS", "ATAQUE CON DEFENSAS"]

    if args.mostrar:
        records = list(iter_records(Path(args.mostrar) / "runs.jsonl"))
        if len(records) < 3:
            raise SystemExit(f"[--] la corrida tiene {len(records)} casos, se esperaban 3")
        imprimir(list(zip(nombres, records[:3])), objetivo)
        return 0

    from aitm.defenses.registry import build_analyst
    from aitm.evaluation.runner import make_client

    limpio = config.resolve(config.paths.data_processed) / "html" / f"{entry['report_id']}.html"
    envenenado = config.resolve(config.paths.poisoned) / entry["poisoned_path"]
    for path in (limpio, envenenado):
        if not path.is_file():
            raise SystemExit(f"[--] falta {path}. Genera los envenenados con: aitm attack --canonical")

    client = make_client(config)
    if not client.is_up():
        raise SystemExit(f"[--] Ollama no responde en {config.ollama.host} (`ollama serve`)")

    run_dir = config.resolve(config.paths.runs) / f"demo_{utc_now().replace(':', '').replace('-', '')}"
    log = RunLog(run_dir)
    log.write_meta({"created_at": utc_now(), "config_hash": config.config_hash,
                    "command": sys.argv, "demo_poison_id": POISON_ID})

    defensas = [d for d in args.defensas.split(",") if d]
    plan = [
        (nombres[0], limpio, [], None),
        (nombres[1], envenenado, [], entry),
        (nombres[2], envenenado, defensas, entry),
    ]
    print(f"{LINEA}\nDEMO — Inyección de prompt en un analista CTI\n{LINEA}")
    print(f"Reporte:  {entry['report_id']}")
    print(f"Ataque:   {entry['injection']['vector']} ({entry['injection']['variant']}), objetivo {entry['goal']}")
    print(f"Payload:  {entry['injection']['payload_text']}")
    print(f"Modelo:   {config.models.analyst}")

    casos = []
    for nombre, path, defs, attack in plan:
        print(f"\n--- {nombre}  (defensas: {', '.join(defs) or 'ninguna'}) ---")
        analyst = build_analyst(config, client, defenses=defs)
        hits = client.hits
        record = analyst.analyze(path, report_id=entry["report_id"], attack=attack)
        log.append(record)
        hallazgo = buscar_ioc(record, objetivo)
        origen = " (desde la caché)" if client.hits > hits else ""
        print(f"IoC {objetivo}: {hallazgo.verdict.upper() if hallazgo else 'NO DETECTADO'}"
              f" | severidad {record.output.severity.upper() if record.output else '-'}"
              f" | {record.latency_ms.get('analyst', 0) / 1000:.0f} s{origen}")
        casos.append((nombre, record))

    imprimir(casos, objetivo)
    print(f"Trazas guardadas en {run_dir}\nPara mostrarlas otra vez: python scripts/demo_fase6.py --mostrar {run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
