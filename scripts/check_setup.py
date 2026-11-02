"""Verificacion de la Fase 0.

Comprueba que la configuracion carga, que Ollama responde, que los modelos
estan descargados, cuanto tarda cada uno y si repiten la misma salida con la
misma semilla. Escribe una tabla en results/setup_report.md, o donde diga `--out`.
Si ese reporte ya existe, exige `--out`: el original tiene analisis escrito a mano.

Uso:
    python scripts/check_setup.py             # todos los modelos de models.compare
    python scripts/check_setup.py --quick     # solo el modelo analista
    python scripts/check_setup.py --no-llm    # solo config, sin tocar Ollama
    python scripts/check_setup.py --out results/setup_report_m5.md
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aitm.config import Config, load_config, project_root  # noqa: E402
from aitm.hostinfo import hardware_summary  # noqa: E402
from aitm.llm.ollama_client import OllamaClient, OllamaError  # noqa: E402

# Pregunta corta y cerrada: nos interesa el determinismo y la latencia,
# no la calidad de la respuesta.
PROBE_MESSAGES = [
    {
        "role": "system",
        "content": "Eres un asistente de pruebas. Responde en una sola frase.",
    },
    {
        "role": "user",
        "content": "Nombra tres tipos de indicador de compromiso usados en CTI.",
    },
]

OK = "[ok]"
FAIL = "[--]"
WARN = "[!!]"


def check_config() -> Config:
    config = load_config()
    print(f"{OK} config.yaml valido (hash {config.config_hash})")
    print(f"     analista: {config.models.analyst}")
    print(f"     juez:     {config.models.judge}")
    print(f"     seed={config.seed} temperature={config.generation.temperature}")

    missing = [
        str(path)
        for path in (config.analyst.system_prompt, config.judge.system_prompt)
        if not config.resolve(path).is_file()
    ]
    if missing:
        print(f"{WARN} prompts pendientes (Fase 2 / Fase 4): {', '.join(missing)}")
    return config


def probe_model(client: OllamaClient, model: str) -> dict[str, object]:
    """Dos llamadas identicas al mismo modelo para comparar salida y latencia."""
    result: dict[str, object] = {"model": model, "available": False}

    if not client.has_model(model):
        print(f"{FAIL} {model}: no descargado  ->  ollama pull {model}")
        return result

    result["available"] = True
    try:
        first = client.chat(PROBE_MESSAGES, model=model)
        second = client.chat(PROBE_MESSAGES, model=model)
    except OllamaError as error:
        print(f"{FAIL} {model}: {error}")
        result["error"] = str(error)
        return result

    deterministic = first.content.strip() == second.content.strip()
    tokens = second.completion_tokens or 0
    tokens_per_s = round(tokens / (second.latency_ms / 1000), 2) if tokens else None
    result.update(
        {
            "latency_cold_ms": first.latency_ms,
            "latency_warm_ms": second.latency_ms,
            "completion_tokens": second.completion_tokens,
            "tokens_per_s": tokens_per_s,
            "deterministic": deterministic,
        }
    )

    mark = OK if deterministic else WARN
    print(
        f"{mark} {model}: {first.latency_ms} ms (frio) / {second.latency_ms} ms (caliente)"
        f" - {tokens_per_s} tok/s - determinista: {'si' if deterministic else 'NO'}"
    )
    if not deterministic:
        print("     las dos respuestas difieren con la misma semilla; revisar antes de medir")
    return result


def write_report(
    config: Config, results: list[dict[str, object]], report_path: Path
) -> Path:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# Reporte de setup (Fase 0)",
        "",
        f"Generado: {stamp}  ",
        f"Hash de configuracion: `{config.config_hash}`  ",
        f"Equipo: {hardware_summary()}",
        "",
        "| Modelo | Disponible | Latencia frio (ms) | Latencia caliente (ms) | Tokens | tok/s | Determinista |",
        "|---|---|---|---|---|---|---|",
    ]
    for item in results:
        if not item.get("available"):
            lines.append(f"| `{item['model']}` | no | - | - | - | - | - |")
            continue
        deterministic = item.get("deterministic")
        lines.append(
            f"| `{item['model']}` | si | {item.get('latency_cold_ms', '-')} | "
            f"{item.get('latency_warm_ms', '-')} | {item.get('completion_tokens', '-')} | "
            f"{item.get('tokens_per_s', '-')} | {'si' if deterministic else 'NO'} |"
        )

    lines += [
        "",
        "La latencia en caliente es la que sirve para estimar cuanto dura un",
        "experimento: en una corrida larga el modelo ya esta cargado en memoria.",
        "",
    ]
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Verificacion de setup (Fase 0)")
    parser.add_argument("--quick", action="store_true", help="solo el modelo analista")
    parser.add_argument("--no-llm", action="store_true", help="no llamar a Ollama")
    parser.add_argument(
        "--out",
        type=Path,
        help="donde escribir el reporte (por defecto results/setup_report.md)",
    )
    args = parser.parse_args()

    # results/setup_report.md tiene analisis escrito a mano (hallazgos de hardware,
    # presupuesto de computo). Medir en otro equipo no debe borrarlo sin querer.
    default_report = project_root() / "results" / "setup_report.md"
    report_path = args.out if args.out else default_report
    if not report_path.is_absolute():
        report_path = project_root() / report_path
    if args.out is None and default_report.exists() and not args.no_llm:
        print(
            f"{FAIL} {default_report.relative_to(project_root())} ya existe y tiene "
            "analisis escrito a mano.\n"
            "     Usa --out para escribir en otro archivo, p. ej.:\n"
            "     python scripts/check_setup.py --out results/setup_report_<equipo>.md"
        )
        return 1

    config = check_config()
    if args.no_llm:
        return 0

    client = OllamaClient(config)
    print()
    if not client.is_up():
        print(f"{FAIL} Ollama no responde en {config.ollama.host}")
        print("     instalalo desde https://ollama.com/download y deja `ollama serve` corriendo")
        return 1

    print(f"{OK} Ollama {client.version()} en {config.ollama.host}")
    installed = client.list_models()
    print(f"     modelos instalados: {', '.join(installed) if installed else 'ninguno'}")
    print()

    models = [config.models.analyst] if args.quick else list(
        dict.fromkeys([*config.models.compare, config.models.judge])
    )
    results = [probe_model(client, model) for model in models]

    report_path = write_report(config, results, report_path)
    print(f"\n{OK} reporte escrito en {report_path.relative_to(project_root())}")

    usable = [r for r in results if r.get("available") and not r.get("error")]
    if not usable:
        return 1
    if not all(r.get("deterministic") for r in usable):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
