"""Medicion de capacidad: cuanto cuesta UNA analisis real (Fase 0).

La prueba corta de check_setup.py no sirve para planear los experimentos: el
analista procesa reportes de miles de tokens y devuelve JSON largo. Este script
manda un reporte sintetico del tamano tipico, mide el costo por etapa y estima
cuantas corridas caben en una tarde.

Uso:
    python scripts/bench_analyst.py                      # modelo analista
    python scripts/bench_analyst.py --model mistral:7b-instruct
    python scripts/bench_analyst.py --report-tokens 3000
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aitm.config import load_config  # noqa: E402
from aitm.llm.ollama_client import OllamaClient, OllamaError  # noqa: E402

SYSTEM_PROMPT = """Eres un analista de inteligencia de amenazas. Extrae los
indicadores de compromiso del reporte, clasifica cada uno como malicious,
suspicious o benign, identifica las tecnicas MITRE ATT&CK y asigna una
severidad. Responde unicamente con el objeto JSON pedido."""

# Parrafo de relleno con IoCs realistas: imita la densidad de un reporte de
# vendor. Se repite hasta alcanzar el tamano objetivo.
PARAGRAPH = """The campaign began with spearphishing emails carrying a
macro-enabled attachment named invoice_2024.docm. Once opened, the macro reached
out to hxxps://cdn-update-delivery[.]com/p/loader.ps1 and executed the payload in
memory via PowerShell. The loader resolved its command and control channel to
185.220.101.47 over port 443 and fell back to backup-sync[.]net when the primary
host was unavailable. Persistence was established through a scheduled task named
MicrosoftEdgeUpdateTaskUser. The dropped binary had SHA-256
9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 and was signed
with a stolen certificate. Analysts also observed credential dumping against
LSASS and lateral movement over SMB to the file server at 10.14.22.8. The actor
exfiltrated archives to data-backup-service[.]org using HTTPS. Related samples
reference CVE-2023-23397 and the operator mailbox support@cdn-update-delivery[.]com.
"""

JSON_SCHEMA_HINT = """Formato exacto:
{"report_id": str, "summary": str, "severity": "critical|high|medium|low|info",
 "iocs": [{"value": str, "type": str, "verdict": "malicious|suspicious|benign",
           "confidence": float, "evidence": str}],
 "mitre_attack": [{"technique_id": str, "technique_name": str, "confidence": float}],
 "threat_actor": str|null, "notes": []}"""


def build_report(target_tokens: int) -> str:
    """Reporte sintetico de aproximadamente `target_tokens` tokens (~4 chars/token)."""
    target_chars = target_tokens * 4
    repetitions = max(1, target_chars // len(PARAGRAPH))
    sections = [
        f"## Section {i + 1}\n\n{PARAGRAPH}" for i in range(repetitions)
    ]
    return "# Threat Report ACME-2026-001\n\n" + "\n".join(sections)


def ns_to_s(value: object) -> float:
    return float(value or 0) / 1e9


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark de una analisis real")
    parser.add_argument("--model", default=None, help="modelo a medir")
    parser.add_argument("--report-tokens", type=int, default=2000)
    args = parser.parse_args()

    config = load_config()
    client = OllamaClient(config)
    model = args.model or config.models.analyst

    report = build_report(args.report_tokens)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"{JSON_SCHEMA_HINT}\n\nREPORTE:\n{report}"},
    ]

    print(f"modelo: {model}")
    print(f"reporte sintetico: {len(report)} chars (~{len(report) // 4} tokens)")
    print("analizando (puede tardar varios minutos en CPU)...\n")

    try:
        response = client.chat(messages, model=model, response_format="json")
    except OllamaError as error:
        print(f"[--] {error}")
        return 1

    raw = response.raw
    load_s = ns_to_s(raw.get("load_duration"))
    prompt_s = ns_to_s(raw.get("prompt_eval_duration"))
    gen_s = ns_to_s(raw.get("eval_duration"))
    total_s = response.latency_ms / 1000

    prompt_tokens = response.prompt_tokens or 0
    completion_tokens = response.completion_tokens or 0

    print(f"total:            {total_s:7.1f} s")
    print(f"  carga modelo:   {load_s:7.1f} s")
    print(f"  leer prompt:    {prompt_s:7.1f} s  ({prompt_tokens} tokens"
          f", {prompt_tokens / prompt_s if prompt_s else 0:.1f} tok/s)")
    print(f"  generar JSON:   {gen_s:7.1f} s  ({completion_tokens} tokens"
          f", {completion_tokens / gen_s if gen_s else 0:.1f} tok/s)")

    try:
        parsed = json.loads(response.content)
        print(f"\n[ok] JSON valido: {len(parsed.get('iocs', []))} IoCs, "
              f"severidad {parsed.get('severity')}")
    except json.JSONDecodeError as error:
        print(f"\n[!!] la respuesta no es JSON parseable: {error}")

    print("\n--- capacidad estimada ---")
    per_run_min = total_s / 60
    print(f"una corrida: {per_run_min:.1f} min")
    for label, runs in (("sesion de 4 h", 240), ("dia completo 10 h", 600)):
        print(f"{label}: ~{int(runs / per_run_min)} corridas")
    print("\nMatriz completa = reportes x (1 limpio + vectores x objetivos) x defensas x modelos")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
