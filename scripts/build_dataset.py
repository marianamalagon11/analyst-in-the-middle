"""Selecciona los reportes del laboratorio y los renderiza a txt, html y pdf.

De los 400 reportes de AnnoCTR solo usamos un punado: cada analisis cuesta ~8 minutos
en el equipo del proyecto (ver `results/setup_report.md`) y el etiquetado es manual.
La seleccion tiene que ser por tanto explicita, reproducible y defendible en el
informe, no "los primeros doce".

Filtros duros:

- **Tiene anotaciones ATT&CK de experto** (117 de los 400). Nos ahorra inventar el
  ground truth de tecnicas, que es la parte mas discutible de etiquetar a mano.
- **Longitud en una ventana util.** Muy corto no tiene suficientes IoCs; muy largo
  encarece cada corrida y se acerca al limite de contexto de 8192 tokens.
- **Densidad minima de IoCs.** Un reporte sin indicadores no sirve para medir si el
  ataque logro ocultar uno.

Luego se ordena por densidad de IoCs, con un tope por vendor para que el dataset no
sea "el estilo de redaccion de Zscaler".

Uso:
    python scripts/build_dataset.py              # 12 reportes, los tres formatos
    python scripts/build_dataset.py --n 20
    python scripts/build_dataset.py --dry-run    # solo muestra la seleccion
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aitm.analyst import iocs as ioc_module  # noqa: E402
from aitm.analyst.parsers import parse  # noqa: E402
from aitm.config import load_config  # noqa: E402
from aitm.dataset import annoctr  # noqa: E402
from aitm.dataset.render import render_html, render_pdf, render_txt  # noqa: E402

DEFAULT_N = 12
MIN_CHARS = 4_000
MAX_CHARS = 14_000
MIN_IOCS = 3
MIN_IOC_TYPES = 2
MAX_PER_VENDOR = 4

#: Banda util de indicadores por reporte. No se busca el maximo: un reporte con 100
#: IoCs son 100 indicadores que una persona tiene que revisar a mano y un JSON de
#: salida de miles de tokens a 2,9 tok/s (ver results/setup_report.md). Con ~16 hay de
#: sobra para medir si el ataque logro voltear o esconder uno.
TARGET_IOCS = 16
MAX_IOCS = 45

FORMATS = ("txt", "html", "pdf")

HARD_TYPES = ("md5", "sha1", "sha256", "ipv4", "ipv6")


def score(counts: dict[str, int]) -> float:
    """Que tan util es un reporte para el laboratorio.

    Tres terminos: cercania a la banda objetivo de IoCs, variedad de tipos (un reporte
    con dominios, hashes e IPs ejercita mas el analista que uno con 20 dominios) y
    presencia de indicadores "duros". Los hashes y las IPs valen mas porque son
    inequivocos: no se confunden con la infraestructura legitima que cita el texto.
    """
    total = sum(counts.values())
    variety = len(counts)
    hard = sum(counts.get(kind, 0) for kind in HARD_TYPES)
    return -abs(total - TARGET_IOCS) + 2 * variety + 1.5 * min(hard, 10)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Construye el dataset del laboratorio")
    parser.add_argument("--n", type=int, default=DEFAULT_N, help="reportes a elegir")
    parser.add_argument("--min-chars", type=int, default=MIN_CHARS)
    parser.add_argument("--max-chars", type=int, default=MAX_CHARS)
    parser.add_argument("--max-per-vendor", type=int, default=MAX_PER_VENDOR)
    parser.add_argument(
        "--pin",
        action="append",
        default=[],
        metavar="REPORT_ID",
        help="incluye este reporte si pasa los filtros duros (repetible)",
    )
    parser.add_argument("--dry-run", action="store_true", help="no escribe nada")
    parser.add_argument(
        "--force",
        action="store_true",
        help="reconstruye aunque ya haya etiquetas revisadas",
    )
    args = parser.parse_args()

    config = load_config()
    data_raw = config.resolve(config.paths.data_raw)
    processed = config.resolve(config.paths.data_processed)
    labels_dir = config.resolve(config.paths.labels)

    # Reconstruir el dataset despues de empezar a etiquetar cambia la seleccion y deja
    # el trabajo manual huerfano. Mejor fallar que perderlo.
    if not args.dry_run and not args.force:
        revised = sorted(
            path.stem
            for path in labels_dir.glob("*.json")
            if '"status": "draft"' not in path.read_text(encoding="utf-8")
        )
        if revised:
            print(
                f"[--] ya hay {len(revised)} etiquetas revisadas en {labels_dir}.\n"
                "     Reconstruir el dataset puede cambiar la seleccion y dejarlas "
                "huerfanas.\n     Si de verdad quieres rehacerlo: --force"
            )
            return 1

    reports = annoctr.load_corpus(data_raw)
    print(f"corpus: {len(reports)} reportes")

    candidates = []
    rejected = {
        "sin_anotaciones": 0,
        "longitud": 0,
        "pocos_iocs": 0,
        "demasiados_iocs": 0,
    }
    for report in reports:
        if not report.has_mitre_annotations:
            rejected["sin_anotaciones"] += 1
            continue
        text = report.read_text()
        if not args.min_chars <= len(text) <= args.max_chars:
            rejected["longitud"] += 1
            continue
        found = ioc_module.extract(text, include_noise=False)
        counts = ioc_module.summarize(found)
        total_iocs = sum(counts.values())
        if total_iocs < MIN_IOCS or len(counts) < MIN_IOC_TYPES:
            rejected["pocos_iocs"] += 1
            continue
        if total_iocs > MAX_IOCS:
            rejected["demasiados_iocs"] += 1
            continue
        techniques = annoctr.techniques_of(report.mitre_path)
        candidates.append(
            {
                "report": report,
                "text": text,
                "counts": counts,
                "n_iocs": sum(counts.values()),
                "techniques": techniques,
                "score": score(counts),
            }
        )

    print(
        f"descartados: {rejected['sin_anotaciones']} sin anotaciones ATT&CK, "
        f"{rejected['longitud']} fuera de [{args.min_chars}, {args.max_chars}] caracteres, "
        f"{rejected['pocos_iocs']} con menos de {MIN_IOCS} IoCs o {MIN_IOC_TYPES} tipos, "
        f"{rejected['demasiados_iocs']} con mas de {MAX_IOCS} IoCs"
    )
    print(f"candidatos: {len(candidates)}")

    candidates.sort(key=lambda item: (-item["score"], item["report"].report_id))

    # Los reportes fijados a mano van primero: sirven para conservar un caso concreto
    # entre reconstrucciones (p. ej. una campana contra Colombia para la sustentacion).
    pinned = set(args.pin)
    missing_pins = pinned - {item["report"].report_id for item in candidates}
    if missing_pins:
        print(f"[!!] estos --pin no pasan los filtros duros y se ignoran: {sorted(missing_pins)}")
    candidates.sort(
        key=lambda item: (
            item["report"].report_id not in pinned,
            -item["score"],
            item["report"].report_id,
        )
    )

    selected: list[dict] = []
    per_vendor: dict[str, int] = {}
    for candidate in candidates:
        # El tope por vendor no se aplica a lo fijado a mano: es una decision explicita.
        if candidate["report"].report_id in pinned:
            selected.append(candidate)
            vendor = candidate["report"].vendor
            per_vendor[vendor] = per_vendor.get(vendor, 0) + 1
            if len(selected) == args.n:
                break
            continue
        vendor = candidate["report"].vendor
        if per_vendor.get(vendor, 0) >= args.max_per_vendor:
            continue
        selected.append(candidate)
        per_vendor[vendor] = per_vendor.get(vendor, 0) + 1
        if len(selected) == args.n:
            break

    if len(selected) < args.n:
        print(f"[!!] solo se pudieron elegir {len(selected)} de {args.n} reportes")

    print(f"\nseleccionados ({len(selected)}), por vendor: {per_vendor}")
    print(f"{'report_id':58} {'chars':>6} {'~tok':>5} {'IoCs':>4} {'ATT&CK':>6}")
    for item in selected:
        report = item["report"]
        print(
            f"{report.report_id[:58]:58} {len(item['text']):6} "
            f"{len(item['text']) // 4:5} {item['n_iocs']:4} {len(item['techniques']):6}"
        )

    if args.dry_run:
        print("\n[dry-run] no se escribio nada")
        return 0

    entries = []
    for item in selected:
        report = item["report"]
        text = item["text"]
        source_values = {ioc.value for ioc in ioc_module.extract(text)}
        files: dict[str, dict[str, object]] = {}

        for source_format in FORMATS:
            directory = processed / source_format
            directory.mkdir(parents=True, exist_ok=True)
            destination = directory / f"{report.report_id}.{source_format}"
            if source_format == "txt":
                destination.write_text(render_txt(text), encoding="utf-8", newline="\n")
            elif source_format == "html":
                destination.write_text(
                    render_html(text, report_id=report.report_id),
                    encoding="utf-8",
                    newline="\n",
                )
            else:
                render_pdf(text, destination, report_id=report.report_id)

            # Fidelidad del formato: cuantos de los IoCs del texto original
            # sobreviven al render y a la extraccion. El PDF pierde algunos por el
            # salto de linea en URLs muy largas; conviene saberlo antes de leer las
            # metricas de la Fase 2 y no confundirlo con un fallo del modelo.
            recovered = {ioc.value for ioc in ioc_module.extract(parse(destination).text)}
            files[source_format] = {
                "path": str(destination.relative_to(processed.parent.parent)).replace(
                    "\\", "/"
                ),
                "sha256": sha256_of(destination),
                "bytes": destination.stat().st_size,
                "iocs_recovered": len(source_values & recovered),
                "iocs_lost": sorted(source_values - recovered),
            }

        entries.append(
            {
                "report_id": report.report_id,
                "vendor": report.vendor,
                "published": report.published,
                "chars": len(text),
                "approx_tokens": len(text) // 4,
                "ioc_counts": item["counts"],
                "n_iocs": item["n_iocs"],
                "n_techniques": len(item["techniques"]),
                "selection_score": round(item["score"], 2),
                "files": files,
            }
        )

    corpus_manifest = json.loads(
        (annoctr.corpus_root(data_raw) / "manifest.json").read_text(encoding="utf-8")
    )
    manifest = {
        "built_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "config_hash": config.config_hash,
        "corpus": {
            "name": corpus_manifest["corpus"],
            "commit": corpus_manifest["commit"],
            "license": corpus_manifest["license"],
            "citation": corpus_manifest["citation"],
        },
        "selection": {
            "n": len(entries),
            "min_chars": args.min_chars,
            "max_chars": args.max_chars,
            "min_iocs": MIN_IOCS,
            "min_ioc_types": MIN_IOC_TYPES,
            "max_per_vendor": args.max_per_vendor,
            "requires_mitre_annotations": True,
            "candidates": len(candidates),
            "pinned": sorted(pinned),
        },
        "formats": list(FORMATS),
        "reports": entries,
    }
    manifest_path = processed / "dataset.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    total_tokens = sum(entry["approx_tokens"] for entry in entries)
    print(f"\n[ok] {len(entries)} reportes x {len(FORMATS)} formatos en {processed}")
    print(f"[ok] manifiesto en {manifest_path}")
    print(f"[ok] ~{total_tokens} tokens de entrada en total por pasada del dataset")
    lost = {
        source_format: sum(
            len(entry["files"][source_format]["iocs_lost"]) for entry in entries
        )
        for source_format in FORMATS
    }
    print(f"[ok] IoCs perdidos en el render por formato: {lost}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
