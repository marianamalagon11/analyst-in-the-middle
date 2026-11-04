"""Subcomandos de la Fase 4 que no necesitan al LLM.

```bash
aitm sanitize-check            # sanitizador contra toda la matriz envenenada + costo en limpios
aitm sanitize-check --table results/tables/sanitizer_coverage.md
```

`sanitize-check` responde, sin inferencia, la pregunta de la Fase 4: **¿que vectores
neutraliza el sanitizador por completo y cuales no?** Para cada reporte envenenado del
manifiesto de la Fase 3 mira si el marcador del payload llega al texto con el parser
ingenuo y si sigue ahi despues de sanitizar. Ademas pasa el sanitizador por los
reportes limpios para medir su costo: en un documento sin nada oculto deberia
devolver exactamente el mismo texto.
"""

from __future__ import annotations

import csv
import io
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory

from aitm.analyst.parsers import normalize_text, parse_pdf
from aitm.attacks.base import PoisonManifestEntry
from aitm.attacks.registry import get_vector
from aitm.attacks.verify import naive_extract
from aitm.config import load_config
from aitm.defenses.sanitizer import sanitize_document
from aitm.evaluation.traces import utc_now

OK, FAIL, WARN = "[ok]", "[--]", "[!!]"


def register(sub) -> None:
    check = sub.add_parser(
        "sanitize-check",
        help="mide que vectores neutraliza el sanitizador (sin LLM)",
    )
    check.add_argument("--manifest", help="manifiesto de envenenados (por defecto paths.poisoned)")
    check.add_argument("--table", help="escribe la tabla Markdown aqui (y el CSV al lado)")
    check.set_defaults(handler=cmd_sanitize_check)


def _verdict(reach: int, survived: int) -> str:
    if reach == 0:
        return "no aplica (no llega)"
    if survived == 0:
        return "**neutraliza**"
    if survived == reach:
        return "no neutraliza"
    return "parcial"


def _clean_body(source_format: str, data: bytes, tmp_dir: Path) -> str:
    """Texto ingenuo de un limpio, sin la cabecera de metadatos en PDF.

    Los PDF del dataset llevan metadatos legitimos (titulo, autor) que el parser
    ingenuo antepone al texto. Quitarlos es justo lo que hace el sanitizador, asi que el
    costo se mide sobre el cuerpo: ¿cambia algo del texto visible?
    """
    if source_format != "pdf":
        # En txt `naive_extract` devuelve el archivo crudo; el pipeline lo normaliza.
        return normalize_text(naive_extract(source_format, data, tmp_dir))
    path = tmp_dir / "clean.pdf"
    path.write_bytes(data)
    text, _ = parse_pdf(path, include_metadata=False)
    return text


def cmd_sanitize_check(args, argv) -> int:
    config = load_config()
    poisoned_root = config.resolve(config.paths.poisoned)
    manifest_path = Path(args.manifest) if args.manifest else poisoned_root / "manifest.jsonl"
    if not manifest_path.is_file():
        print(f"{FAIL} no existe {manifest_path}")
        return 1
    entries = [
        PoisonManifestEntry.model_validate_json(line)
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    missing = [e for e in entries if not (poisoned_root / e.poisoned_path).is_file()]
    if missing:
        print(
            f"{FAIL} faltan {len(missing)}/{len(entries)} documentos envenenados en {poisoned_root}.\n"
            "     Se regeneran con: python scripts/fetch_dataset.py && "
            "python scripts/build_dataset.py && aitm attack"
        )
        return 1

    # (vector, variante, formato) -> [n, llega, sobrevive]
    groups: dict[tuple[str, str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
    rows: list[dict[str, object]] = []
    clean_paths: dict[str, Path] = {}

    with TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for entry in entries:
            vector = get_vector(entry.injection.vector)
            data = (poisoned_root / entry.poisoned_path).read_bytes()
            markers = vector.extraction_markers(entry.injection.payload_text, entry.injection.variant)
            naive = naive_extract(entry.source_format, data, tmp_dir)
            cleaned = sanitize_document(entry.source_format, data, naive)
            reach = any(marker in naive for marker in markers)
            survived = any(marker in cleaned.text for marker in markers)

            key = (entry.injection.vector, entry.injection.variant, entry.source_format)
            groups[key][0] += 1
            groups[key][1] += int(reach)
            groups[key][2] += int(survived)
            rows.append(
                {
                    "poison_id": entry.poison_id,
                    "report_id": entry.report_id,
                    "format": entry.source_format,
                    "vector": entry.injection.vector,
                    "variant": entry.injection.variant,
                    "visibility": entry.injection.visibility,
                    "goal": entry.goal,
                    "reaches_naive": reach,
                    "survives_sanitizer": survived,
                    "removed_chars": cleaned.removed_chars,
                    "actions": "; ".join(cleaned.actions),
                }
            )
            clean_paths.setdefault(f"{entry.report_id}|{entry.source_format}", config.resolve(Path(entry.clean_path)))

        # Costo en los limpios: ¿cambia el texto visible?
        cost: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])  # formato -> [n, identicos, chars]
        changed: list[str] = []
        for key, path in sorted(clean_paths.items()):
            fmt = key.split("|")[1]
            if not path.is_file():
                continue
            data = path.read_bytes()
            body = _clean_body(fmt, data, tmp_dir)
            cleaned = sanitize_document(fmt, data, body)
            identical = cleaned.text == body
            cost[fmt][0] += 1
            cost[fmt][1] += int(identical)
            cost[fmt][2] += max(0, len(body) - len(cleaned.text))
            if not identical:
                changed.append(f"{key}: {'; '.join(cleaned.actions) or 'normalizacion'}")

    lines = [
        "# Cobertura del sanitizador por vector",
        "",
        f"Generado: {utc_now()} con `aitm sanitize-check` · config `{config.config_hash}` · "
        f"{len(entries)} reportes envenenados (`{manifest_path.name}`).",
        "",
        "Un payload *llega* si su marcador aparece en el texto del parser ingenuo (el de la",
        "línea base) y *sobrevive* si sigue ahí después de sanitizar. Sin LLM: mide la",
        "extracción, no el efecto en el modelo (eso es la Fase 5).",
        "",
        "| Vector | Variante | Formato | Envenenados | Llega (ingenuo) | Sobrevive (sanitizado) | Resultado |",
        "|---|---|---|---|---|---|---|",
    ]
    for (vector, variant, fmt), (n, reach, survived) in sorted(groups.items()):
        lines.append(
            f"| `{vector}` | `{variant}` | {fmt} | {n} | {reach} | {survived} | {_verdict(reach, survived)} |"
        )

    by_vector: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for (vector, _, _), (_, reach, survived) in groups.items():
        by_vector[vector][0] += reach
        by_vector[vector][1] += survived
    lines += [
        "",
        "## Resumen por vector",
        "",
        "| Vector | Llega | Sobrevive | Neutralizado |",
        "|---|---|---|---|",
    ]
    for vector, (reach, survived) in sorted(by_vector.items()):
        share = f"{(reach - survived) / reach:.0%}" if reach else "-"
        lines.append(f"| `{vector}` | {reach} | {survived} | {share} |")

    lines += [
        "",
        "## Costo en reportes limpios",
        "",
        "Texto visible del limpio con el parser ingenuo (en PDF, sin la cabecera de",
        "metadatos) contra el texto sanitizado. Idéntico = el sanitizador no cambia nada",
        "de lo que el modelo debería leer.",
        "",
        "| Formato | Limpios | Idénticos | Caracteres quitados |",
        "|---|---|---|---|",
    ]
    for fmt, (n, identical, chars) in sorted(cost.items()):
        lines.append(f"| {fmt} | {n} | {identical} | {chars} |")
    if changed:
        lines += ["", "Limpios que cambian:", "", *[f"- {item}" for item in changed]]
    lines.append("")
    report = "\n".join(lines)

    print(report)
    if args.table:
        destination = config.resolve(Path(args.table))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(report, encoding="utf-8")
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
        destination.with_suffix(".csv").write_text(buffer.getvalue(), encoding="utf-8")
        print(f"{OK} {destination} (+ .csv)")
    return 0
