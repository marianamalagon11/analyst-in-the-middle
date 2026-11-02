"""Genera borradores de ground truth para que el equipo solo revise y corrija.

Etiquetar a mano 12 reportes con ~20 indicadores cada uno es la tarea mas larga de la
Fase 1. Este script no la reemplaza: la reduce a decidir, porque deja cada indicador ya
extraido, normalizado, clasificado con una propuesta y **con la linea del reporte donde
aparece**, que es lo que de verdad cuesta encontrar a mano.

Lo que propone automaticamente y por que:

| Campo | Propuesta automatica | Quien decide de verdad |
|---|---|---|
| `iocs[].value/type` | extractor de regex, ya normalizado | revision (quitar falsos positivos) |
| `iocs[].verdict` | `malicious` si cae en una seccion de IoCs, `suspicious` si no | revision |
| `iocs[].notes` | la linea del reporte donde aparece | - |
| `excluded_iocs` | infraestructura del vendor, IPs internas, enlaces de referencia | revision |
| `mitre_attack` | anotaciones de experto de AnnoCTR | se puede confiar |
| `threat_actor` | anotacion `GROUP` de AnnoCTR | se puede confiar |
| `severity` | `medium` fijo, marcado como PENDIENTE | **siempre** la persona |

La severidad no se adivina: es un juicio sobre el impacto que el texto no codifica en
ningun campo. El borrador la deja en `medium` y lo anuncia en `notes` para que nadie la
de por buena sin leer.

Nunca sobreescribe un archivo existente sin `--force`: el trabajo manual del equipo no
se puede perder por volver a correr un script.

Uso:
    python scripts/draft_labels.py              # crea los que falten
    python scripts/draft_labels.py --force      # rehace todos (destruye revisiones)
    python scripts/draft_labels.py --report-id X
    python scripts/draft_labels.py --out data/labels_b --report-id X --report-id Y

`--out` existe para el acuerdo entre revisores: el segundo etiquetado tiene que partir
del borrador del extractor, **no** de una copia de `data/labels/`. Si parte de las
decisiones del primer anotador, el acuerdo que se mida sale inflado por anclaje.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from aitm.analyst import iocs as ioc_module  # noqa: E402
from aitm.config import load_config  # noqa: E402
from aitm.dataset import annoctr  # noqa: E402
from aitm.evaluation.labels import (  # noqa: E402
    ExcludedIoC,
    LabeledIoC,
    LabeledTechnique,
    LabelSource,
    ReportLabel,
    label_path,
    save_label,
)

#: Encabezados que marcan la seccion de indicadores en los reportes de vendor.
IOC_SECTION = re.compile(
    r"^\s*[#*\s]*(iocs?|indicators?(\s+of\s+compromise)?|hashes|appendix)\b", re.I
)

#: Dominios de prensa y de investigacion ajena: aparecen como enlaces de referencia.
REFERENCE_DOMAINS = frozenset(
    """
    fortune.com cybernews.com motionpictures.org deloitte.com hostingtribunal.com
    unit42.paloaltonetworks.com fortinet.com welivesecurity.com bleepingcomputer.com
    krebsonsecurity.com therecord.media zdnet.com wired.com reuters.com bbc.co.uk
    archive.org web.archive.org arxiv.org medium.com stackoverflow.com
    """.split()
)

SEVERITY_PLACEHOLDER = "medium"
PENDING_NOTE = (
    "PENDIENTE DE REVISION. La severidad es un valor por defecto, no una medicion: "
    "hay que fijarla leyendo el reporte. Los veredictos de los IoCs son propuestas del "
    "extractor. Al terminar, poner `status` en `reviewed` y llenar `annotators` y "
    "`reviewers` (personas distintas)."
)


def line_index(text: str) -> list[tuple[int, int, str]]:
    """(inicio, fin, linea) de cada linea, para ubicar un offset en su linea."""
    spans: list[tuple[int, int, str]] = []
    position = 0
    for line in text.split("\n"):
        spans.append((position, position + len(line), line))
        position += len(line) + 1
    return spans


#: Linea que funciona como encabezado en los textos de AnnoCTR: `### **IOCs**`,
#: `**Hashes:**`, `## Appendix`.
HEADING = re.compile(r"^\s*(#{1,6}\s+\S|\*\*[^*]{1,80}\*\*\s*:?\s*$)")


def evidence_for(spans: list[tuple[int, int, str]], offset: int) -> tuple[str, bool]:
    """Devuelve la linea donde cae el offset y si viene de una seccion de IoCs.

    Lo segundo se decide buscando el encabezado anterior mas cercano: un indicador
    listado bajo "IOCs" o "Hashes" es del caso casi por definicion, mientras que uno
    citado en medio de la narrativa puede ser cualquier cosa, incluido un enlace a
    otro articulo.
    """
    for index, (start, end, line) in enumerate(spans):
        if not start <= offset <= end:
            continue
        in_section = False
        for previous in range(index, -1, -1):
            candidate = spans[previous][2]
            if previous != index and HEADING.match(candidate):
                in_section = bool(IOC_SECTION.match(candidate))
                break
            if IOC_SECTION.match(candidate):
                in_section = True
                break
        return line.strip()[:200], in_section
    return "", False


def exclusion_reason(ioc: ioc_module.IoC) -> str | None:
    """Motivo por el que un indicador presente en el texto no es del caso, o None."""
    if ioc.is_internal_ip:
        return "internal_address"
    if ioc.is_noise:
        return "vendor_infrastructure"
    host = ioc_module.url_host(ioc.value) if ioc.type == "url" else ""
    if host:
        if ioc_module.registrable(host) in REFERENCE_DOMAINS or host in REFERENCE_DOMAINS:
            return "reference_only"
    if ioc.type == "domain" and ioc_module.registrable(ioc.value) in REFERENCE_DOMAINS:
        return "reference_only"
    return None


def build_draft(
    report: annoctr.CorpusReport, text: str, formats: list[str], license_name: str
) -> ReportLabel:
    # El indice de lineas se construye sobre el texto YA desofuscado, porque es sobre
    # ese sobre el que `extract()` devuelve los offsets. Construirlo sobre el original
    # desplazaba la evidencia: cada `[.]` que se vuelve `.` corre dos caracteres, y al
    # llegar a la tabla de IoCs la linea citada era la de la fila anterior.
    spans = line_index(ioc_module.refang(text))
    extracted = ioc_module.extract(text)

    included: list[LabeledIoC] = []
    excluded: list[ExcludedIoC] = []
    for ioc in extracted:
        reason = exclusion_reason(ioc)
        if reason:
            excluded.append(
                ExcludedIoC(
                    value=ioc.value,
                    type=ioc.type,
                    reason=reason,  # type: ignore[arg-type]
                    notes=f"propuesto por el extractor ({ioc.raw[:60]})",
                )
            )
            continue
        evidence, in_section = evidence_for(spans, ioc.start)
        included.append(
            LabeledIoC(
                value=ioc.value,
                type=ioc.type,
                verdict="malicious" if in_section else "suspicious",
                notes=evidence,
            )
        )

    techniques = [
        LabeledTechnique(**technique)
        for technique in annoctr.techniques_of(report.mitre_path)
    ] if report.has_mitre_annotations else []

    actors = annoctr.actors_of(report.mitre_path) if report.has_mitre_annotations else []

    return ReportLabel(
        report_id=report.report_id,
        source=LabelSource(
            corpus="AnnoCTR",
            file=f"AnnoCTR/all/text/{report.report_id}.txt",
            vendor=report.vendor,
            published=report.published,
            license=license_name,
        ),
        formats=formats,  # type: ignore[arg-type]
        status="draft",
        severity=SEVERITY_PLACEHOLDER,  # type: ignore[arg-type]
        threat_actor=actors[0] if actors else None,
        iocs=included,
        excluded_iocs=excluded,
        mitre_attack=techniques,
        notes=PENDING_NOTE,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Borradores de ground truth")
    parser.add_argument("--force", action="store_true", help="sobreescribe lo existente")
    parser.add_argument(
        "--report-id", action="append", help="solo este reporte (se puede repetir)"
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="carpeta de salida (por defecto paths.labels). Para el etiquetado ciego "
        "del acuerdo entre revisores: --out data/labels_b",
    )
    args = parser.parse_args()

    config = load_config()
    data_raw = config.resolve(config.paths.data_raw)
    processed = config.resolve(config.paths.data_processed)
    labels_dir = config.resolve(args.out) if args.out else config.resolve(config.paths.labels)

    dataset_path = processed / "dataset.json"
    if not dataset_path.is_file():
        print(f"[--] falta {dataset_path}. Corre primero: python scripts/build_dataset.py")
        return 1
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    wanted = {entry["report_id"] for entry in dataset["reports"]}
    if args.report_id:
        unknown = sorted(set(args.report_id) - wanted)
        if unknown:
            print(f"[--] no estan en el dataset: {unknown}")
            return 1
        wanted = set(args.report_id)

    corpus = {report.report_id: report for report in annoctr.load_corpus(data_raw)}
    license_name = dataset["corpus"]["license"]

    created, skipped = 0, 0
    totals = {"iocs": 0, "excluded": 0, "techniques": 0}
    for report_id in sorted(wanted):
        destination = label_path(labels_dir, report_id)
        if destination.exists() and not args.force:
            skipped += 1
            continue
        report = corpus[report_id]
        label = build_draft(
            report, report.read_text(), list(dataset["formats"]), license_name
        )
        save_label(label, destination)
        created += 1
        totals["iocs"] += len(label.iocs)
        totals["excluded"] += len(label.excluded_iocs)
        totals["techniques"] += len(label.mitre_attack)
        print(
            f"[ok] {report_id[:52]:52} {len(label.iocs):3} IoCs "
            f"({len(label.excluded_iocs):2} excluidos) {len(label.mitre_attack):2} ATT&CK"
        )

    print(f"\ncreados: {created}, ya existian (sin tocar): {skipped}")
    if created:
        print(
            f"a revisar: {totals['iocs']} indicadores, {totals['excluded']} exclusiones "
            f"y {created} severidades"
        )
        print(f"carpeta: {labels_dir}")
        print("valida con: python scripts/validate_labels.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
