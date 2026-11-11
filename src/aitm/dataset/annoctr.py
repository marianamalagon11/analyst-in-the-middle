"""Acceso al corpus AnnoCTR ya descargado en `data/raw/annoctr/`.

Encapsula el formato del corpus (nombres de archivo, anotaciones en JSON Lines con
extension `.json`) para que el resto del proyecto no tenga que conocerlo. Si algun dia
cambiamos de fuente, se escribe otro modulo con estas mismas tres funciones.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

#: `zscaler_2019-09-12_innfirat-new-rat-aiming-your`
_NAME = re.compile(r"^(?P<vendor>[a-z0-9]+)_(?P<date>\d{4}-\d{2}-\d{2})_(?P<slug>.+)$")

#: Enlaces de ATT&CK: `/techniques/T1574` o `/techniques/T1574/002`
_TECHNIQUE = re.compile(r"/techniques/(T\d{4})(?:/(\d{3}))?", re.I)

CORPUS_SUBDIR = "annoctr"
TEXT_SUBDIR = "AnnoCTR/all/text"
MITRE_SUBDIR = "AnnoCTR/all/linking_mitre_only"
SPLITS_FILE = "AnnoCTR/all/splits.tsv"


@dataclass(frozen=True)
class CorpusReport:
    """Un reporte del corpus, con lo que se puede saber antes de analizarlo."""

    report_id: str
    vendor: str
    published: str | None
    slug: str
    text_path: Path
    mitre_path: Path | None

    @property
    def has_mitre_annotations(self) -> bool:
        return self.mitre_path is not None

    def read_text(self) -> str:
        return self.text_path.read_text(encoding="utf-8", errors="replace")


def corpus_root(data_raw: Path) -> Path:
    return Path(data_raw) / CORPUS_SUBDIR


def _parse_name(stem: str) -> tuple[str, str | None, str]:
    match = _NAME.match(stem)
    if not match:
        return stem.split("_")[0], None, stem
    return match["vendor"], match["date"], match["slug"]


def load_corpus(data_raw: Path) -> list[CorpusReport]:
    """Lista los reportes disponibles. Falla si el corpus no se ha descargado."""
    root = corpus_root(data_raw)
    text_dir = root / TEXT_SUBDIR
    if not text_dir.is_dir():
        raise FileNotFoundError(
            f"no existe {text_dir}. Corre primero: python scripts/fetch_dataset.py"
        )

    mitre_dir = root / MITRE_SUBDIR
    reports: list[CorpusReport] = []
    for path in sorted(text_dir.glob("*.txt")):
        vendor, published, slug = _parse_name(path.stem)
        mitre_path = mitre_dir / f"{path.stem}.json"
        # Los 400 archivos de anotacion existen, pero solo ~117 tienen contenido:
        # son los que un experto anoto con la capa de ciberseguridad.
        annotated = mitre_path.is_file() and mitre_path.stat().st_size > 50
        reports.append(
            CorpusReport(
                report_id=path.stem,
                vendor=vendor,
                published=published,
                slug=slug,
                text_path=path,
                mitre_path=mitre_path if annotated else None,
            )
        )
    return reports


def read_mitre_annotations(path: Path) -> list[dict[str, str]]:
    """Lee las anotaciones de un documento.

    Los archivos traen extension `.json` pero son JSON Lines (una mencion por linea),
    asi que hay que leerlos linea a linea.
    """
    rows: list[dict[str, str]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def techniques_of(path: Path) -> list[dict[str, str]]:
    """Tecnicas ATT&CK anotadas en un documento, deduplicadas y ordenadas.

    Se conserva el id mas especifico: si el anotador marco `T1574/002` y tambien
    `T1574`, el ground truth lleva la subtecnica.
    """
    found: dict[str, str] = {}
    for row in read_mitre_annotations(path):
        if row.get("entity_type") != "TECHNIQUE":
            continue
        match = _TECHNIQUE.search(row.get("label_link", ""))
        if not match:
            continue
        base, sub = match.group(1).upper(), match.group(2)
        technique_id = f"{base}.{sub}" if sub else base
        found[technique_id] = row.get("label_title", "")

    specific = {
        technique_id
        for technique_id in found
        if "." not in technique_id
        and any(other.startswith(f"{technique_id}.") for other in found)
    }
    return [
        {"technique_id": technique_id, "technique_name": found[technique_id]}
        for technique_id in sorted(found)
        if technique_id not in specific
    ]


def actors_of(path: Path) -> list[str]:
    """Grupos de amenaza anotados (ATT&CK `GROUP`), en orden de aparicion."""
    actors: list[str] = []
    for row in read_mitre_annotations(path):
        if row.get("entity_type") == "GROUP":
            title = row.get("label_title", "").strip()
            if title and title not in actors:
                actors.append(title)
    return actors


def malware_of(path: Path) -> list[str]:
    """Familias de malware y herramientas anotadas. Entran en el resumen del reporte."""
    names: list[str] = []
    for row in read_mitre_annotations(path):
        if row.get("entity_type") in ("MALWARE", "TOOL"):
            title = row.get("label_title", "").strip()
            if title and title not in names:
                names.append(title)
    return names
