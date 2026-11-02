"""Descarga reproducible del corpus AnnoCTR a `data/raw/annoctr/`.

AnnoCTR (Lange et al., LREC-COLING 2024) son 400 reportes CTI de cinco vendors, con el
texto completo y, en 120 de ellos, anotaciones de experto enlazadas a MITRE ATT&CK.
Licencia CC-BY-SA 4.0, que es lo que lo hace usable aqui: ver docs/DATASET.md.

El repositorio se descarga **fijado a un commit**, no a `main`, para que dos personas
del equipo que corran esto en semanas distintas obtengan exactamente el mismo corpus.
El commit, el sha256 del archivo y el inventario quedan en `manifest.json`.

Uso:
    python scripts/fetch_dataset.py                  # descarga e instala el corpus
    python scripts/fetch_dataset.py --archive x.zip  # usa un zip ya descargado
    python scripts/fetch_dataset.py --keep-archive    # no borra el zip de 88 MB
    python scripts/fetch_dataset.py --force           # vuelve a extraer todo
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import requests  # noqa: E402

from aitm.config import load_config  # noqa: E402

REPO = "boschresearch/anno-ctr-lrec-coling-2024"

#: Commit fijado. El repositorio no ha cambiado desde la publicacion del articulo
#: (2024-04-12); si alguna vez hiciera falta actualizarlo, se cambia aqui a proposito
#: y se vuelve a congelar el dataset.
PINNED_COMMIT = "d510b6949e1938d47c93a43eedd562dc538439dc"

LICENSE = "CC-BY-SA-4.0"
CITATION = (
    "Lange, L., Muller, M., Torbati, G. H., Pujari, S. C., Grau, P., et al. (2024). "
    "AnnoCTR: A Dataset for Detecting and Linking Entities, Tactics, and Techniques "
    "in Cyber Threat Reports. LREC-COLING 2024."
)

#: Lo que se extrae del zip. El resto (anotaciones NER, TimeML, splits de linking
#: generales) no lo necesita este proyecto y son decenas de MB.
WANTED_PREFIXES = (
    "AnnoCTR/all/text/",
    "AnnoCTR/all/linking_mitre_only/",
)
WANTED_FILES = ("AnnoCTR/all/splits.tsv",)

CHUNK = 1 << 20


def archive_url(commit: str) -> str:
    return f"https://codeload.github.com/{REPO}/zip/{commit}"


def download(url: str, destination: Path) -> Path:
    """Descarga mostrando progreso, a un archivo temporal que luego se renombra."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    print(f"descargando {url}")
    with requests.get(url, stream=True, timeout=120) as response:
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))
        done = 0
        with temporary.open("wb") as handle:
            for chunk in response.iter_content(chunk_size=CHUNK):
                handle.write(chunk)
                done += len(chunk)
                if total:
                    print(f"\r  {done / 1048576:6.1f} / {total / 1048576:.1f} MB", end="")
                else:
                    print(f"\r  {done / 1048576:6.1f} MB", end="")
    print()
    temporary.replace(destination)
    return destination


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _wanted(member: str) -> bool:
    """El zip de GitHub prefija todo con `<repo>-<commit>/`; se compara sin ese prefijo."""
    inner = member.split("/", 1)[1] if "/" in member else member
    if inner in WANTED_FILES:
        return True
    if not inner.startswith(WANTED_PREFIXES):
        return False
    # De los cuatro variantes por documento (base, _w_con, _w_neg, _w_con_w_neg) solo
    # se necesita el base: los otros son para entrenar modelos de linking.
    if inner.startswith("AnnoCTR/all/linking_mitre_only/"):
        stem = Path(inner).stem
        return not stem.endswith(("_w_con", "_w_neg", "_w_con_w_neg"))
    return inner.endswith(".txt") or inner.endswith(".tsv")


def extract(archive: Path, target: Path, *, force: bool) -> list[str]:
    """Extrae solo lo necesario, protegiendo contra rutas que escapen del destino."""
    target.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with zipfile.ZipFile(archive) as bundle:
        members = [name for name in bundle.namelist() if not name.endswith("/")]
        for member in members:
            if not _wanted(member):
                continue
            inner = member.split("/", 1)[1]
            destination = (target / inner).resolve()
            if not str(destination).startswith(str(target.resolve())):
                raise RuntimeError(f"ruta sospechosa en el zip: {member}")
            if destination.exists() and not force:
                extracted.append(inner)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(member) as source, destination.open("wb") as handle:
                shutil.copyfileobj(source, handle)
            extracted.append(inner)
    return sorted(extracted)


def main() -> int:
    parser = argparse.ArgumentParser(description="Descarga el corpus AnnoCTR")
    parser.add_argument("--commit", default=PINNED_COMMIT, help="commit a descargar")
    parser.add_argument("--archive", type=Path, help="zip ya descargado")
    parser.add_argument("--keep-archive", action="store_true", help="no borrar el zip")
    parser.add_argument("--force", action="store_true", help="reextraer lo existente")
    args = parser.parse_args()

    config = load_config()
    target = config.resolve(config.paths.data_raw) / "annoctr"
    manifest_path = target / "manifest.json"

    if manifest_path.exists() and not args.force:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("commit") == args.commit:
            print(f"[ok] el corpus ya esta en {target} ({manifest['n_reports']} reportes)")
            print("     usa --force para volver a extraerlo")
            return 0

    archive = args.archive
    downloaded_here = False
    if archive is None:
        archive = target / f"annoctr-{args.commit[:12]}.zip"
        if not archive.exists():
            download(archive_url(args.commit), archive)
            downloaded_here = True
    if not archive.is_file():
        print(f"[--] no existe el archivo {archive}")
        return 1

    print(f"calculando sha256 de {archive.name}")
    archive_hash = sha256_of(archive)

    print(f"extrayendo a {target}")
    files = extract(archive, target, force=args.force)
    reports = [name for name in files if name.startswith("AnnoCTR/all/text/")]
    annotations = [
        name for name in files if name.startswith("AnnoCTR/all/linking_mitre_only/")
    ]

    manifest = {
        "corpus": "AnnoCTR",
        "repo": REPO,
        "commit": args.commit,
        "archive_sha256": archive_hash,
        "license": LICENSE,
        "citation": CITATION,
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "n_reports": len(reports),
        "n_mitre_annotations": len(annotations),
        "files": len(files),
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    if downloaded_here and not args.keep_archive:
        archive.unlink()
        print(f"[ok] zip borrado (usa --keep-archive para conservarlo)")

    print(f"[ok] {len(reports)} reportes, {len(annotations)} con anotaciones MITRE")
    print(f"[ok] manifiesto en {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
