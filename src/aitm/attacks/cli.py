"""Subcomando `aitm attack`: genera los reportes envenenados y su manifiesto.

Para cada combinación reporte × formato × vector × variante × objetivo × payload toma el
documento limpio de `data/processed/`, inyecta el payload, verifica que llegue al modelo
y (si es invisible) que se vea igual, y escribe el envenenado en `data/poisoned/` con una
entrada en `manifest.jsonl`. No llama al LLM: generar es barato; medir el ASR es la
Fase 5.

```bash
aitm attack                 # matriz completa: todos los vectores, variantes y objetivos
aitm attack --canonical     # solo el payload y la variante canónicos (matriz de la F5)
aitm attack --vectors html_hidden --goals flip_to_benign
```
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from aitm import __version__
from aitm.attacks.base import ATTACK_GOALS, PoisonManifestEntry, poison_id
from aitm.attacks.payloads import CANONICAL, get_payload, payloads_for
from aitm.attacks.registry import all_vectors, get_vector, vectors_for_format
from aitm.attacks.targets import targets_for_report
from aitm.attacks.verify import payload_reaches_model, visual_equivalent
from aitm.config import load_config
from aitm.evaluation.labels import iter_labels

OK, FAIL, WARN = "[ok]", "[--]", "[!!]"
_EXT = {"txt": "txt", "html": "html", "pdf": "pdf"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def register(sub) -> None:
    attack = sub.add_parser("attack", help="genera reportes envenenados (Fase 3)")
    attack.add_argument("--reports", nargs="*", help="report_ids (por defecto todos)")
    attack.add_argument("--vectors", nargs="*", help="vectores (por defecto todos)")
    attack.add_argument("--goals", nargs="*", choices=ATTACK_GOALS, help="objetivos (por defecto todos)")
    attack.add_argument("--formats", nargs="*", choices=["txt", "html", "pdf"])
    attack.add_argument(
        "--canonical",
        action="store_true",
        help="solo el payload canónico y la primera variante de cada vector (matriz F5)",
    )
    attack.add_argument("--all-payloads", action="store_true", help="todos los payloads, no solo el canónico")
    attack.add_argument("--out", help="carpeta de salida (por defecto paths.poisoned)")
    attack.set_defaults(handler=cmd_attack)


def cmd_attack(args, argv) -> int:
    config = load_config()
    labels = {l.report_id: l for l in iter_labels(config.resolve(config.paths.labels))}
    if not labels:
        print(f"{FAIL} no hay etiquetas en {config.paths.labels}")
        return 1
    if not all(l.status == "frozen" for l in labels.values()):
        print(f"{WARN} el ground truth no está congelado: los objetivos pueden cambiar al congelar")

    processed = config.resolve(config.paths.data_processed)
    out_dir = config.resolve(Path(args.out)) if args.out else config.resolve(config.paths.poisoned)
    out_dir.mkdir(parents=True, exist_ok=True)

    report_ids = args.reports or sorted(labels)
    goals = tuple(args.goals) if args.goals else ATTACK_GOALS
    formats = args.formats or ["txt", "html", "pdf"]
    vector_names = args.vectors or [v.name for v in all_vectors()]

    manifest: list[PoisonManifestEntry] = []
    targets_dump: dict[str, dict[str, dict]] = {}
    stats = {"generated": 0, "reach": 0, "visual_checked": 0, "visual_ok": 0, "skipped_format": 0}
    per_vector: dict[str, int] = {}

    with TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        for report_id in report_ids:
            label = labels.get(report_id)
            if label is None:
                print(f"{WARN} sin etiqueta: {report_id}")
                continue
            targets = targets_for_report(label, goals)
            targets_dump[report_id] = {g: t.model_dump(exclude_none=True) for g, t in targets.items()}

            for fmt in formats:
                clean_path = processed / fmt / f"{report_id}.{_EXT[fmt]}"
                if not clean_path.is_file():
                    stats["skipped_format"] += 1
                    continue
                clean = clean_path.read_bytes()
                clean_sha = _sha(clean)

                for vector in vectors_for_format(fmt):
                    if vector.name not in vector_names:
                        continue
                    variants = (vector.variants[0],) if args.canonical else vector.variants
                    for goal, target in targets.items():
                        payload_ids = (
                            [CANONICAL[goal]]
                            if args.canonical or not args.all_payloads
                            else [p.payload_id for p in payloads_for(goal)]
                        )
                        for payload_id in payload_ids:
                            payload = get_payload(payload_id)
                            if not payload.supports(goal):
                                continue
                            text = payload.render(goal, target)
                            for variant in variants:
                                entry = _generate(
                                    vector, fmt, variant, goal, target, payload_id, text,
                                    clean, clean_sha, clean_path, report_id, out_dir, config, tmp_dir,
                                )
                                manifest.append(entry)
                                stats["generated"] += 1
                                per_vector[vector.name] = per_vector.get(vector.name, 0) + 1
                                if entry.payload_reaches_model:
                                    stats["reach"] += 1
                                if entry.visual_equivalent is not None:
                                    stats["visual_checked"] += 1
                                    stats["visual_ok"] += int(entry.visual_equivalent)

    _write(out_dir, manifest, targets_dump)
    _summary(out_dir, stats, per_vector, len(manifest))
    return 0


def _generate(
    vector, fmt, variant, goal, target, payload_id, text,
    clean, clean_sha, clean_path, report_id, out_dir, config, tmp_dir,
) -> PoisonManifestEntry:
    poisoned, location = vector.inject(clean, text, target, variant=variant)
    name = f"{report_id}__{goal}__{payload_id}__{variant}.{_EXT[fmt]}"
    dest = out_dir / vector.name / fmt / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(poisoned)

    markers = vector.extraction_markers(text, variant)
    reaches = payload_reaches_model(fmt, poisoned, markers, tmp_dir)
    visual = None
    if vector.visibility(variant) == "invisible":
        visual = visual_equivalent(fmt, clean, poisoned)

    from aitm.attacks.base import InjectionRecord

    return PoisonManifestEntry(
        poison_id=poison_id(report_id, fmt, vector.name, variant, goal, payload_id),
        report_id=report_id,
        source_format=fmt,
        goal=goal,
        target=target,
        injection=InjectionRecord(
            vector=vector.name,
            variant=variant,
            visibility=vector.visibility(variant),
            payload_id=payload_id,
            payload_text=text,
            location=location,
        ),
        clean_path=clean_path.relative_to(config.resolve(Path("."))).as_posix()
        if clean_path.is_relative_to(config.resolve(Path(".")))
        else str(clean_path),
        clean_sha256=clean_sha,
        poisoned_path=dest.relative_to(out_dir).as_posix(),
        poisoned_sha256=_sha(poisoned),
        payload_reaches_model=reaches,
        visual_equivalent=visual,
        generator_version=__version__,
        config_hash=config.config_hash,
    )


def _write(out_dir: Path, manifest, targets_dump) -> None:
    with (out_dir / "manifest.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for entry in manifest:
            handle.write(entry.model_dump_json() + "\n")
    (out_dir / "targets.json").write_text(
        json.dumps(targets_dump, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _summary(out_dir: Path, stats, per_vector, total) -> None:
    print(f"{OK} {total} reportes envenenados en {out_dir}")
    reach = stats["reach"]
    print(f"     payload llega al modelo: {reach}/{total} ({reach / total:.0%})" if total else "")
    if stats["visual_checked"]:
        vok, vc = stats["visual_ok"], stats["visual_checked"]
        mark = OK if vok == vc else FAIL
        print(f"     {mark} se ven igual al original (variantes invisibles): {vok}/{vc}")
    print(f"     por vector: {dict(sorted(per_vector.items()))}")
    print(f"{OK} manifiesto en {out_dir / 'manifest.jsonl'}")
    print(f"{OK} objetivos en {out_dir / 'targets.json'}")
