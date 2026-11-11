"""Defensa `schema_validation`: validacion estricta de la salida del analista.

La validacion base (`aitm.analyst.schema.validate_output`) es tolerante a proposito:
descarta un elemento mal formado y conserva el resto, porque eso haria un pipeline
razonable sin defensas. Esta defensa agrega, sobre la salida ya validada, las reglas
que la arquitectura llama *coherencia* (`docs/ARCHITECTURE.md`, seccion 3.5):

1. **Todo IoC reportado tiene que aparecer literalmente en el texto de entrada** (el
   que vio el modelo, despues de las defensas `pre`). Se compara tras el refang y sin
   distinguir mayusculas, con la misma regla que usa el evaluador
   (`matching.appears_in_text`). Bloquea los IoC alucinados y los que un payload
   intente colar desde fuera del texto.
2. **El valor tiene que tener la forma de su tipo**: un `sha256` de 64 hex, una
   `ipv4` valida, un `domain` que parezca dominio. Un tipo equivocado se descarta,
   no se corrige: la defensa no adivina lo que el modelo quiso decir.
3. **Sin duplicados** de IoC (por forma canonica) ni de tecnica.

Todo lo descartado queda en `validation_warnings` y en `defense_notes` de la traza.

**Lo que NO hace, y hay que decirlo en el informe.** Los cuatro objetivos de ataque del
laboratorio (`flip_to_benign`, `omit_ioc`, `downgrade_severity`, `drop_technique`) no
introducen IoCs nuevos: cambian un veredicto, quitan un indicador, bajan la severidad
o quitan una tecnica. Ninguna regla de coherencia con el texto puede detectar eso,
porque la salida manipulada sigue siendo coherente con el reporte. Se espera, por
tanto, que esta defensa casi no mueva el ASR y que su efecto se vea en el costo
(IoCs reales descartados por un refang mal hecho del modelo). Por la misma razon
**nunca bloquea** la corrida: filtra.
"""

from __future__ import annotations

import ipaddress
import re
from typing import ClassVar

from aitm.analyst.iocs import refang
from aitm.analyst.parsers import ParsedReport
from aitm.analyst.schema import IoCFinding, TechniqueFinding, ValidatedOutput
from aitm.defenses.base import DefenseContext, PostDefense
from aitm.evaluation.matching import _haystack, appears_in_text, canonical

_PORT = re.compile(r":\d{1,5}$")
_HEX = {"md5": 32, "sha1": 40, "sha256": 64}
_DOMAIN = re.compile(r"^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}$", re.I)
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://[^\s/]+\S*$", re.I)
_EMAIL = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}$", re.I)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
_REGISTRY = re.compile(r"^(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)(?:\\|/)", re.I)


def _ip(value: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(value).version == version
    except ValueError:
        return False


def type_matches(ioc_type: str, value: str) -> bool:
    """¿El valor tiene la forma del tipo declarado? Se mira tras el refang."""
    value = refang(value.strip()).strip()
    if ioc_type in _HEX:
        return re.fullmatch(rf"[0-9a-f]{{{_HEX[ioc_type]}}}", value, re.I) is not None
    if ioc_type == "ipv4":
        return _ip(_PORT.sub("", value), 4)
    if ioc_type == "ipv6":
        return _ip(value.strip("[]"), 6)
    if ioc_type == "domain":
        host = _PORT.sub("", value).rstrip(".")
        return bool(_DOMAIN.match(host)) and not _ip(host, 4)
    if ioc_type == "url":
        return bool(_URL.match(value))
    if ioc_type == "email":
        return bool(_EMAIL.match(value))
    if ioc_type == "cve":
        return bool(_CVE.match(value))
    if ioc_type == "registry_key":
        return bool(_REGISTRY.match(value))
    if ioc_type == "file_path":
        return any(sep in value for sep in ("\\", "/")) or value.startswith("%")
    return False


class SchemaValidator(PostDefense):
    name: ClassVar[str] = "schema_validation"

    def apply(
        self,
        validated: ValidatedOutput | None,
        report: ParsedReport,
        context: DefenseContext,
    ) -> ValidatedOutput | None:
        if validated is None:
            context.note(self.name, "sin salida que validar")
            return None

        haystack = _haystack(report.text)
        warnings = list(validated.warnings)
        kept_iocs: list[IoCFinding] = []
        seen: set[tuple[str, str]] = set()
        dropped = {"ausente": 0, "tipo": 0, "duplicado": 0}
        for ioc in validated.output.iocs:
            if not appears_in_text(ioc.value, report.text, haystack=haystack):
                dropped["ausente"] += 1
                warnings.append(f"{self.name}: IoC no aparece en el texto: {ioc.value!r}")
                continue
            if not type_matches(ioc.type, ioc.value):
                dropped["tipo"] += 1
                warnings.append(f"{self.name}: {ioc.value!r} no tiene forma de {ioc.type}")
                continue
            key = (ioc.type, canonical(ioc.type, ioc.value))
            if key in seen:
                dropped["duplicado"] += 1
                continue
            seen.add(key)
            kept_iocs.append(ioc)

        kept_techniques: list[TechniqueFinding] = []
        seen_techniques: set[str] = set()
        for technique in validated.output.mitre_attack:
            if technique.technique_id in seen_techniques:
                dropped["duplicado"] += 1
                continue
            seen_techniques.add(technique.technique_id)
            kept_techniques.append(technique)

        total = sum(dropped.values())
        if total:
            detail = ", ".join(f"{n} {why}" for why, n in dropped.items() if n)
            context.note(self.name, f"descarto {total} elemento(s): {detail}")
        else:
            context.note(self.name, "salida coherente con el texto")

        output = validated.output.model_copy(
            update={"iocs": kept_iocs, "mitre_attack": kept_techniques}
        )
        return ValidatedOutput(output=output, warnings=warnings)
