"""Extraccion y normalizacion de indicadores de compromiso por expresiones regulares.

Dos usos distintos y deliberados:

1. **Apoyo al etiquetado (Fase 1).** El extractor propone los IoCs de un reporte para
   que el equipo solo tenga que revisar y corregir, en vez de leer buscando IPs a ojo.
   Es un ayudante, no la verdad: la verdad la fija la revision humana.
2. **Normalizacion para las metricas (Fase 2+).** Para comparar lo que dijo el modelo
   con el ground truth hay que llevar ambos a la misma forma: `hxxps://EVIL[.]com/a`
   y `https://evil.com/a` son el mismo indicador y deben emparejar.

El extractor es deliberadamente conservador: preferimos perder un IoC raro a inundar
el etiquetado de falsos positivos (numeros de version leidos como IPs, nombres de
archivo leidos como dominios).
"""

from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Literal

IoCType = Literal[
    "ipv4",
    "ipv6",
    "domain",
    "url",
    "md5",
    "sha1",
    "sha256",
    "email",
    "file_path",
    "registry_key",
    "cve",
]

# --- Desofuscacion (refang) ------------------------------------------------
#
# Los reportes publican los indicadores "defanged" para que nadie los clique por
# accidente. Hay que deshacerlo antes de extraer, y hacerlo igual en el ground truth
# y en la salida del modelo, o las metricas comparan peras con manzanas.

_REFANG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"h(?:xx|tt)p(s?)(?:://|\[://\]|\[:\]//)", re.I), r"http\1://"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)"), "@"),
    (re.compile(r"\[\s*at\s*\]|\(\s*at\s*\)", re.I), "@"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    # Defang asimetrico, con un solo corchete: `onedrive.live.]com`,
    # `santiagonasar.]duckdns.org`, `hxxp://miandfish[.store`. En AnnoCTR aparece 49
    # veces y sin esta regla el extractor parte la URL en el corchete y se queda con
    # `https://onedrive.live`, que no emparejaria con nada. Se exige caracter de
    # palabra a ambos lados para no tocar texto normal del tipo `[ver nota.]`.
    (re.compile(r"(?<=\w)\.\](?=\w)"), "."),
    (re.compile(r"(?<=\w)\[\.(?=\w)"), "."),
)


def refang(text: str) -> str:
    """Deshace el "defanging" tipico de los reportes: hxxp, [.], [at], [:] ..."""
    for pattern, replacement in _REFANG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# --- Patrones ---------------------------------------------------------------
#
# El orden importa: lo que ya se consumio como URL no se vuelve a ofrecer como
# dominio suelto, y un sha256 no se puede trocear en hashes mas cortos.

# TLDs aceptados. Una lista cerrada es la forma mas barata de no confundir
# "loader.ps1" o "invoice_2024.docm" con dominios. Si hace falta un TLD nuevo para
# un reporte concreto se agrega aqui y se anota en docs/DATASET.md.
_TLDS = frozenset(
    """
    com net org edu gov mil int info biz name pro xyz top site online shop club live
    icu vip cc tv cn ru su ua by kz pl de fr it es nl be ch at se no fi dk cz sk hu
    ro bg gr pt ie uk eu us ca mx br ar cl co pe ve io ai app dev cloud tech space
    website fun store press host link click work life world today news media email
    download mov cfd sbs rest cyber tokyo moe pw ws me tk ml ga cf gq buzz monster
    quest bar best beauty bond casa charity codes company digital energy estate
    events expert fail finance fit fyi gdn global group guru help ink jp kr
    in id my sg th tw hk vn ph au nz za ng ke eg sa ae ir tr il
    st to is im li la ovh ms sh gg nu fm am cx ac mn bz tt cat re nl pm wf yt
    """.split()
)

_FILE_EXTENSIONS = frozenset(
    """
    exe dll sys bin dat tmp log txt doc docx docm xls xlsx xlsm ppt pptx pdf rtf
    zip rar 7z tar gz bz2 iso img vhd ps1 psm1 bat cmd vbs js jse wsf hta lnk scr
    cpl msi msp jar py pyc pl sh elf so dylib apk ipa php asp aspx jsp html htm xml
    json yaml yml csv ini conf cfg reg crt pem key pfx p12 eml msg one pub docb
    """.split()
)

# Comillas tipograficas y guiones largos: los reportes copiados de blogs los traen
# pegados a los indicadores y no forman parte del valor.
_TYPOGRAPHIC = "“”‘’«»–— "

_PATTERNS: tuple[tuple[IoCType, re.Pattern[str]], ...] = (
    ("url", re.compile(rf"\bhttps?://[^\s<>\"'`\[\](),{_TYPOGRAPHIC}]{{3,}}", re.I)),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)),
    ("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.I)),
    ("sha1", re.compile(r"\b[a-f0-9]{40}\b", re.I)),
    ("md5", re.compile(r"\b[a-f0-9]{32}\b", re.I)),
    ("email", re.compile(r"\b[a-z0-9._%+-]+@[a-z0-9][a-z0-9.-]*\.[a-z]{2,24}\b", re.I)),
    (
        "registry_key",
        re.compile(
            r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CURRENT_CONFIG|USERS|CLASSES_ROOT)"
            rf"|HKLM|HKCU|HKCR|HKU)\\[^\s\"'<>|{_TYPOGRAPHIC}]+",
            re.I,
        ),
    ),
    (
        "file_path",
        re.compile(
            r"(?:\b[A-Za-z]:\\|%[A-Za-z_]+%\\|\\\\[A-Za-z0-9._-]+\\)"
            rf"[^\s\"'<>|{_TYPOGRAPHIC}]{{2,}}"
        ),
    ),
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("ipv6", re.compile(r"\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b", re.I)),
    (
        "domain",
        re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I),
    ),
)

# Dominios que aparecen en casi todos los reportes y casi nunca son el indicador:
# el propio vendor, redes sociales, repositorios, sandboxes. No se descartan, se
# marcan, porque la decision es del etiquetado humano.
NOISE_DOMAINS = frozenset(
    """
    zscaler.com proofpoint.com intel471.com lab52.io quointelligence.eu
    microsoft.com windows.com office.com live.com msn.com bing.com
    google.com youtube.com gstatic.com googleapis.com blogspot.com
    twitter.com x.com facebook.com linkedin.com instagram.com t.me
    github.com githubusercontent.com gitlab.com bitbucket.org
    virustotal.com any.run hybrid-analysis.com joesandbox.com
    mitre.org cve.org nist.gov cisa.gov
    wikipedia.org w3.org schema.org mozilla.org apache.org
    amazonaws.com cloudflare.com akamai.net fastly.net
    """.split()
)


class IoC:
    """Un indicador extraido, con su forma normalizada y la forma como aparecia."""

    __slots__ = ("type", "value", "raw", "start", "end")

    def __init__(self, type: IoCType, value: str, raw: str, start: int, end: int):
        self.type = type
        self.value = value
        self.raw = raw
        self.start = start
        self.end = end

    def __repr__(self) -> str:  # pragma: no cover - ayuda al depurar
        return f"IoC({self.type}, {self.value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IoC):
            return NotImplemented
        return (self.type, self.value) == (other.type, other.value)

    def __hash__(self) -> int:
        return hash((self.type, self.value))

    @property
    def is_noise(self) -> bool:
        """Dominio o URL de infraestructura legitima omnipresente en los reportes."""
        if self.type == "domain":
            return registrable(self.value) in NOISE_DOMAINS
        if self.type == "url":
            host = url_host(self.value)
            return bool(host) and registrable(host) in NOISE_DOMAINS
        return False

    @property
    def is_internal_ip(self) -> bool:
        """IP privada, loopback o reservada: casi siempre la victima, no el atacante."""
        if self.type not in ("ipv4", "ipv6"):
            return False
        try:
            address = ipaddress.ip_address(self.value)
        except ValueError:
            return False
        return not address.is_global

    def as_dict(self) -> dict[str, object]:
        return {
            "value": self.value,
            "type": self.type,
            "raw": self.raw,
            "offset": self.start,
        }


def registrable(domain: str) -> str:
    """Ultimos dos labels del dominio. Aproximacion: no maneja TLDs compuestos."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def url_host(url: str) -> str:
    match = re.match(r"https?://(?:[^/@]+@)?([^/:?#]+)", url, re.I)
    return match.group(1).lower() if match else ""


#: Palabras que delatan que lo que sigue es un numero de version, no una IP.
#: "Framework\\v4.0.30319" y "version 4.2.1.0" aparecen en casi todos los reportes.
_VERSION_CONTEXT = re.compile(
    r"(?:version|versión|ver\.|v\.?|build|release|framework|runtime|sdk|"
    r"update|patch|rev\.?)[\s:=v]*$",
    re.I,
)


def _valid_ipv4(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
    except ValueError:
        return False
    return True


def _looks_like_version(text: str, start: int) -> bool:
    """Decide por contexto si una IP sintacticamente valida es un numero de version.

    Se mira la palabra anterior en vez de la forma del numero: exigir un octeto de dos
    cifras parecia buena idea pero descartaba `8.8.8.8` y `1.1.1.1`, que son IPs de
    verdad. Perder un indicador real es peor que ofrecer uno falso, porque al falso lo
    quita la revision (motivo `extraction_artifact`) y al perdido nadie lo ve.
    """
    return bool(_VERSION_CONTEXT.search(text[max(0, start - 24) : start]))


def _valid_ipv6(candidate: str) -> bool:
    try:
        ipaddress.IPv6Address(candidate)
    except ValueError:
        return False
    return True


def _valid_domain(candidate: str) -> bool:
    labels = candidate.lower().split(".")
    if len(labels) < 2 or len(candidate) > 253:
        return False
    tld = labels[-1]
    if tld in _FILE_EXTENSIONS and tld not in _TLDS:
        return False
    return tld in _TLDS


_VALIDATORS = {
    "ipv4": _valid_ipv4,
    "ipv6": _valid_ipv6,
    "domain": _valid_domain,
}


def normalize_value(ioc_type: IoCType, value: str) -> str:
    """Forma canonica de un indicador, para comparar ground truth con salida del LLM."""
    value = refang(value.strip()).strip()
    if ioc_type in ("md5", "sha1", "sha256", "domain", "email", "ipv6"):
        return value.lower().rstrip(".")
    if ioc_type == "cve":
        return value.upper()
    if ioc_type == "url":
        # Los textos del corpus vienen de markdown, que escapa los guiones bajos:
        # `install\_flash\_player.exe`. Una URL real no lleva barras invertidas, asi que
        # deshacer el escape aqui es seguro, y necesario para que el ground truth
        # empareje con lo que diga el modelo, que vera el nombre sin escapar.
        value = value.replace("\\_", "_").replace("\\-", "-").replace("\\.", ".")
        # El esquema y el host no distinguen mayusculas; la ruta si.
        match = re.match(r"(https?://)([^/]+)(.*)", value, re.I)
        if not match:
            return value
        scheme, host, rest = match.groups()
        return f"{scheme.lower()}{host.lower()}{rest}".rstrip(".,;)")
    if ioc_type in ("registry_key", "file_path"):
        # Un punto, un parentesis o un acento invertido final es puntuacion del texto,
        # no parte de la ruta: "...escribio C:\\Users\\Public\\svchost.exe." no lleva el
        # punto, y "`%APPDATA%\\Word\\Moon.wll`" no lleva los acentos del markdown.
        value = value.strip("`").rstrip(".,;:)]}\u201d\u2019")
        return value.replace("/", "\\") if ioc_type == "registry_key" else value
    return value


def extract(text: str, *, include_noise: bool = True) -> list[IoC]:
    """Extrae los IoCs de un texto ya normalizado, sin solapamientos.

    Recorre los patrones en orden de especificidad y marca las posiciones ya
    consumidas, de forma que el host de una URL no reaparezca como dominio suelto
    ni un sha256 se trocee en hashes mas cortos.
    """
    refanged = refang(text)
    claimed: list[tuple[int, int]] = []
    found: dict[tuple[str, str], IoC] = {}

    def overlaps(start: int, end: int) -> bool:
        return any(start < c_end and c_start < end for c_start, c_end in claimed)

    for ioc_type, pattern in _PATTERNS:
        for match in pattern.finditer(refanged):
            start, end = match.span()
            if overlaps(start, end):
                continue
            raw = match.group(0)
            value = normalize_value(ioc_type, raw)
            validator = _VALIDATORS.get(ioc_type)
            if validator and not validator(value):
                continue
            if ioc_type == "ipv4" and _looks_like_version(refanged, start):
                continue
            claimed.append((start, end))
            key = (ioc_type, value)
            if key not in found:
                found[key] = IoC(ioc_type, value, raw, start, end)

    iocs = sorted(found.values(), key=lambda ioc: (ioc.start, ioc.type))
    if include_noise:
        return iocs
    return [ioc for ioc in iocs if not ioc.is_noise]


def summarize(iocs: Iterable[IoC]) -> dict[str, int]:
    """Cuenta por tipo. Sirve para elegir los reportes mas densos del corpus."""
    counts: dict[str, int] = {}
    for ioc in iocs:
        counts[ioc.type] = counts.get(ioc.type, 0) + 1
    return dict(sorted(counts.items()))
