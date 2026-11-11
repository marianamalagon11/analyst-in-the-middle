"""Pruebas del extractor de IoCs.

El extractor alimenta el etiquetado y la normalizacion de las metricas, asi que los
dos errores que hay que vigilar son opuestos: perder un indicador real (recall) e
inventarse indicadores donde solo hay numeros de version o nombres de archivo
(precision). Hay una prueba para cada uno.
"""

from __future__ import annotations

from aitm.analyst.iocs import extract, normalize_value, refang, summarize


def test_refang_de_las_variantes_del_corpus() -> None:
    assert refang("evil[.]com") == "evil.com"
    assert refang("evil(.)com") == "evil.com"
    assert refang("evil[dot]com") == "evil.com"
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("admin[@]evil.com") == "admin@evil.com"
    assert refang("admin[at]evil.com") == "admin@evil.com"


def test_refang_asimetrico() -> None:
    """AnnoCTR trae 49 indicadores con un solo corchete; sin esto se parten."""
    assert refang("onedrive.live.]com/download") == "onedrive.live.com/download"
    assert refang("santiagonasar.]duckdns.org") == "santiagonasar.duckdns.org"
    assert refang("hxxp://miandfish[.store/a") == "http://miandfish.store/a"


def test_refang_no_toca_el_texto_normal() -> None:
    """`.]` dentro de prosa no es defang y no se debe reescribir."""
    assert refang("ver la nota [al final.] y seguir") == "ver la nota [al final.] y seguir"
    assert refang("una lista [1.] y otra") == "una lista [1.] y otra"


def test_extrae_los_tipos_principales() -> None:
    texto = """
    El loader contacto hxxps://cdn-update-delivery[.]com/p/loader.ps1 y resolvio
    185.220.101.47 en el puerto 443, con respaldo en backup-sync[.]net.
    SHA-256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08.
    Correo del operador: support@cdn-update-delivery[.]com. Relacionado con
    CVE-2023-23397. Persistencia en HKCU\\Software\\Microsoft\\Windows\\Run
    y binario en C:\\Users\\Public\\svchost.exe.
    """
    found = {ioc.type: ioc.value for ioc in extract(texto)}

    assert found["url"] == "https://cdn-update-delivery.com/p/loader.ps1"
    assert found["ipv4"] == "185.220.101.47"
    assert found["domain"] == "backup-sync.net"
    assert found["sha256"] == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert found["email"] == "support@cdn-update-delivery.com"
    assert found["cve"] == "CVE-2023-23397"
    assert found["registry_key"].startswith("HKCU\\Software")
    assert found["file_path"] == "C:\\Users\\Public\\svchost.exe"


def test_no_inventa_iocs_en_texto_inocente() -> None:
    texto = (
        "La version 4.2.1.0 del agente abrio invoice_2024.docm y escribio loader.ps1 "
        "en disco. El informe 1.0 de 2024 cita la seccion 3.2.1 del anexo."
    )
    assert extract(texto) == []


def test_el_sha256_no_se_trocea_en_hashes_mas_cortos() -> None:
    """Un sha256 contiene subcadenas validas de md5 y sha1: no deben salir."""
    sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    tipos = [ioc.type for ioc in extract(f"hash: {sha256}")]
    assert tipos == ["sha256"]


def test_el_host_de_una_url_no_reaparece_como_dominio() -> None:
    found = extract("descarga en https://evil.com/a/b")
    assert [(ioc.type, ioc.value) for ioc in found] == [
        ("url", "https://evil.com/a/b")
    ]


def test_marca_ruido_e_ips_internas() -> None:
    found = {ioc.value: ioc for ioc in extract("ver zscaler.com y 10.14.22.8 y evil.net")}
    assert found["zscaler.com"].is_noise
    assert found["10.14.22.8"].is_internal_ip
    assert not found["evil.net"].is_noise
    assert not found["evil.net"].is_internal_ip


def test_include_noise_false_filtra_el_ruido() -> None:
    texto = "ver zscaler.com y evil.net"
    assert len(extract(texto)) == 2
    assert [ioc.value for ioc in extract(texto, include_noise=False)] == ["evil.net"]


def test_normalizacion_es_idempotente_y_canoniza() -> None:
    assert normalize_value("domain", "EVIL[.]COM") == "evil.com"
    assert normalize_value("domain", "evil.com") == "evil.com"
    assert normalize_value("sha256", "ABCDEF") == "abcdef"
    assert normalize_value("cve", "cve-2023-23397") == "CVE-2023-23397"
    # En una URL el host no distingue mayusculas, la ruta si.
    assert normalize_value("url", "HTTPS://EVIL.COM/Path") == "https://evil.com/Path"


def test_resumen_cuenta_por_tipo() -> None:
    found = extract("evil.com, evil2.com y 8.8.8.8")
    assert summarize(found) == {"domain": 2, "ipv4": 1}


def test_deduplica_por_valor_normalizado() -> None:
    found = extract("evil[.]com aparece, y evil.com otra vez, y EVIL.COM tambien")
    assert len(found) == 1
