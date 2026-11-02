"""Pruebas del emparejamiento de IoCs y de las metricas.

Los casos estan calculados a mano: si una de estas cuentas cambia, cambian todas las
tablas del informe, asi que cada regla de emparejamiento tiene su prueba.
"""

from __future__ import annotations

import pytest

from aitm.analyst.schema import AnalystOutput, IoCFinding
from aitm.evaluation.labels import ReportLabel
from aitm.evaluation.matching import appears_in_text, match_iocs
from aitm.evaluation.metrics import (
    always_malicious_macro_f1,
    f1_per_class,
    macro_f1,
    percentile,
    regex_baseline,
    score_run,
    score_techniques,
)

TEXTO = """Report. The C2 was santiagonasar.duckdns[.]org and the payload was served from
hxxps://nyc008.hawkhost[.]com/~invoixec/ . The loader runs
C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe and drops
ff525bc3aade928db718dab395eeba0f886054c889dda2389a51628d58924ff5.
Read more at https://lab52.io/blog/post and on shodan.io.
"""


def etiqueta() -> ReportLabel:
    return ReportLabel.model_validate(
        {
            "report_id": "r1",
            "source": {"corpus": "t", "file": "t.txt", "license": "CC"},
            "formats": ["txt"],
            "status": "assisted",
            "annotators": ["A"],
            "severity": "high",
            "iocs": [
                {"value": "santiagonasar.duckdns.org", "type": "domain", "verdict": "malicious"},
                {"value": "https://nyc008.hawkhost.com/~invoixec/", "type": "url", "verdict": "malicious"},
                {
                    "value": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "type": "file_path",
                    "verdict": "benign",
                },
                {
                    "value": "ff525bc3aade928db718dab395eeba0f886054c889dda2389a51628d58924ff5",
                    "type": "sha256",
                    "verdict": "malicious",
                },
            ],
            "excluded_iocs": [
                {"value": "https://lab52.io/blog/post", "type": "url", "reason": "vendor_infrastructure"}
            ],
            "mitre_attack": [{"technique_id": "T1059"}, {"technique_id": "T1566.001"}],
        }
    )


def ioc(value: str, type_: str, verdict: str = "malicious") -> IoCFinding:
    return IoCFinding(value=value, type=type_, verdict=verdict, confidence=0.9)


def test_defang_y_mayusculas_emparejan() -> None:
    result = match_iocs(
        [ioc("SantiagoNasar.DuckDNS[.]org", "domain"), ioc("FF525BC3AADE928DB718DAB395EEBA0F886054C889DDA2389A51628D58924FF5", "sha256")],
        etiqueta(),
        TEXTO,
    )
    assert result.tp == 2
    assert result.false_positives == 0


def test_url_defanged_empareja() -> None:
    result = match_iocs([ioc("hxxps://nyc008.hawkhost[.]com/~invoixec/", "url")], etiqueta(), TEXTO)
    assert result.tp == 1


def test_ruta_de_windows_no_distingue_mayusculas() -> None:
    result = match_iocs(
        [ioc("c:\\windows\\system32\\windowspowershell\\v1.0\\POWERSHELL.EXE", "file_path", "malicious")],
        etiqueta(),
        TEXTO,
    )
    assert result.tp == 1
    assert result.verdict_pairs == [("benign", "malicious")], "LOLBin marcado malicioso"


def test_las_cuatro_clases_de_falso_positivo() -> None:
    result = match_iocs(
        [
            ioc("https://lab52.io/blog/post", "url"),  # excluido con motivo
            ioc("shodan.io", "domain"),  # esta en el texto, nadie lo etiqueto
            ioc("evil-inventado.com", "domain"),  # no esta en el texto
            ioc("santiagonasar.duckdns.org", "domain"),
            ioc("santiagonasar.duckdns.org", "domain"),  # repetido
        ],
        etiqueta(),
        TEXTO,
    )
    assert result.count("excluded") == 1
    assert result.count("unlabeled_in_text") == 1
    assert result.count("hallucinated") == 1
    assert result.count("duplicate") == 1
    assert result.tp == 1
    assert result.false_positives == 3, "los duplicados no son FP"


def test_tipo_equivocado_empareja_pero_se_marca() -> None:
    result = match_iocs([ioc("santiagonasar.duckdns.org", "url")], etiqueta(), TEXTO)
    assert result.tp == 1
    assert result.predictions[0].type_mismatch


def test_el_host_de_una_url_es_parcial_no_acierto() -> None:
    result = match_iocs([ioc("nyc008.hawkhost.com", "domain")], etiqueta(), TEXTO)
    assert result.tp == 0
    assert result.predictions[0].partial_of == "https://nyc008.hawkhost.com/~invoixec/"


def test_lo_no_reportado_queda_como_omitido() -> None:
    result = match_iocs([ioc("santiagonasar.duckdns.org", "domain")], etiqueta(), TEXTO)
    assert len(result.missed) == 3


def test_appears_in_text_tolera_defang() -> None:
    assert appears_in_text("santiagonasar.duckdns.org", TEXTO)
    assert not appears_in_text("otro.com", TEXTO)


# -- metricas ---------------------------------------------------------------


def test_f1_por_clase_a_mano() -> None:
    pairs = [("malicious", "malicious"), ("malicious", "benign"), ("benign", "benign")]
    table = f1_per_class(pairs)
    assert table["malicious"]["precision"] == 1.0
    assert table["malicious"]["recall"] == 0.5
    assert table["benign"]["precision"] == 0.5
    assert table["suspicious"]["f1"] is None, "clase ausente: no entra al promedio"
    assert macro_f1(pairs) == pytest.approx((2 / 3 + 2 / 3) / 2)


def test_siempre_malicious_da_un_macro_f1_bajo() -> None:
    valor = always_malicious_macro_f1([etiqueta()])
    # 3 malicious y 1 benign: F1(malicious) = 6/7, F1(benign) = 0.
    assert valor == pytest.approx((6 / 7 + 0) / 2)


def test_tecnicas_estricto_y_por_padre() -> None:
    score = score_techniques(["T1059.001", "T1566.001", "T1105"], ["T1059", "T1566.001"])
    assert score.recall_strict == 0.5
    assert score.recall_parent == 1.0
    assert score.precision_parent == pytest.approx(2 / 3)


def test_percentil() -> None:
    assert percentile([1, 2, 3, 4], 0.5) == 2.5
    assert percentile([], 0.5) is None


def test_corrida_fallida_cuenta_como_analisis_vacio() -> None:
    from tests_helpers import record_para

    score = score_run(record_para("r1", None, TEXTO, status="parse_failed"), etiqueta())
    assert score.recall == 0.0
    assert score.precision is None
    assert not score.severity_exact


def test_puntaje_de_una_corrida() -> None:
    from tests_helpers import record_para

    salida = AnalystOutput(
        severity="medium",
        iocs=[ioc("santiagonasar.duckdns.org", "domain"), ioc("evil.com", "domain")],
        mitre_attack=[{"technique_id": "T1059.001", "confidence": 0.5}],
    )
    score = score_run(record_para("r1", salida, TEXTO), etiqueta())
    assert (score.tp, score.fp, score.fp_hallucinated) == (1, 1, 1)
    assert score.precision == 0.5 and score.recall == 0.25
    assert not score.severity_exact and score.severity_within_one
    assert score.techniques.recall_parent == 0.5


def test_linea_base_regex() -> None:
    tp, fp, total = regex_baseline(etiqueta(), TEXTO)
    assert total == 4
    assert tp == 4, "el extractor encuentra los cuatro indicadores del texto"
    assert fp >= 1, "y tambien propone shodan.io, que nadie etiqueto"
