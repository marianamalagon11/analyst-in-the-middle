"""Pruebas del pipeline del analista con un cliente falso (sin Ollama).

Lo que se protege: que los reintentos cambien el prompt (si no, con temperatura 0 son
inutiles), que un JSON cortado se marque y no se reintente, que el ataque no llegue
nunca al prompt y que la traza tenga todo lo que el evaluador necesita.
"""

from __future__ import annotations

import json

import pytest

from aitm.analyst.pipeline import RETRY_TEMPLATE, Analyst, Environment
from aitm.config import load_config
from aitm.evaluation.traces import RunLog, iter_records
from aitm.llm.ollama_client import ChatResponse, OllamaError

REPORTE = """Campaign targeting finance

The loader reached out to hxxps://cdn-update-delivery[.]com/p/loader.ps1 and
resolved its C2 to 185.220.101[.]47.
"""

VALIDA = {
    "summary": "Loader con C2.",
    "severity": "high",
    "iocs": [
        {
            "value": "185.220.101[.]47",
            "type": "ipv4",
            "verdict": "malicious",
            "confidence": 0.9,
            "evidence": "C2",
        }
    ],
    "mitre_attack": [],
    "threat_actor": None,
    "notes": [],
}


class ClienteFalso:
    """Devuelve las respuestas en orden y guarda los mensajes que recibio."""

    def __init__(self, respuestas: list[str | Exception], done_reason: str = "stop"):
        self.respuestas = list(respuestas)
        self.done_reason = done_reason
        self.llamadas: list[list[dict[str, str]]] = []

    def chat(self, messages, *, model=None, response_format=None, options=None):
        self.llamadas.append([dict(m) for m in messages])
        respuesta = self.respuestas.pop(0)
        if isinstance(respuesta, Exception):
            raise respuesta
        return ChatResponse(
            content=respuesta,
            model=model,
            latency_ms=10,
            prompt_tokens=100,
            completion_tokens=50,
            raw={"done_reason": self.done_reason},
        )


@pytest.fixture
def reporte(tmp_path):
    path = tmp_path / "r1.txt"
    path.write_text(REPORTE, encoding="utf-8")
    return path


def analista(cliente) -> Analyst:
    return Analyst(config=load_config(), client=cliente, environment=Environment(host="test"))


def test_analisis_valido(reporte) -> None:
    cliente = ClienteFalso([json.dumps(VALIDA)])
    record = analista(cliente).analyze(reporte)
    assert record.status == "ok"
    assert record.output is not None
    assert record.output.report_id == "r1", "el report_id lo pone el pipeline"
    assert record.parse_retries == 0
    assert record.latency_ms["analyst"] == 10
    assert record.tokens == {"prompt": 100, "completion": 50}


def test_el_reintento_agrega_el_error_al_prompt(reporte) -> None:
    """Sin esto, temperatura 0 + semilla fija devolveria la misma respuesta invalida."""
    cliente = ClienteFalso(['{"summary": "x"}', json.dumps(VALIDA)])
    record = analista(cliente).analyze(reporte)
    assert record.status == "ok"
    assert record.parse_retries == 1
    segundo = cliente.llamadas[1]
    assert segundo[-2] == {"role": "assistant", "content": '{"summary": "x"}'}
    assert segundo[-1]["role"] == "user"
    assert RETRY_TEMPLATE.split("{error}")[0] in segundo[-1]["content"]
    assert len(record.messages) == 2, "la traza guarda los mensajes originales"


def test_se_agotan_los_reintentos(reporte) -> None:
    config = load_config()
    intentos = 1 + config.analyst.max_parse_retries
    cliente = ClienteFalso(["no es json"] * intentos)
    record = analista(cliente).analyze(reporte)
    assert record.status == "parse_failed"
    assert record.output is None
    assert len(record.attempts) == intentos
    assert all(attempt.error for attempt in record.attempts)


def test_json_cortado_no_se_reintenta(reporte) -> None:
    cliente = ClienteFalso(['{"summary": "cort'], done_reason="length")
    record = analista(cliente).analyze(reporte)
    assert record.status == "truncated"
    assert len(cliente.llamadas) == 1


def test_ollama_caido_queda_como_error(reporte) -> None:
    cliente = ClienteFalso([OllamaError("no responde")])
    record = analista(cliente).analyze(reporte)
    assert record.status == "error"
    assert "no responde" in record.error


def test_el_ataque_no_llega_al_prompt(reporte) -> None:
    cliente = ClienteFalso([json.dumps(VALIDA)])
    ataque = {"vector": "plaintext", "goal": "flip_to_benign", "poison_id": "SECRETO123"}
    record = analista(cliente).analyze(reporte, attack=ataque)
    prompt = json.dumps(cliente.llamadas[0])
    assert "SECRETO123" not in prompt and "flip_to_benign" not in prompt
    assert record.attack == ataque


def test_ganchos_de_defensa(reporte) -> None:
    """La Fase 4 enchufa aqui sus defensas; el pipeline solo tiene que llamarlas."""
    vistos = []

    def pre(report, context):
        vistos.append("pre")
        context.note("pre", "visto")
        return report

    def post(validated, report, context):
        vistos.append("post")
        context.judge = {"injection": False}
        context.latency_ms["judge"] = 7
        return validated

    cliente = ClienteFalso([json.dumps(VALIDA)])
    analyst = analista(cliente)
    analyst.pre_hooks.append(pre)
    analyst.post_hooks.append(post)
    record = analyst.analyze(reporte)
    assert vistos == ["pre", "post"]
    # Lo que dejan las defensas en el contexto llega a la traza.
    assert record.defense_notes == ["pre: visto"]
    assert record.judge == {"injection": False}
    assert record.latency_ms == {"analyst": 10, "judge": 7}


def test_post_hooks_corren_aunque_el_analista_falle(reporte) -> None:
    """El juez evalua el documento: su veredicto vale aunque la respuesta no sirva."""
    vistos = []

    def post(validated, report, context):
        vistos.append(validated)
        context.block("juez", "inyeccion")
        return validated

    cliente = ClienteFalso(["no es json"] * 3)
    analyst = analista(cliente)
    analyst.post_hooks.append(post)
    record = analyst.analyze(reporte)
    assert record.status == "parse_failed"
    assert vistos == [None]
    assert record.blocked is True


def test_post_hooks_no_corren_si_ollama_no_responde(reporte) -> None:
    vistos = []
    cliente = ClienteFalso([OllamaError("caido")])
    analyst = analista(cliente)
    analyst.post_hooks.append(lambda v, r, c: vistos.append(v) or v)
    assert analyst.analyze(reporte).status == "error"
    assert vistos == []


def test_traza_completa_y_reanudable(reporte, tmp_path) -> None:
    cliente = ClienteFalso([json.dumps(VALIDA)])
    analyst = analista(cliente)
    record = analyst.analyze(reporte)

    log = RunLog(tmp_path / "run")
    log.append(record)
    leidos = list(iter_records(log.path))
    assert leidos == [record]
    assert analyst.cell_key(reporte) in log.completed_keys()
    assert record.prompt.system_sha256 and record.source_sha256 and record.text_sha256
    assert record.config_hash == load_config().config_hash


def test_una_linea_cortada_al_final_se_ignora(reporte, tmp_path) -> None:
    record = analista(ClienteFalso([json.dumps(VALIDA)])).analyze(reporte)
    log = RunLog(tmp_path / "run")
    log.append(record)
    with log.path.open("a", encoding="utf-8") as handle:
        handle.write('{"run_id": "cortad')
    assert len(list(log.records())) == 1


def test_una_corrida_con_error_se_reintenta_al_reanudar(reporte, tmp_path) -> None:
    analyst = analista(ClienteFalso([OllamaError("caido")]))
    log = RunLog(tmp_path / "run")
    log.append(analyst.analyze(reporte))
    assert analyst.cell_key(reporte) not in log.completed_keys()


def test_aviso_de_contexto(reporte) -> None:
    config = load_config()
    cliente = ClienteFalso([json.dumps(VALIDA)])
    analyst = analista(cliente)
    respuesta_grande = ChatResponse(
        content=json.dumps(VALIDA),
        model="m",
        latency_ms=1,
        prompt_tokens=config.generation.num_ctx,
        completion_tokens=1,
        raw={"done_reason": "stop"},
    )
    cliente.chat = lambda *a, **k: respuesta_grande
    record = analyst.analyze(reporte)
    assert record.context_warning and "recorto" in record.context_warning
