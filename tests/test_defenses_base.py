"""Pruebas de la interfaz `Defense` y de su composicion.

Lo que se protege: que el orden en que se declaran las defensas no cambie el pipeline
(ni la clave de la celda en las trazas), que no se puedan combinar dos defensas de
etapa `prompt`, y que el registro arme un `Analyst` con los ganchos puestos.
"""

from __future__ import annotations

import itertools
from pathlib import Path
from typing import ClassVar

import pytest

from aitm.analyst.parsers import ParsedReport
from aitm.analyst.pipeline import Analyst, Environment
from aitm.config import load_config
from aitm.defenses.base import (
    DefenseContext,
    PostDefense,
    PreDefense,
    PromptDefense,
    compose,
)
from aitm.defenses.registry import available, build_analyst, parse_names


class _Pre(PreDefense):
    name: ClassVar[str] = "sanitizer"

    def apply(self, report, context):
        context.note(self.name, "pre")
        return report


class _Prompt(PromptDefense):
    name: ClassVar[str] = "spotlighting"

    def build_messages(self, system_prompt, report):
        return [{"role": "system", "content": system_prompt}, {"role": "user", "content": report.text}]


class _OtroPrompt(_Prompt):
    name: ClassVar[str] = "otro_prompt"


class _Validador(PostDefense):
    name: ClassVar[str] = "schema_validation"

    def apply(self, validated, report, context):
        context.note(self.name, "post")
        return validated


class _Juez(PostDefense):
    name: ClassVar[str] = "llm_judge"

    def apply(self, validated, report, context):
        context.note(self.name, "post")
        return validated


TODAS = [_Juez, _Validador, _Prompt, _Pre]


@pytest.mark.parametrize("orden", list(itertools.permutations(range(4))))
def test_la_composicion_no_depende_del_orden(orden):
    defensas = [TODAS[i]() for i in orden]
    composicion = compose(defensas)
    assert composicion.names == ("sanitizer", "spotlighting", "schema_validation", "llm_judge")


def test_los_ganchos_corren_por_etapa_y_en_orden_canonico():
    composicion = compose([_Juez(), _Pre(), _Validador()])
    contexto = DefenseContext()
    reporte = ParsedReport(report_id="r", source_format="txt", text="x")
    for hook in composicion.pre_hooks:
        reporte = hook(reporte, contexto)
    for hook in composicion.post_hooks:
        hook(None, reporte, contexto)
    assert contexto.notes == ["sanitizer: pre", "schema_validation: post", "llm_judge: post"]


def test_no_se_repiten_defensas():
    with pytest.raises(ValueError, match="repetidas"):
        compose([_Pre(), _Pre()])


def test_solo_una_defensa_de_prompt():
    with pytest.raises(ValueError, match="prompt"):
        compose([_Prompt(), _OtroPrompt()])


def test_el_bloqueo_queda_anotado():
    contexto = DefenseContext()
    contexto.block("llm_judge", "instrucciones al modelo")
    assert contexto.blocked
    assert contexto.block_reasons == ["llm_judge: instrucciones al modelo"]
    assert "BLOQUEADO" in contexto.notes[0]


def test_parse_names():
    assert parse_names(None) is None
    assert parse_names("none") == []
    assert parse_names("") == []
    assert parse_names("llm_judge, sanitizer") == ["llm_judge", "sanitizer"]


def test_el_registro_conoce_el_sanitizador():
    assert "sanitizer" in available()


def test_defensa_desconocida():
    with pytest.raises(KeyError, match="desconocida"):
        build_analyst(load_config(), client=None, defenses=["no_existe"], environment=Environment())


def test_build_analyst_sin_defensas_es_el_analista_base():
    config = load_config()
    base = Analyst(config=config, client=None, environment=Environment())
    defendido = build_analyst(config, client=None, defenses=[], environment=Environment())
    assert defendido.defenses == []
    assert defendido.prompt_info == base.prompt_info
    assert defendido.pre_hooks == [] and defendido.post_hooks == []


def test_build_analyst_toma_las_defensas_de_la_config():
    config = load_config()
    analista = build_analyst(config, client=None, environment=Environment())
    assert analista.defenses == list(config.defenses.enabled)


def test_la_clave_de_celda_incluye_las_defensas(tmp_path: Path):
    config = load_config()
    documento = tmp_path / "r.txt"
    documento.write_text("texto", encoding="utf-8")
    sin = build_analyst(config, client=None, defenses=[], environment=Environment())
    con = build_analyst(config, client=None, defenses=["sanitizer"], environment=Environment())
    assert sin.cell_key(documento) != con.cell_key(documento)
