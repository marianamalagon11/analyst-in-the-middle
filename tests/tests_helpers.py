"""Constructores de objetos de prueba compartidos entre archivos de tests."""

from __future__ import annotations

from aitm.analyst.schema import AnalystOutput
from aitm.evaluation.traces import PromptInfo, RunRecord


def record_para(
    report_id: str,
    output: AnalystOutput | None,
    text: str,
    *,
    status: str = "ok",
    model: str = "m",
    source_format: str = "txt",
    attack: dict | None = None,
) -> RunRecord:
    """Una traza minima con el texto que "vio" el modelo en el mensaje de usuario."""
    return RunRecord(
        run_id="t",
        created_at="t",
        config_hash="h",
        model=model,
        report_id=report_id,
        source_path=f"{report_id}.{source_format}",
        source_format=source_format,
        source_sha256="s",
        text_sha256="t",
        text_chars=len(text),
        parser={},
        attack=attack,
        prompt=PromptInfo(system_path="p", system_sha256="s", user_template_sha256="u"),
        status=status,
        messages=[{"role": "system", "content": "sys"}, {"role": "user", "content": text}],
        output=output,
        latency_ms={"analyst": 1000},
        tokens={"prompt": 10, "completion": 5},
    )
