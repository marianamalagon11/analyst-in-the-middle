"""Cache de inferencia: la misma peticion a Ollama no se calcula dos veces.

Funciona porque el laboratorio es **determinista**: con `seed` fija, `temperature: 0` y
`top_k: 1` la misma peticion devuelve exactamente la misma respuesta (verificado en
la Fase 0 en los dos equipos, `results/setup_report*.md`). Entonces la respuesta
guardada *es* la que daria el modelo, y repetir la inferencia solo gasta horas.

En la Fase 5 eso recorta mucho la matriz, sin recortar el diseno:

- Con `sanitizer`, un `html_hidden` o un `pdf_hidden` sanitizado es byte a byte el
  reporte limpio sanitizado: misma peticion, misma respuesta.
- `schema_validation` solo filtra la salida: el prompt del analista no cambia.
- El juez ve el mismo documento en todas las combinaciones que no cambian el texto.

**Que entra en la clave.** El modelo, los mensajes completos, el `format`, las
opciones efectivas (semilla, temperatura, `num_ctx`...) y el **equipo**: el
determinismo esta verificado por equipo, no entre equipos, asi que una respuesta del M5
no se reutiliza en el MacBook. Ademas cada entrada guarda el digest de los pesos y se
ignora si el modelo instalado ya no es el mismo.

La respuesta se reproduce tal cual, **incluida su latencia original**: la latencia de
una celda sigue siendo lo que cuesta calcularla, no lo que tardo en leerse de disco.
La cache es un archivo JSONL de solo agregar (`results/runs/_cache/ollama.jsonl`,
fuera de git), asi que interrumpir una corrida no la corrompe.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from aitm.llm.ollama_client import ChatResponse, OllamaError

CACHE_FILE = "ollama.jsonl"


def request_key(
    *,
    model: str,
    messages: list[dict[str, str]],
    response_format: Any,
    options: dict[str, Any],
    host: str,
) -> str:
    payload = json.dumps(
        {
            "model": model,
            "messages": messages,
            "format": response_format,
            "options": options,
            "host": host,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def effective_options(client: Any, options: dict[str, Any] | None) -> dict[str, Any]:
    """Las opciones que de verdad viajan a Ollama (semilla y generacion incluidas)."""
    builder = getattr(client, "_options", None)
    return builder(options) if callable(builder) else dict(options or {})


class InferenceCache:
    """Respuestas guardadas por clave. Carga el JSONL una vez y agrega al final."""

    def __init__(self, directory: Path | str) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / CACHE_FILE
        self.entries: dict[str, dict[str, Any]] = {}
        if self.path.is_file():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue  # ultima linea cortada por una interrupcion
                self.entries[entry["key"]] = entry

    def get(self, key: str, digest: str | None) -> dict[str, Any] | None:
        entry = self.entries.get(key)
        if entry is None:
            return None
        if digest and entry.get("digest") and entry["digest"] != digest:
            return None  # cambiaron los pesos con el mismo nombre
        return entry

    def __contains__(self, key: str) -> bool:
        return key in self.entries

    def put(self, key: str, entry: dict[str, Any]) -> None:
        entry = {"key": key, **entry}
        self.entries[key] = entry
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


class CachingClient:
    """Envuelve al cliente de Ollama. Para el pipeline es indistinguible del original."""

    def __init__(self, inner: Any, cache: InferenceCache, host: str) -> None:
        self.inner = inner
        self.cache = cache
        self.host = host
        self.hits = 0
        self.misses = 0
        self._digests: dict[str, str | None] = {}

    def __getattr__(self, name: str) -> Any:
        # version(), model_digest(), has_model(), is_up()... van directo al cliente real.
        return getattr(self.inner, name)

    def digest(self, model: str) -> str | None:
        if model not in self._digests:
            try:
                self._digests[model] = self.inner.model_digest(model)
            except (AttributeError, OllamaError):
                self._digests[model] = None
        return self._digests[model]

    def key_for(
        self,
        messages: list[dict[str, str]],
        *,
        model: str,
        response_format: Any = None,
        options: dict[str, Any] | None = None,
    ) -> str:
        return request_key(
            model=model,
            messages=messages,
            response_format=response_format,
            options=effective_options(self.inner, options),
            host=self.host,
        )

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        response_format: Any = None,
        options: dict[str, Any] | None = None,
    ) -> ChatResponse:
        model = model or self.inner.config.models.analyst
        key = self.key_for(messages, model=model, response_format=response_format, options=options)
        entry = self.cache.get(key, self.digest(model))
        if entry is not None:
            self.hits += 1
            return ChatResponse(
                content=entry["content"],
                model=entry["model"],
                latency_ms=entry["latency_ms"],
                prompt_tokens=entry.get("prompt_tokens"),
                completion_tokens=entry.get("completion_tokens"),
                raw={**entry.get("raw", {}), "cached": True},
            )
        self.misses += 1
        response = self.inner.chat(messages, model=model, response_format=response_format, options=options)
        self.cache.put(
            key,
            {
                "model": response.model,
                "digest": self.digest(model),
                "content": response.content,
                "latency_ms": response.latency_ms,
                "prompt_tokens": response.prompt_tokens,
                "completion_tokens": response.completion_tokens,
                "raw": {"done_reason": response.raw.get("done_reason")},
            },
        )
        return response
