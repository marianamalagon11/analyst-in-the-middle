"""Cliente minimo para la API HTTP de Ollama.

Centraliza la semilla y los parametros de generacion: ningun otro modulo
deberia hablar con Ollama directamente, para que todas las llamadas del
laboratorio sean igual de reproducibles.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Literal

import requests

from aitm.config import Config, get_config

Role = Literal["system", "user", "assistant"]


class OllamaError(RuntimeError):
    """Fallo al hablar con Ollama (no alcanzable, timeout o error HTTP)."""


@dataclass(frozen=True)
class ChatResponse:
    content: str
    model: str
    latency_ms: int
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False)


class OllamaClient:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or get_config()
        self.host = self.config.ollama.host.rstrip("/")
        self._session = requests.Session()

    # -- introspeccion ----------------------------------------------------

    def version(self) -> str:
        return str(self._get("/api/version").get("version", "desconocida"))

    def list_models(self) -> list[str]:
        payload = self._get("/api/tags")
        return sorted(m["name"] for m in payload.get("models", []))

    def model_digest(self, name: str) -> str | None:
        """Digest de los pesos instalados con ese nombre.

        Es la huella que identifica el modelo exacto: la misma etiqueta
        (`mistral:7b-instruct`) puede apuntar a pesos distintos en dos equipos.
        """
        for model in self._get("/api/tags").get("models", []):
            if model.get("name") in (name, f"{name}:latest"):
                return model.get("digest")
        return None

    def has_model(self, name: str) -> bool:
        """Compara tolerando el sufijo `:latest` que Ollama agrega solo."""
        available = self.list_models()
        return name in available or f"{name}:latest" in available

    def is_up(self) -> bool:
        try:
            self.version()
        except OllamaError:
            return False
        return True

    # -- generacion -------------------------------------------------------

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        model: str | None = None,
        response_format: dict[str, Any] | Literal["json"] | None = None,
        options: dict[str, Any] | None = None,
    ) -> ChatResponse:
        """Una ronda de chat. `response_format` restringe la salida a JSON."""
        model = model or self.config.models.analyst
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "keep_alive": self.config.ollama.keep_alive,
            "options": self._options(options),
        }
        if response_format is not None:
            body["format"] = response_format

        started = time.perf_counter()
        payload = self._post("/api/chat", body)
        latency_ms = int((time.perf_counter() - started) * 1000)

        return ChatResponse(
            content=payload.get("message", {}).get("content", ""),
            model=payload.get("model", model),
            latency_ms=latency_ms,
            prompt_tokens=payload.get("prompt_eval_count"),
            completion_tokens=payload.get("eval_count"),
            raw=payload,
        )

    def _options(self, overrides: dict[str, Any] | None) -> dict[str, Any]:
        generation = self.config.generation
        options: dict[str, Any] = {
            "seed": self.config.seed,
            "temperature": generation.temperature,
            "top_p": generation.top_p,
            "top_k": generation.top_k,
            "repeat_penalty": generation.repeat_penalty,
            "num_ctx": generation.num_ctx,
            "num_predict": generation.num_predict,
        }
        options.update(overrides or {})
        return options

    # -- transporte -------------------------------------------------------

    def _get(self, route: str) -> dict[str, Any]:
        return self._request("GET", route, None)

    def _post(self, route: str, body: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", route, body)

    def _request(
        self, method: str, route: str, body: dict[str, Any] | None
    ) -> dict[str, Any]:
        url = f"{self.host}{route}"
        last_error: Exception | None = None

        for attempt in range(self.config.ollama.max_retries + 1):
            try:
                response = self._session.request(
                    method,
                    url,
                    json=body,
                    timeout=self.config.ollama.timeout_s,
                )
                response.raise_for_status()
                return response.json()
            except requests.RequestException as error:
                last_error = error
                # Un 4xx no mejora reintentando: modelo inexistente, body invalido.
                status = getattr(error.response, "status_code", None)
                if status is not None and 400 <= status < 500:
                    break
                if attempt < self.config.ollama.max_retries:
                    time.sleep(2**attempt)

        raise OllamaError(
            f"fallo {method} {url}: {last_error}. "
            "Revisa que Ollama este corriendo (`ollama serve`) y que el modelo exista."
        ) from last_error
