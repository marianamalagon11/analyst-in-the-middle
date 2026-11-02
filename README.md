# analyst-in-the-middle
Prompt injection project against LLM-based CTI analysts: poisoning threat reports to fool the model and evaluating defenses. Python + Ollama.

## Equipo

Proyecto final de **Inteligencia de Amenazas Cibernéticas** — Maestría en Informática,
Escuela Colombiana de Ingeniería Julio Garavito.

- Juan Carlos Leal
- Juan Sebastián Ortega
- Mariana Malagón
- Raúl Moreno

## Documentación

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — arquitectura, componentes, formato JSON de salida y decisiones técnicas.
- [ROADMAP.md](ROADMAP.md) — plan de trabajo por fases.

## Requisitos

- Python 3.10 o superior.
- [Ollama](https://ollama.com/download) corriendo en local (`http://localhost:11434`).
- Unos 15 GB libres en disco para los tres modelos de 7–8B cuantizados.

## Instalación

```bash
git clone <url-del-repo>
cd analyst-in-the-middle

python -m venv .venv
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

pip install -e ".[dev]"
```

Descarga de los modelos (una sola vez, ~15 GB en total):

```bash
ollama pull llama3.1:8b-instruct-q4_K_M
ollama pull mistral:7b-instruct
ollama pull qwen2.5:7b-instruct
```

## Verificación del entorno

```bash
python scripts/check_setup.py            # config + Ollama + los tres modelos
python scripts/check_setup.py --quick    # solo el modelo analista
python scripts/check_setup.py --no-llm   # solo valida config.yaml
```

El script comprueba que `config.yaml` sea válido, que Ollama responda, que los modelos estén
descargados, mide la latencia de cada uno y verifica el **determinismo** (dos llamadas
idénticas con la misma semilla deben dar la misma salida). Escribe el resultado en
`results/setup_report.md`.

Pruebas:

```bash
pytest
```

## Configuración

Todo lo que afecta un resultado vive en [`config.yaml`](config.yaml): modelos, semilla,
temperatura, ventana de contexto, defensas activas, vectores de ataque y rutas. Cada corrida
guarda el hash de esa configuración para poder reconstruirla después.

## Estado

Fase 0 (setup) completa. Fase 1 (dataset) en curso — ver [ROADMAP.md](ROADMAP.md).
