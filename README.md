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
- [docs/DATASET.md](docs/DATASET.md) — fuentes candidatas y sus licencias, fuente elegida, composición del dataset y formato del ground truth.
- [ROADMAP.md](ROADMAP.md) — plan de trabajo por fases.
- [results/setup_report.md](results/setup_report.md) — medición del equipo: latencia, determinismo y presupuesto de cómputo.

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

## Dataset

El corpus no se versiona (material de terceros, decenas de MB): se reconstruye con dos
comandos. Detalles y justificación en [docs/DATASET.md](docs/DATASET.md).

```bash
python scripts/fetch_dataset.py      # corpus AnnoCTR, commit fijado (~88 MB)
python scripts/build_dataset.py      # selecciona 12 reportes y los renderiza a txt/html/pdf
python scripts/build_dataset.py --dry-run   # solo muestra qué elegiría
```

Ground truth (`data/labels/`, un JSON por reporte, sí versionado):

```bash
python scripts/draft_labels.py            # borradores pre-llenados desde el extractor
python scripts/validate_labels.py         # esquema, cobertura y consistencia con el texto
python scripts/agreement.py --other data/labels_b --sample 4   # acuerdo entre revisores
python scripts/freeze_dataset.py          # congela y escribe la composición final
```

Las etiquetas pasan por cuatro estados: `draft` (salida del extractor) →
`assisted` (un integrante decidió veredicto por indicador y severidad) → `reviewed` (firmada
por una segunda persona) → `frozen` (congelada, con huellas sha256). Solo las dos
últimas sirven para medir, y el esquema **no permite que el revisor sea la misma persona
que anotó**. Criterios de severidad y convenciones de veredicto en la sección 6 de
[docs/DATASET.md](docs/DATASET.md).

Los scripts protegen el trabajo manual: `draft_labels.py` nunca sobreescribe una
etiqueta existente sin `--force`, y `build_dataset.py` se niega a reconstruir el dataset
si ya hay etiquetas firmadas, porque eso cambiaría la selección y las dejaría huérfanas.

## Medición de capacidad

```bash
python scripts/bench_analyst.py                          # costo real de un análisis
python scripts/bench_analyst.py --model mistral:7b-instruct
```

En el equipo de referencia (i5-1135G7, sin GPU) un análisis cuesta **7,7 min**. De ahí
sale el tamaño de los experimentos de las fases 3 y 5; ver
[results/setup_report.md](results/setup_report.md).

## Defensas (Fase 4)

Cuatro defensas componibles (`src/aitm/defenses/`): `sanitizer` (quita lo que un
humano no vería: HTML oculto, comentarios, Unicode invisible, metadatos y texto
invisible del PDF), `spotlighting` (reporte entre marcas irrepetibles + prompt
reforzado), `schema_validation` (todo IoC debe estar literalmente en el texto) y
`llm_judge` (un segundo modelo decide si el documento trae inyección).

```bash
aitm analyze data/processed --defenses sanitizer,spotlighting   # o defenses.enabled en config.yaml
aitm analyze data/processed --defenses none                     # sin defensas
aitm sanitize-check --table results/tables/sanitizer_coverage.md   # qué vectores neutraliza (sin LLM)
aitm judge --table results/tables/judge_fp.md                   # falsos positivos del juez en limpios
aitm judge data/processed data/poisoned                         # + detección por vector
aitm judge --run-dir results/runs/<ts> --regrade                # re-aplica la regla de evidencia, sin LLM
```

`sanitize-check` y `judge` sobre envenenados necesitan la matriz de la Fase 3 en
`data/poisoned/` (`aitm attack` la regenera, idéntica al manifiesto versionado).

## Experimentos (Fase 5)

Cuatro experimentos declarados en `experiments/*.yaml` antes de correr. `aitm run` los
ejecuta (reanudable con el mismo comando) y `aitm report` calcula el ASR, el costo de las
defensas, las tablas (`results/tables/exp*`) y las gráficas (`results/figures/`) sin LLM.

```bash
aitm run experiments/e1_vectores.yaml --dry-run   # celdas, inferencias nuevas y horas estimadas
aitm run experiments/e1_vectores.yaml             # Ctrl+C y se retoma con el mismo comando
aitm run experiments/e3_defensas.yaml
aitm run experiments/e4_combinadas.yaml
aitm run experiments/e2_modelos.yaml              # independiente: puede ir en otro equipo
aitm report
```

El laboratorio es determinista, así que una petición idéntica a una ya hecha **en el mismo
equipo** sale de una cache (`results/runs/_cache/`) en vez de volver a inferirse. Diseño
reducido (6 reportes, `flip_to_benign`): en orden E1 → E3 → E4 son 108 análisis y 54
consultas al juez (~1,5 h en una GPU T4); E2, opcional, 96 análisis más.

**Sin GPU propia:** [`experiments/fase5_kaggle.ipynb`](experiments/fase5_kaggle.ipynb) hace
todo en Kaggle (GPU gratuita) de forma desatendida con *Save & Run All*, y deja
`resultados_fase5.zip` en la salida. Descomprimirlo en la raíz del repo y correr `aitm report`.
Resultados y observaciones de la corrida: [results/phase5_report.md](results/phase5_report.md).

## Configuración

Todo lo que afecta un resultado vive en [`config.yaml`](config.yaml): modelos, semilla,
temperatura, ventana de contexto, defensas activas, vectores de ataque y rutas. Cada corrida
guarda el hash de esa configuración para poder reconstruirla después.

## Estado

Fases 0 y 1 cerradas. Dataset congelado: 12 reportes × 3 formatos, 171 indicadores
etiquetados, 119 técnicas ATT&CK y la severidad de cada reporte, anotado por Mariana
Malagón y revisado y firmado por Juan Sebastián Ortega (método en la sección 6 de
[docs/DATASET.md](docs/DATASET.md)). Fase 2: analista LLM,
trazas, evaluador y línea base de 108 análisis (modelo principal `llama3.1:8b`). Fase 3:
1056 reportes envenenados con 5 vectores. Fase 4: cuatro defensas componibles; el juez bloquea
el 17 % de los reportes limpios (`results/tables/judge_fp.md`). Fase 5: corrida en Kaggle,
ASR 0 % en todas las configuraciones con el payload canónico; el juez detecta la mitad de
los ataques y bloquea 5/18 limpios ([results/phase5_report.md](results/phase5_report.md)). Ver [ROADMAP.md](ROADMAP.md).
