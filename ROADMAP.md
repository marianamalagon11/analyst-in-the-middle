# ROADMAP — `analyst-in-the-middle` (poisoned-intel)

Proyecto final de **Inteligencia de Amenazas Cibernéticas** 
Escuela Colombiana de Ingeniería Julio Garavito.

**Integrantes:** Juan Carlos Leal · Juan Sebastián Ortega · Mariana Malagón · Raúl Moreno

**Fecha de inicio:** 2026-11-01 · 

Cada casilla debería poder terminarse en una sesión de trabajo. Arquitectura y decisiones
técnicas: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

> **Convención de trabajo:** se trabaja desde la rama `develop`. Los commits los hace el
> equipo, no herramientas automáticas.

---

## Fase 0 — Setup

- [ ] Acordar el reparto inicial de fases entre los cuatro integrantes.
- [ ] Instalar Ollama en al menos dos equipos del equipo y verificar `ollama --version`.
- [ ] Descargar los modelos: `ollama pull llama3.1:8b-instruct-q4_K_M`, `mistral:7b-instruct`, `qwen2.5:7b-instruct`.
- [ ] Medir y anotar en una tabla cuánto tarda cada modelo en una petición de prueba en cada equipo (define cuántos experimentos aguantamos).
- [ ] Crear el entorno virtual (`python -m venv .venv`) y el `pyproject.toml` con las dependencias base: `requests`, `pydantic`, `pyyaml`, `beautifulsoup4`, `lxml`, `pypdf`, `pandas`, `matplotlib`, `pytest`.
- [ ] Crear el esqueleto de carpetas descrito en `docs/ARCHITECTURE.md` (con `.gitkeep` donde haga falta).
- [ ] Escribir `config.yaml` inicial: modelos, `seed`, `temperature: 0`, `num_ctx`, rutas, lista de defensas activas.
- [ ] Implementar `src/aitm/config.py` que carga y valida `config.yaml` y calcula su hash.
- [ ] Implementar `src/aitm/llm/ollama_client.py` con una llamada mínima a `/api/chat` y probar que responde.
- [ ] Verificar determinismo: la misma petición dos veces con la misma semilla debe dar la misma salida; anotar el resultado.
- [ ] Actualizar el `README.md` con instrucciones de instalación y ejecución.

## Fase 1 — Dataset

- [ ] Revisar [Awesome-Cybersecurity-Datasets](https://github.com/shramos/Awesome-Cybersecurity-Datasets) y Hugging Face; anotar en `docs/` las 3–4 fuentes candidatas con su licencia.
- [ ] Elegir la fuente principal y justificar la elección en una nota breve (entra al informe).
- [ ] Descargar 20–30 reportes CTI reales a `data/raw/`, cubriendo los tres formatos (txt, html, pdf).
- [ ] Escribir `scripts/fetch_dataset.py` para que la descarga sea reproducible.
- [ ] Implementar `src/aitm/analyst/parsers.py` (txt/html/pdf → texto normalizado) y probarlo con los reportes descargados.
- [ ] Escribir un extractor de IoCs por regex (IPs, dominios, URLs, hashes, CVEs, correos) como apoyo al etiquetado.
- [ ] Definir el formato de `data/labels/<report_id>.json` (IoCs + veredicto, severidad, técnicas ATT&CK).
- [ ] Etiquetar a mano los reportes, repartidos entre los cuatro; cada reporte revisado por una segunda persona.
- [ ] Medir el acuerdo entre revisores en una muestra y anotar las discrepancias resueltas.
- [ ] Congelar el dataset etiquetado y documentar su composición (nº de reportes por formato, nº de IoCs, distribución de severidad).

## Fase 2 — Analista LLM base y línea base

- [ ] Escribir el system prompt base del analista en `src/aitm/llm/prompts/analyst_base.md`.
- [ ] Implementar `src/aitm/analyst/schema.py` (modelos Pydantic del JSON definido en la arquitectura).
- [ ] Implementar `src/aitm/analyst/pipeline.py`: parser → prompt → Ollama (`format` = esquema) → objeto validado.
- [ ] Añadir el comando `aitm analyze <ruta>` en `src/aitm/cli.py` y probarlo con un reporte real.
- [ ] Implementar el guardado de trazas en `results/runs/<timestamp>/*.jsonl` con latencia y hash de configuración.
- [ ] Implementar `src/aitm/evaluation/matching.py`: normalización de IoCs (defanging, mayúsculas) y emparejamiento con el ground truth.
- [ ] Implementar `src/aitm/evaluation/metrics.py`: precisión/recall de IoCs, macro-F1 del veredicto, acierto de severidad, recall de ATT&CK.
- [ ] Correr la línea base sobre todo el dataset limpio con los tres modelos y guardar los resultados.
- [ ] Construir la tabla de línea base por modelo y elegir el **modelo principal** del proyecto; justificar la elección.
- [ ] Anotar los modos de fallo observados sin ataque (alucinaciones, IoCs partidos, severidad inestable) — material para "Observaciones experimentales".

## Fase 3 — Ataques

- [ ] Definir la interfaz `AttackVector` en `src/aitm/attacks/base.py` (entrada: reporte + objetivo; salida: reporte envenenado + manifiesto).
- [ ] Escribir el catálogo de payloads en `src/aitm/attacks/payloads.py` (3–5 redacciones por objetivo: `flip_to_benign`, `omit_ioc`, `downgrade_severity`, `drop_technique`).
- [ ] Implementar el vector `plaintext` y verificar manualmente su efecto en un reporte.
- [ ] Implementar el vector `html_hidden` (`display:none`, `font-size:0`, texto blanco, comentarios HTML).
- [ ] Implementar el vector `unicode_invisible` (zero-width y caracteres bidi).
- [ ] Implementar el vector `pdf_hidden` (metadatos y texto con render invisible).
- [ ] Implementar el vector `author_note` (nota del analista / actualización falsa del reporte).
- [ ] Implementar `registry.py` y el comando `aitm attack` que genera `data/poisoned/` con su manifiesto.
- [ ] Verificar que cada reporte envenenado **se ve igual que el original** para un humano (captura de pantalla para el informe).
- [ ] Generar la matriz completa de reportes envenenados: reporte × vector × objetivo.
- [ ] Escribir pruebas unitarias de los vectores (que el payload esté, que el formato siga siendo válido).

## Fase 4 — Defensas

- [ ] Definir la interfaz `Defense` en `src/aitm/defenses/base.py` (fase `pre` sobre el texto, fase `post` sobre la salida).
- [ ] Implementar `sanitizer.py`: quitar nodos ocultos por CSS, comentarios HTML, caracteres invisibles/bidi y metadatos PDF.
- [ ] Probar el sanitizador contra cada vector y anotar cuáles neutraliza por completo y cuáles no.
- [ ] Implementar `spotlighting.py`: delimitadores irrepetibles + system prompt reforzado (`analyst_hardened.md`).
- [ ] Implementar `schema_validator.py`: validación estricta + regla de que todo IoC reportado exista literalmente en el texto de entrada.
- [ ] Escribir el prompt del juez (`judge.md`) e implementar `llm_judge.py` como segunda llamada independiente.
- [ ] Hacer que las defensas se activen/desactiven desde `config.yaml` y se puedan componer en cualquier orden.
- [ ] Medir los falsos positivos del juez sobre los reportes limpios.
- [ ] Pruebas unitarias del sanitizador y del validador de esquema.

## Fase 5 — Experimentos y métricas

- [ ] Implementar `src/aitm/evaluation/runner.py`: ejecuta la matriz `reporte × ataque × defensas × modelo` y reanuda si se interrumpe.
- [ ] Definir el criterio exacto de "ataque exitoso" por cada objetivo y dejarlo escrito en código y en el informe.
- [ ] Implementar el cálculo de **ASR** condicionado a que el reporte limpio sí dé el resultado correcto.
- [ ] Correr el experimento 1: ASR por vector, sin defensas, modelo principal.
- [ ] Correr el experimento 2: ASR por vector y por modelo (los tres), sin defensas.
- [ ] Correr el experimento 3: ASR con cada defensa por separado.
- [ ] Correr el experimento 4: ASR con todas las defensas combinadas.
- [ ] Correr el experimento 5: costo de las defensas (exactitud sobre reportes limpios, FP del juez, latencia p50/p95).
- [ ] Implementar `plots.py` y generar las gráficas: ASR por vector, ASR por modelo, ASR por defensa, exactitud vs. latencia.
- [ ] Exportar las tablas a `results/tables/` en CSV y Markdown.
- [ ] Redactar las observaciones experimentales: qué vector fue más efectivo, qué defensa aportó más, qué nos sorprendió.
- [ ] Guardar las trazas de 2–3 casos ilustrativos (prompt + salida) para mostrarlos tal cual en la sustentación.

## Fase 6 — Demo para la sustentación

- [ ] Elegir el reporte de la demo (uno visual, con un dominio malicioso claro).
- [ ] Preparar las tres versiones: limpia, envenenada y envenenada con defensas activas.
- [ ] Implementar `aitm demo` que corra los tres casos en secuencia y muestre el diff del veredicto en consola.
- [ ] Cronometrar la demo completa: debe durar menos de 8 minutos en el portátil que se use.
- [ ] Precalentar los modelos y dejar un plan B: trazas grabadas por si Ollama falla en vivo.
- [ ] Armar las diapositivas de apoyo (problema, arquitectura, resultados, conclusiones) y repartir quién habla de qué.
- [ ] Ensayo general completo con los cuatro integrantes, cronometrado a 30 minutos.

## Fase 7 — Informe final en PDF

- [ ] Montar la plantilla del informe en `docs/informe/` y definir la herramienta de exportación a PDF.
- [ ] Redactar el **Resumen ejecutivo**.
- [ ] Redactar los **Objetivos** (general y específicos).
- [ ] Redactar el **Alcance y limitaciones** (partir de la sección 8 de `ARCHITECTURE.md`).
- [ ] Redactar la **Arquitectura implementada** e incluir el diagrama de alto nivel exportado como imagen.
- [ ] Redactar la **Guía a alto nivel de los pasos de implementación** (resumen de las fases 0 a 5).
- [ ] Redactar las **Observaciones experimentales** con las tablas y gráficas de la fase 5.
- [ ] Redactar las **Conclusiones** y el trabajo futuro (ataques adaptativos, modelos más grandes).
- [ ] Añadir referencias: artículo guía de Medium, fuente del dataset, MITRE ATT&CK, literatura de prompt injection.
- [ ] Añadir una nota de uso ético y responsable del material de ataque.
- [ ] Revisión cruzada entre los cuatro integrantes y corrección de estilo.
- [ ] Exportar el PDF final y verificar que las figuras se vean legibles impresas.
