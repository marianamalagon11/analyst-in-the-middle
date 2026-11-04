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

- [x] Acordar el reparto inicial de fases entre los cuatro integrantes.
- [x] Instalar Ollama en al menos dos equipos del equipo y verificar `ollama --version`. **Segundo equipo: Apple M5 de Juan Sebastián** (Ollama 0.40.13, inferencia en GPU, 26–28 tok/s, determinista): [results/setup_report_m5.md](results/setup_report_m5.md).
- [x] Descargar los modelos: `ollama pull llama3.1:8b-instruct-q4_K_M`, `mistral:7b-instruct`, `qwen2.5:7b-instruct`.
- [x] Medir y anotar en una tabla cuánto tarda cada modelo en una petición de prueba en cada equipo (define cuántos experimentos aguantamos).
- [x] Crear el entorno virtual (`python -m venv .venv`) y el `pyproject.toml` con las dependencias base: `requests`, `pydantic`, `pyyaml`, `beautifulsoup4`, `lxml`, `pypdf`, `pandas`, `matplotlib`, `pytest`.
- [x] Crear el esqueleto de carpetas descrito en `docs/ARCHITECTURE.md` (con `.gitkeep` donde haga falta).
- [x] Escribir `config.yaml` inicial: modelos, `seed`, `temperature: 0`, `num_ctx`, rutas, lista de defensas activas.
- [x] Implementar `src/aitm/config.py` que carga y valida `config.yaml` y calcula su hash.
- [x] Implementar `src/aitm/llm/ollama_client.py` con una llamada mínima a `/api/chat` y probar que responde.
- [x] Verificar determinismo: la misma petición dos veces con la misma semilla debe dar la misma salida; anotar el resultado.
- [x] Actualizar el `README.md` con instrucciones de instalación y ejecución.

> **Estado (2026-11-01):** la parte técnica de la Fase 0 está cerrada y verificada en el
> portátil de Mariana; el reporte de la medición está en
> [results/setup_report.md](results/setup_report.md). Quedan abiertas solo las dos
> casillas que dependen del equipo: el reparto de fases y tener Ollama en un segundo
> equipo. Lo segundo importa más de lo que parece: aquí la inferencia corre 100 % en CPU
> (~1–1,7 tok/s) y un equipo con GPU cambiaría el tamaño de los experimentos de las
> fases 3 y 5.
>
> **Medición clave:** un análisis real cuesta **7,7 min** con el modelo más rápido
> (mistral), ~20 min con `llama3.1`. La matriz completa que plantea la arquitectura son
> 9.450 análisis = más de 1.200 h de cómputo, así que **no cabe**. En
> [results/setup_report.md](results/setup_report.md) está la propuesta de matriz
> reducida (262 análisis, ~36 h) para revisar en equipo antes de la Fase 3.

## Fase 1 — Dataset

- [x] Revisar [Awesome-Cybersecurity-Datasets](https://github.com/shramos/Awesome-Cybersecurity-Datasets) y Hugging Face; anotar en `docs/` las 3–4 fuentes candidatas con su licencia.
- [x] Elegir la fuente principal y justificar la elección en una nota breve (entra al informe).
- [x] Descargar los reportes a `data/raw/` y cubrir los tres formatos (txt, html, pdf). **Ajustado: 12 reportes en vez de 20–30**, por el presupuesto de cómputo y de horas de etiquetado; los tres formatos se generan desde el mismo texto (ver [docs/DATASET.md](docs/DATASET.md), sección 3).
- [x] Escribir `scripts/fetch_dataset.py` para que la descarga sea reproducible.
- [x] Implementar `src/aitm/analyst/parsers.py` (txt/html/pdf → texto normalizado) y probarlo con los reportes descargados.
- [x] Escribir un extractor de IoCs por regex (IPs, dominios, URLs, hashes, CVEs, correos) como apoyo al etiquetado.
- [x] Definir el formato de `data/labels/<report_id>.json` (IoCs + veredicto, severidad, técnicas ATT&CK).
- [x] Etiquetar los 12 reportes: veredicto por indicador, exclusiones con motivo, severidad y actor. **Ajustado: lo hizo un solo integrante** en vez de repartirse entre los cuatro (165 indicadores, rúbrica de severidad en [docs/DATASET.md](docs/DATASET.md) sección 6).
- [x] **Firmar cada reporte:** una persona distinta del anotador lo revisa, se agrega en `reviewers` y pone `status: reviewed`. El esquema no permite congelar sin esto. **(responsable: quien haga la Fase 2)** Firmadas las 12 por Juan Sebastián Ortega; la revisión cambió seis etiquetas (tres URLs de entrega mal excluidas, un C2 que faltaba, `1.1.1.1` mal marcado). Detalle en [docs/DATASET.md](docs/DATASET.md), sección 6.
- [x] Medir el acuerdo entre revisores en una muestra y anotar las discrepancias resueltas. Herramienta lista: `python scripts/agreement.py --other data/labels_b --sample 4` (Jaccard, acuerdo de veredicto y kappa de Cohen). Los dos etiquetados tienen que hacerse sin verse. **(responsable: quien haga la Fase 2)** Muestra de 4 reportes, uno por vendor; segundo etiquetado (Juan Sebastián Ortega) desde el borrador del extractor: **kappa 1,00** en 55 veredictos, severidad 4/4, una discrepancia (actor de Taurus) resuelta. No fue ciego del todo: [results/tables/agreement.md](results/tables/agreement.md).
- [x] Congelar el dataset etiquetado y documentar su composición. Herramienta lista: `python scripts/freeze_dataset.py` (exige las 12 firmas, escribe las huellas sha256 en `data/labels/FROZEN.json` y la tabla de composición en `results/tables/dataset_composition.md`). **(responsable: quien haga la Fase 2)** Congelado el 2026-11-02: 171 indicadores (154 `malicious`, 14 `benign`, 3 `suspicious`), 108 exclusiones, 119 técnicas.

> **Estado (2026-11-01):** la Fase 1 está hecha salvo la firma. Fuente elegida y
> justificada, dataset construido (12 reportes × 3 formatos, manifiesto con sha256),
> parsers, extractor de IoCs, esquema de ground truth y **el etiquetado completo: 165
> indicadores con veredicto, 82 exclusiones motivadas, 119 técnicas ATT&CK, y severidad
> y actor por reporte** (1 `critical`, 9 `high`, 2 `medium`). Todo en
> [docs/DATASET.md](docs/DATASET.md).
>
> Quedan tres casillas, las tres encadenadas a una sola cosa: **que una persona firme**.
> El etiquetado lo hizo un solo integrante, así que el esquema exige un revisor distinto
> antes de congelar. Después de firmar, el acuerdo y el congelado son un comando cada
> uno. Si la Fase 1 ya cambió de manos, esa firma le toca a quien haga la Fase 2.
>
> ```bash
> python scripts/validate_labels.py        # qué falta por firmar
> python scripts/freeze_dataset.py --check # si ya se puede cerrar la fase
> ```
>
> **Estado (2026-11-02, Juan Sebastián):** preparado todo lo que no es la firma humana.
> - `annotators` ya dice `Mariana Malagón` en las 12 etiquetas (antes decía
>   "integrante del equipo", con lo que la regla revisor ≠ anotador no protegía nada).
> - Corregidos dos bugs que rompían la reproducibilidad entre equipos:
>   `fetch_dataset.py` no descargaba nada en un clon nuevo (miraba solo el manifiesto
>   versionado) y verificaba el sha256 del zip, que GitHub regenera; ahora usa una
>   huella del contenido. Y el `config_hash` daba distinto en Windows y en macOS por
>   el separador de rutas.
> - Corpus verificado en el segundo equipo: los 12 textos son idénticos byte a byte a
>   los etiquetados. El PDF ahora es determinista (`invariant`).
> - Acuerdo entre revisores: el flujo documentado copiaba `data/labels/` como punto de
>   partida, lo que ancla al segundo etiquetador. Ahora parte del borrador del
>   extractor (`draft_labels.py --out`). Borradores ciegos de la muestra (4 reportes,
>   un vendor cada uno) en `data/labels_b/`.
>
> **Fase 1 cerrada (2026-11-02).** Acuerdo medido, 12 etiquetas firmadas por Juan
> Sebastián Ortega y dataset congelado. Método completo en DATASET.md, sección 6,
> "Cómo se construyó".

## Fase 2 — Analista LLM base y línea base

- [x] **Antes de medir nada: revisar y firmar el ground truth de la Fase 1.** Leer las 12 etiquetas de `data/labels/`, corregir los veredictos y severidades que no se compartan, agregarse en `reviewers` y pasar `status` a `reviewed`; luego congelar con `python scripts/freeze_dataset.py`. Quien haga esta fase es responsable del ground truth que va a usar como referencia: una etiqueta en `assisted` la decidió una sola persona y nadie más la ha verificado. Criterios en la sección 6 de [docs/DATASET.md](docs/DATASET.md).
- [x] Escribir el system prompt base del analista en `src/aitm/llm/prompts/analyst_base.md`. En español; sin ninguna instrucción anti-inyección (eso es `analyst_hardened.md`, Fase 4).
- [x] Implementar `src/aitm/analyst/schema.py` (modelos Pydantic del JSON definido en la arquitectura).
- [x] Implementar `src/aitm/analyst/pipeline.py`: parser → prompt → Ollama (`format` = esquema) → objeto validado. Ganchos `pre_hooks` / `message_builder` / `post_hooks` listos y vacíos para la Fase 4.
- [x] Añadir el comando `aitm analyze <ruta>` en `src/aitm/cli.py` y probarlo con un reporte real. También `aitm evaluate <run-dir>`.
- [x] Implementar el guardado de trazas en `results/runs/<timestamp>/*.jsonl` con latencia y hash de configuración (`src/aitm/evaluation/traces.py`; además sha256 del prompt, digest del modelo y equipo). Reanudable con `--run-dir`.
- [x] Implementar `src/aitm/evaluation/matching.py`: normalización de IoCs (defanging, mayúsculas) y emparejamiento con el ground truth.
- [x] Implementar `src/aitm/evaluation/metrics.py`: precisión/recall de IoCs, macro-F1 del veredicto, acierto de severidad, recall de ATT&CK. Con dos líneas base sin LLM: "siempre `malicious`" y el extractor regex.
- [x] Correr la línea base sobre todo el dataset limpio con los tres modelos y guardar los resultados. 108 análisis en el M5, 0 fallos; trazas en `results/runs/baseline-f2/`.
- [x] Construir la tabla de línea base por modelo y elegir el **modelo principal** del proyecto; justificar la elección. Tabla en [results/tables/baseline.md](results/tables/baseline.md); modelo principal **`llama3.1:8b-instruct-q4_K_M`** por el criterio pre-registrado (desempate apretado con mistral, justificado en [results/baseline_report.md](results/baseline_report.md)).
- [x] Anotar los modos de fallo observados sin ataque (alucinaciones, IoCs partidos, severidad inestable) — material para "Observaciones experimentales". En [results/baseline_report.md](results/baseline_report.md): nunca dicen `benign` ni `critical`, el regex supera a los tres LLM en recall de IoCs, macro-F1 de veredicto pegado a la línea base trivial.

> **Estado (2026-11-02, Juan Sebastián):** Fase 2 completa. Analista, trazas y evaluador
> funcionando; línea base de 108 análisis sobre el ground truth congelado, sin fallos.
> Modelo principal `llama3.1:8b` (el que ya traía la config). Hallazgo central: los tres
> modelos clasifican el veredicto al nivel de "responder siempre malicious" y nunca
> aciertan un `benign` ni un `critical`; para la pura extracción de IoCs el regex los
> supera. Deja la base medida para el ASR de la Fase 5.

> **Estado (2026-11-02, Juan Sebastián):** código de la fase completo y probado (106
> pruebas). Línea base corriendo en el M5: 12 reportes × 3 formatos × 3 modelos = 108
> análisis, ~100 s cada uno. Criterios de selección del modelo escritos **antes** de
> ver resultados, en [results/baseline_report.md](results/baseline_report.md), junto
> con los primeros modos de fallo (bucle de enumeración de ATT&CK con decodificación
> greedy, tipos de hash equivocados). Ajustes de config hechos en las pruebas de humo:
> `num_ctx` 12288 y `num_predict` 4096 (el prompt real del reporte más largo son 5.637
> tokens, no los ~3.200 que daba chars/4). Las métricas finales se calculan cuando se
> congele el ground truth: el evaluador es puro y se re-ejecuta sobre las mismas
> trazas, sin repetir la inferencia.

## Fase 3 — Ataques

- [x] Definir la interfaz `AttackVector` en `src/aitm/attacks/base.py` (entrada: reporte + objetivo; salida: reporte envenenado + manifiesto). Incluye los **criterios de éxito** por objetivo (`attack_succeeded`), que la Fase 5 usará para el ASR.
- [x] Escribir el catálogo de payloads en `src/aitm/attacks/payloads.py` (4 familias por objetivo: `direct_override`, `authority`, `contextual`, `format_mimic`, en español; payload canónico fijado a priori).
- [x] Implementar el vector `plaintext` y verificar manualmente su efecto en un reporte. (Efecto sobre el modelo: Fase 5; aquí se verifica que el payload llega al texto extraído.)
- [x] Implementar el vector `html_hidden` (`display:none`, `font-size:0`, texto blanco, comentarios HTML).
- [x] Implementar el vector `unicode_invisible` (tags/ASCII smuggling, zero-width, bidi). `bidi` queda como `camouflaged`, no invisible: deja las letras presentes. Solo txt/html (las fuentes del PDF no codifican esos puntos).
- [x] Implementar el vector `pdf_hidden` (metadatos y texto con render invisible).
- [x] Implementar el vector `author_note` (nota del analista / actualización falsa del reporte).
- [x] Implementar `registry.py` y el comando `aitm attack` que genera `data/poisoned/` con su manifiesto.
- [x] Verificar que cada reporte envenenado **se ve igual que el original** para un humano (captura de pantalla para el informe). PDF por píxeles (`pypdfium2`), HTML/txt por palabras visibles. Captura limpia vs envenenada en `results/figures/visual/` (byte a byte idénticas).
- [x] Generar la matriz completa de reportes envenenados: reporte × vector × objetivo. 1056 documentos; payload llega al modelo 1056/1056, invisibles se ven igual 440/440.
- [x] Escribir pruebas unitarias de los vectores (que el payload esté, que el formato siga siendo válido).

> **Estado (2026-11-02, Juan Sebastián):** Fase 3 completa. 5 vectores con sus variantes,
> catálogo de payloads, selección determinista de objetivos desde el ground truth
> congelado (`targets.py`), comando `aitm attack` y verificación de extracción + visual.
> Matriz de 1056 reportes envenenados generada; el manifiesto (`data/poisoned/manifest.jsonl`)
> y los objetivos (`data/poisoned/targets.json`) se versionan, los documentos se regeneran.
> **El efecto real de cada ataque sobre el modelo (ASR) es la Fase 5:** aquí se garantiza
> que el payload llega y que el documento se ve igual, con los criterios de éxito ya en
> código. 182 pruebas en verde.

## Fase 4 — Defensas

- [x] Definir la interfaz `Defense` en `src/aitm/defenses/base.py` (fase `pre` sobre el texto, fase `post` sobre la salida). Tres etapas (`pre`, `prompt`, `post`); `compose()` ordena por etapa y orden canónico, así que el orden de declaración no cambia el pipeline ni la clave de celda. Lo que hace cada defensa queda en la traza (`defense_notes`, `blocked`, `judge`).
- [x] Implementar `sanitizer.py`: quitar nodos ocultos por CSS, comentarios HTML, caracteres invisibles/bidi y metadatos PDF. Además, el texto PDF en modo de render invisible (reescribe el content stream) y las reglas de `<style>` con selectores simples.
- [x] Probar el sanitizador contra cada vector y anotar cuáles neutraliza por completo y cuáles no. `aitm sanitize-check` sobre los 1056 envenenados: neutraliza **100 %** de `html_hidden` y `pdf_hidden` y `unicode_invisible` en `tags`/`zero_width`; **no** neutraliza `plaintext`, `author_note` ni `bidi` (contenido visible). Costo en limpios: 36/36 idénticos. Tabla en [results/tables/sanitizer_coverage.md](results/tables/sanitizer_coverage.md).
- [x] Implementar `spotlighting.py`: delimitadores irrepetibles + system prompt reforzado (`analyst_hardened.md`). Marcas `«INICIO_REPORTE_<código>»` con código de 16 hex ausente del texto (determinista por semilla, para reproducir), marcas falsas del reporte neutralizadas y la regla repetida tras el bloque. El reforzado contiene el base línea por línea (lo verifica una prueba): solo cambia la defensa, no la tarea.
- [x] Implementar `schema_validator.py`: validación estricta + regla de que todo IoC reportado exista literalmente en el texto de entrada. Además, forma del valor según su tipo y sin duplicados. Filtra, nunca bloquea; lo descartado queda en la traza.
- [x] Escribir el prompt del juez (`judge.md`) e implementar `llm_judge.py` como segunda llamada independiente. Otro modelo (`models.judge` = qwen2.5) y otro prompt; ve el documento entre las marcas del spotlighting, no la respuesta. Bloquea si `injection` y `confidence >= judge.threshold`; si falla no bloquea (*fail-open*) y se cuenta aparte. Bloquear no borra la salida del analista.
- [x] Hacer que las defensas se activen/desactiven desde `config.yaml` y se puedan componer en cualquier orden. `defenses.enabled` o `aitm analyze --defenses a,b` (el override no cambia el hash de la config: una sola config para toda la matriz de la Fase 5). Cualquier orden da el mismo pipeline (prueba con las 24 permutaciones).
- [ ] Medir los falsos positivos del juez sobre los reportes limpios. **Herramienta lista, falta correrla en el M5** (necesita Ollama con `qwen2.5:7b-instruct`): `aitm judge --table results/tables/judge_fp.md` (36 limpios, ~minutos). Opcional, detección por vector: `aitm judge data/processed data/poisoned`.
- [x] Pruebas unitarias del sanitizador y del validador de esquema. (Más las de spotlighting y composición: 337 pruebas.)

> **Estado (2026-11-04, Juan Carlos):** interfaz de defensas y sanitizador listos.
> El sanitizador hace lo que promete y nada más: quita lo que un humano no vería, así
> que **solo puede ganar contra los vectores ocultos**. Contra `plaintext`,
> `author_note` y `bidi` el payload pasa entero (en `bidi`, quitar los controles deja
> el texto incluso más legible para el modelo); para esos quedan el spotlighting y el
> juez. Supuestos declarados en `sanitizer.py`: fondo blanco (texto blanco = oculto),
> render 3 = oculto (rompería un PDF escaneado con OCR) y CSS sin cascada (un selector
> compuesto lo rodea: ataque adaptativo, fuera de alcance). Matriz de la Fase 3
> regenerada desde cero en otro equipo: manifiesto byte a byte idéntico al
> versionado.

> **Estado (2026-11-04, Juan Carlos):** spotlighting y validador estricto listos. Una
> advertencia para leer bien la Fase 5: **el validador no puede bajar el ASR de
> nuestros cuatro objetivos.** Ninguno introduce IoCs nuevos (voltean un veredicto,
> quitan un indicador, bajan la severidad o quitan una técnica), así que la salida
> manipulada sigue siendo coherente con el texto. Su valor está contra IoCs alucinados
> o inyectados, y su costo se verá en IoCs reales perdidos por un refang mal hecho
> (`defang_error` en la línea base). El prompt reforzado y las marcas agregan ~500 tokens: con el
> reporte más largo (5.637) + `num_predict` 4.096 sigue cabiendo en `num_ctx` 12.288.
> El prompt reforzado y su plantilla no van en `config.yaml` a propósito: cambiarla
> cambia el hash y rompe la comparación con la línea base; la traza guarda su ruta y
> sha256.

> **Estado (2026-11-04, Juan Carlos):** código de la Fase 4 completo: las cuatro
> defensas, su composición y su activación por config o CLI. 350 pruebas en verde.
> Falta solo **una medición que necesita Ollama**: los falsos positivos del juez en
> los 36 limpios (comando en la casilla). En Ollama del M5:
>
> ```bash
> ollama pull qwen2.5:7b-instruct
> aitm judge --table results/tables/judge_fp.md
> ```
>
> Para la Fase 5: `aitm analyze --defenses ...` ya produce trazas con `defenses`,
> `blocked`, `judge` y `defense_notes`, y la clave de celda incluye las defensas, así
> que el runner puede recorrer `reporte × ataque × defensas × modelo` reanudando sin
> mezclar celdas. El ASR con defensa debe contar una corrida bloqueada como ataque
> fallido (y reportar aparte la tasa de bloqueo, como pide la arquitectura).

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
- [ ] Documentar en el informe **cómo se construyó el ground truth** (extracción automática, decisión por indicador, revisión independiente y acuerdo entre revisores), para que el método sea auditable. Fuente: secciones 6 y 7 de [docs/DATASET.md](docs/DATASET.md).
- [ ] Revisión cruzada entre los cuatro integrantes y corrección de estilo.
- [ ] Exportar el PDF final y verificar que las figuras se vean legibles impresas.

> **Material ya escrito que entra directo al informe** (Fases 0 y 1):
>
> | Sección del informe | De dónde sale |
> |---|---|
> | Arquitectura implementada | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), con el diagrama Mermaid de la sección 2 |
> | Alcance y limitaciones | sección 8 de `ARCHITECTURE.md` + sección 7 de [docs/DATASET.md](docs/DATASET.md) (8 limitaciones documentadas) |
> | Guía de implementación, fases 0–1 | [results/setup_report.md](results/setup_report.md) y secciones 1–6 de `DATASET.md` |
> | Observaciones experimentales, parte de hardware | [results/setup_report.md](results/setup_report.md): 7,7 min por análisis, 100 % CPU, presupuesto de cómputo |
> | Referencias | cita de AnnoCTR en la sección 8 de `DATASET.md` |
>
> No hay que redactar nada nuevo para esas partes: están en español y con el nivel de
> detalle del enunciado.
