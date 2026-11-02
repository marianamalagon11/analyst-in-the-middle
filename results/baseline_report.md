# Línea base del analista (Fase 2)

Analista LLM sin ataques y sin defensas sobre el dataset limpio: 12 reportes × 3
formatos × 3 modelos = 108 análisis. Este documento tiene tres partes, escritas en este
orden:

1. **Criterios de selección del modelo principal**, fijados *antes* de correr la línea
   base, para que la elección no se acomode a los resultados.
2. **Resultados y elección**.
3. **Modos de fallo observados**, material para "Observaciones experimentales".

---

## 1. Criterios de selección (pre-registrados, 2026-11-02)

**Elegibilidad.** Un modelo queda fuera si más del 10 % de sus análisis fallan (JSON
inválido tras los reintentos, JSON cortado u Ollama caído). Un analista que no responde
no sirve, por bien que lo haga cuando responde.

**Puntaje.** Promedio simple de cuatro métricas sobre los 36 análisis de cada modelo
(definiciones en `src/aitm/evaluation/metrics.py`):

| Métrica | Por qué entra |
|---|---|
| F1 de IoCs (micro) | Extraer los indicadores es la tarea principal; F1 penaliza tanto omitir como inventar. |
| Macro-F1 del veredicto | Clasificar lo encontrado; es lo que ataca `flip_to_benign`. |
| Severidad exacta | Es lo que ataca `downgrade_severity`. |
| Recall ATT&CK (técnica padre) | Es lo que ataca `drop_technique`. |

Las cuatro métricas corresponden a los cuatro objetivos de ataque de la Fase 3. Elegir
el modelo que mejor las hace en limpio maximiza los casos en que el reporte limpio sale
bien, que es la condición para que un ataque cuente en el ASR de la Fase 5.

**Desempate por costo.** Si los dos mejores puntajes difieren en menos de 0,03, gana el
de menor latencia p50: con presupuesto de cómputo fijo, un modelo más rápido permite
una matriz de experimentos más grande.

**Restricción conocida para la Fase 4.** El juez (`models.judge`) debe ser un modelo
distinto del analista (ARCHITECTURE.md, sección 7). Hoy el juez es `qwen2.5`; si el
analista elegido es `qwen2.5`, la Fase 4 tiene que cambiar el juez.

**Advertencia.** Las métricas finales se calculan sobre el ground truth **congelado**.
La inferencia se puede correr antes de la firma porque el evaluador es puro: cuando se
congele, `aitm evaluate` se vuelve a ejecutar sobre las mismas trazas sin llamar al LLM.

### Ajustes del pipeline hechos antes de la línea base

Hechos durante las pruebas de humo, con un reporte por modelo. Son correcciones de
fallos del pipeline, no ajustes para mejorar el puntaje. **El prompt no se afinó
contra el dataset de evaluación**: hacerlo sería sobreajustar al conjunto con el que
se mide.

| Ajuste | Motivo observado |
|---|---|
| `num_ctx` 8192 → 12288, `num_predict` 2048 → 4096 | El reporte más largo ocupa 5.637 tokens de prompt reales (la estimación chars/4 daba 3.183): quedaban ~500 tokens de margen, que un payload de la Fase 3 no respetaría. |
| `maxItems` en las listas del esquema (50 IoCs, 25 técnicas, 5 notas) | mistral y llama3.1 entraron en bucle enumerando técnicas inventadas con IDs consecutivos hasta agotar `num_predict`, y el JSON quedó cortado. |

### Correcciones del evaluador hechas al ver la línea base

Se hicieron **después** de ver las primeras trazas de mistral, y por eso se declaran.
No tocan la inferencia (las trazas son las mismas) ni el ground truth (sigue
congelado): corrigen dos casos en que el emparejamiento clasificaba mal un error del
modelo. Las dos se aplican igual a los tres modelos.

| Corrección | Qué pasaba | Cómo se deja trazable |
|---|---|---|
| Doble punto tras el refang (`urbancinema.[.]net` → `urbancinema..net`) se colapsa en dominios, IPs y hosts de URL | mistral inserta un punto antes del `[.]` del defang. Indicadores reales se contaban como **alucinados** (14 en las primeras 34 corridas), que es otro error y otra métrica. | Cada caso queda marcado `defang_error` y se cuenta en la columna "Defang mal hecho": quien quiera el criterio estricto puede restarlos. |
| Se quita el puerto de IPs y dominios (`149.56.106.83:443`) | Los reportes publican los C2 con puerto y el modelo los copia así. El puerto no forma parte de la identidad del indicador, igual que las mayúsculas. | Prueba en `tests/test_matching.py`. |

**Lo que no se corrigió:** un hash de 63 caracteres en la tabla de IoCs del reporte de
APT-C-36 (`0d7abdd1…`, errata del vendor) no está en el ground truth porque no es un
sha256 válido. Los modelos lo reportan igual y cuenta como falso positivo: un analista
atento debería notar que no sirve.

---

## 2. Resultados

Corrida `baseline-f2`, 108 análisis (12 reportes × 3 formatos × 3 modelos), config
`08a6cd5a4a9e`, en el Apple M5. **Ninguno falló** (0 JSON inválidos o cortados). Tabla
completa en `results/tables/baseline.md`; CSV por corrida en `baseline.csv`.

| Modelo | F1 IoC | Macro-F1 veredicto | Recall `benign` | Severidad exacta | Recall ATT&CK (padre) | p50 (s) | **Puntaje** |
|---|---|---|---|---|---|---|---|
| **llama3.1:8b** | 0.70 | 0.32 | 0.00 | **0.83** | 0.30 | **70** | **0.5375** |
| mistral:7b | **0.78** | 0.33 | 0.00 | 0.69 | 0.31 | 87 | 0.5275 |
| qwen2.5:7b | 0.68 | 0.37 | 0.00 | 0.25 | 0.31 | 79 | 0.4025 |

**Líneas base sin LLM:** macro-F1 de responder siempre `malicious` = **0.32**; extractor
regex = precisión 0.80, **recall 0.95** de IoCs.

### Modelo principal elegido: `llama3.1:8b-instruct-q4_K_M`

Por el criterio pre-registrado (promedio de las cuatro métricas): llama 0.5375, mistral
0.5275, qwen 0.4025. La diferencia llama–mistral (0.010) cae bajo el umbral de 0.03, así
que decide la latencia p50, y también favorece a llama (70 s < 87 s). Es además el
analista que ya traía `config.yaml`, así que no se cambia nada.

**Pero la elección es apretada y hay que decirlo con todas sus letras:**

- **mistral es claramente el mejor extrayendo IoCs** (F1 0.78, precisión 0.97, **cero
  alucinaciones**, cero exclusiones reportadas). llama gana por la severidad (0.83 vs
  0.69), que con 12 reportes y 9 `high` es la métrica más ruidosa de las cuatro. Si el
  informe prioriza la extracción sobre la severidad, mistral es defendible; lo dejamos
  escrito para no esconder la fragilidad del desempate.
- **El dato que corrige al setup report:** en CPU, mistral era el más barato (3× más
  rápido que llama). En la GPU del M5 **llama es el más rápido** (p50 70 s). El costo
  depende del hardware, no es una propiedad del modelo.

### El hallazgo que importa para el proyecto

Los tres modelos tienen un **macro-F1 de veredicto de 0.32–0.37, es decir, pegado a la
línea base trivial de "responder siempre malicious" (0.32)**. No saben *clasificar* lo
que encuentran: solo lo encuentran. Esto importa para las fases 3–5, porque el ataque
`flip_to_benign` intenta mover un veredicto que el modelo, de entrada, casi no razona.

El regex sin LLM saca **recall 0.95** de IoCs contra el 0.62–0.66 de los modelos: para la
pura extracción de indicadores, una expresión regular supera a los tres LLM. El valor del
LLM tendría que estar en el veredicto, la severidad y ATT&CK, y ahí es donde flojea.

---

## 3. Modos de fallo observados

Material directo para "Observaciones experimentales" del informe. Medidos sobre las 108
corridas.

- **Nunca dicen `benign` ni `critical`.** De los 14 indicadores que el ground truth marca
  `benign` (recursos legítimos abusados: `powershell.exe`, `cloudflare-dns.com`,
  `battle.net`...), los modelos clasificaron como `benign` **cero**: todos como
  `malicious` o `suspicious`. Y en severidad solo predicen `high` (65 de 108) o `medium`
  (43); nunca `critical`, `low` ni `info`, así que el único reporte `critical` (TA456)
  no se detecta nunca. El analista colapsa el rango a "amenaza / amenaza menor", que es
  justo lo que los casos `benign` fueron diseñados para exponer.
- **El regex gana en extracción.** Recall 0.95 vs 0.62–0.66. El LLM omite indicadores que
  una regex no omitiría; su aporte no está en encontrar IoCs.
- **Perfiles de error opuestos entre modelos.** mistral no alucina nada pero comete el
  error de defang (`x.[.]com`, 14 casos, ya contabilizado aparte); llama y qwen sí
  alucinan (16 y 10) y reportan indicadores excluidos (21 y 22: URLs del vendor, enlaces
  de referencia), lo que hunde su precisión.
- **Bucle de enumeración de ATT&CK con decodificación greedy.** Tras 3–6 técnicas
  plausibles, mistral y llama3.1 siguen con IDs consecutivos inventados
  (`T1086.038`, `T1086.039`…; `T1362`, `T1364`, `T1366`… todas "Data Encrypted File").
  Con temperatura 0 la continuación más probable de una serie es seguir la serie. El
  tope del esquema evita que se corte el JSON, pero no el bucle: baja la precisión de
  ATT&CK y cuesta ~1.000 tokens (~40 s) por análisis.
- **Tipo de hash equivocado.** Un sha256 de 64 caracteres etiquetado como `md5`, y un
  md5 como `sha1`. El emparejamiento lo cuenta como acierto con `type_mismatch`.
- **Nombre de host como IP.** `ec2-3-134-252-78.us-east-2.compute.amazonaws.com`
  reportado como `ipv4`.
- **JSON con indentación** pese a pedirlo compacto: gasta tokens de generación en
  espacios. La gramática de Ollama permite el espacio en blanco y el esquema no lo
  puede prohibir.
