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

---

## 2. Resultados

*(Pendiente: se llena al terminar la corrida.)*

---

## 3. Modos de fallo observados

*(Se completa con la línea base. Ya vistos en las pruebas de humo:)*

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
