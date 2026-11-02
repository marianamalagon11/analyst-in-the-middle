# Evaluacion de `baseline-f2`

Generado: 2026-11-02T19:18:52Z · ground truth: congelado · config: `08a6cd5a4a9e`

## Por modelo

| Modelo | Corridas | Fallidas | Precision IoC | Recall IoC | F1 IoC | Alucinados | Excluidos reportados | Defang mal hecho | Macro-F1 veredicto | Recall benign | Severidad exacta | Severidad +-1 | Recall ATT&CK (padre) | Recall ATT&CK (estricto) | Latencia p50 (s) | Latencia p95 (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| llama3.1:8b-instruct-q4_K_M | 36 | 0 | 0.79 | 0.62 | 0.70 | 16 | 21 | 0 | 0.32 | 0.00 | 83% | 100% | 0.30 | 0.27 | 70 | 131 |
| mistral:7b-instruct | 36 | 0 | 0.97 | 0.66 | 0.78 | 0 | 0 | 14 | 0.33 | 0.00 | 69% | 100% | 0.31 | 0.28 | 87 | 153 |
| qwen2.5:7b-instruct | 36 | 0 | 0.73 | 0.64 | 0.68 | 10 | 22 | 0 | 0.37 | 0.00 | 25% | 100% | 0.31 | 0.23 | 79 | 188 |

## Por modelo y formato

| Modelo · formato | Corridas | Fallidas | Precision IoC | Recall IoC | F1 IoC | Alucinados | Excluidos reportados | Defang mal hecho | Macro-F1 veredicto | Recall benign | Severidad exacta | Severidad +-1 | Recall ATT&CK (padre) | Recall ATT&CK (estricto) | Latencia p50 (s) | Latencia p95 (s) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| llama3.1:8b-instruct-q4_K_M · html | 12 | 0 | 0.84 | 0.66 | 0.74 | 3 | 7 | 0 | 0.31 | 0.00 | 83% | 100% | 0.31 | 0.29 | 75 | 133 |
| llama3.1:8b-instruct-q4_K_M · pdf | 12 | 0 | 0.74 | 0.54 | 0.63 | 8 | 7 | 0 | 0.33 | 0.00 | 83% | 100% | 0.27 | 0.24 | 69 | 106 |
| llama3.1:8b-instruct-q4_K_M · txt | 12 | 0 | 0.79 | 0.67 | 0.72 | 5 | 7 | 0 | 0.33 | 0.00 | 83% | 100% | 0.32 | 0.29 | 65 | 129 |
| mistral:7b-instruct · html | 12 | 0 | 0.95 | 0.61 | 0.75 | 0 | 0 | 0 | 0.33 | 0.00 | 75% | 100% | 0.29 | 0.27 | 87 | 140 |
| mistral:7b-instruct · pdf | 12 | 0 | 0.98 | 0.77 | 0.86 | 0 | 0 | 0 | 0.33 | 0.00 | 58% | 100% | 0.32 | 0.29 | 82 | 205 |
| mistral:7b-instruct · txt | 12 | 0 | 0.96 | 0.59 | 0.73 | 0 | 0 | 14 | 0.33 | 0.00 | 75% | 100% | 0.30 | 0.28 | 89 | 121 |
| qwen2.5:7b-instruct · html | 12 | 0 | 0.68 | 0.59 | 0.63 | 7 | 8 | 0 | 0.32 | - | 25% | 100% | 0.30 | 0.24 | 81 | 160 |
| qwen2.5:7b-instruct · pdf | 12 | 0 | 0.76 | 0.67 | 0.71 | 0 | 7 | 0 | 0.32 | 0.00 | 25% | 100% | 0.33 | 0.24 | 78 | 173 |
| qwen2.5:7b-instruct · txt | 12 | 0 | 0.74 | 0.66 | 0.70 | 3 | 7 | 0 | 0.66 | - | 25% | 100% | 0.29 | 0.23 | 73 | 155 |

## Lineas base sin LLM

- Macro-F1 de responder siempre `malicious`: **0.32**
- Extractor regex (`aitm.analyst.iocs`, sin la lista de ruido):

| Formato | Precision IoC | Recall IoC |
|---|---|---|
| html | 0.80 | 0.95 |
| pdf | 0.80 | 0.95 |
| todos | 0.80 | 0.95 |
| txt | 0.80 | 0.95 |

Precision y recall de IoCs en *micro* (sumando todos los reportes). Las corridas
fallidas cuentan como analisis vacio. Definiciones en `src/aitm/evaluation/metrics.py`.
