# Reporte de setup (Fase 0)

Generado: 2026-11-02 16:09 UTC  
Hash de configuracion: `52daeb40e2df`  
Equipo: Apple M5 (10 hilos, 16.0 GB RAM), Darwin 27.0.0

| Modelo | Disponible | Latencia frio (ms) | Latencia caliente (ms) | Tokens | tok/s | Determinista |
|---|---|---|---|---|---|---|
| `llama3.1:8b-instruct-q4_K_M` | si | 6182 | 2384 | 63 | 26.43 | si |
| `mistral:7b-instruct` | si | 3191 | 1195 | 34 | 28.45 | si |
| `qwen2.5:7b-instruct` | si | 3528 | 1449 | 41 | 28.3 | si |

La latencia en caliente es la que sirve para estimar cuanto dura un
experimento: en una corrida larga el modelo ya esta cargado en memoria.
