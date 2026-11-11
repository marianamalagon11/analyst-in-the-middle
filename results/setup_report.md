# Reporte de setup (Fase 0)

Generado: 2026-11-02 03:19 UTC  
Hash de configuracion al medir la tabla: `00983a6da8e3`  
Hash tras subir `timeout_s`: `4c67d6307bfa`  
Equipo de referencia: Intel Core i5-1135G7 (4 nucleos / 8 hilos), 11,7 GB RAM,
grafica integrada Intel Iris Xe (sin VRAM dedicada utilizable), Windows 11.  
Version de Ollama: 0.40.13

| Modelo | Disponible | Latencia frio (ms) | Latencia caliente (ms) | Tokens | Determinista |
|---|---|---|---|---|---|
| `llama3.1:8b-instruct-q4_K_M` | si | 169230 | 58014 | 63 | si |
| `mistral:7b-instruct` | si | 88953 | 19715 | 34 | si |
| `qwen2.5:7b-instruct` | si | 139100 | 26189 | 38 | si |

La latencia en caliente es la que sirve para estimar cuanto dura un
experimento: en una corrida larga el modelo ya esta cargado en memoria.


## Hallazgo: la inferencia corre 100% en CPU

`ollama ps` reporta `100% CPU` para los tres modelos: la Iris Xe no es una GPU que
Ollama pueda usar para inferencia, y con 11,7 GB de RAM solo cabe un modelo cargado a
la vez. Eso deja el rendimiento en ~1-1,7 tokens/s segun el modelo.

Consecuencia practica: `ollama.timeout_s` se subio de 300 a 1800 s en `config.yaml`,
porque un analisis real no cabe en 5 minutos, y la matriz de experimentos de las
fases 3 y 5 hay que dimensionarla con el costo medido abajo, no con la prueba corta
de la tabla anterior.

## Determinismo

Los tres modelos devolvieron una salida identica byte a byte al repetir la misma
peticion con `seed: 1337`, `temperature: 0`, `top_k: 1`. La reproducibilidad que pide
el enunciado queda confirmada en este equipo.

## Costo real de UN analisis (lo que define el tamano del proyecto)

`scripts/bench_analyst.py --model mistral:7b-instruct` sobre un reporte sintetico de
~1.900 tokens con la densidad de IoCs de un reporte de vendor, pidiendo el JSON
completo del analista:

| Etapa | Tiempo | Detalle |
|---|---|---|
| Cargar el modelo | 12,7 s | solo en la primera peticion de la corrida |
| Leer el prompt | 129,2 s | 2.761 tokens a 21,4 tok/s |
| Generar el JSON | 318,4 s | 930 tokens a 2,9 tok/s |
| **Total** | **462,4 s (7,7 min)** | JSON valido: 7 IoCs, severidad `critical` |

Capacidad del equipo con el modelo **mas rapido** de los tres:

- **7,7 min por analisis**
- ~31 analisis en una sesion de 4 h
- ~77 analisis en un dia completo de 10 h

Con `llama3.1:8b` hay que multiplicar por ~3 (es el mas lento de los tres), asi que un
analisis con el modelo que hoy figura como `models.analyst` en `config.yaml` costaria
del orden de 20 min.

Dos observaciones que importan para el informe:

1. **La generacion es el cuello de botella**, no la lectura del reporte: 318 s de 462 s
   se van en escribir el JSON (2,9 tok/s contra 21,4 tok/s de lectura). Abaratar el
   esquema de salida es mucho mas eficaz que acortar los reportes.
2. El `evidence` por cada IoC es la parte mas cara del JSON. Acotarlo (p. ej. a 80
   caracteres) o hacerlo opcional deberia recortar la generacion de forma apreciable
   sin perder nada que las metricas necesiten.

## Presupuesto de computo: la matriz completa no cabe

La matriz que plantea `docs/ARCHITECTURE.md` son
30 reportes x (1 limpio + 5 vectores x 4 objetivos) x 5 configuraciones de defensa x 3
modelos = **9.450 analisis**. A 7,7 min cada uno son **mas de 1.200 horas** de computo
en este equipo. Hay que recortar.

Propuesta de matriz reducida, dimensionada para ~35-40 h de computo (viable en varias
noches, y mucho mas rapido si aparece un equipo con GPU):

| Experimento | Diseno reducido | Analisis | Horas |
|---|---|---|---|
| Linea base en limpio | 12 reportes (4 txt / 4 html / 4 pdf) | 12 | 1,5 |
| ASR sin defensas | 12 reportes x 5 vectores x 1 objetivo (`flip_to_benign`) | 60 | 7,7 |
| Defensas | 6 reportes x 5 vectores x 5 configuraciones | 150 | ~19 |
| Comparacion de modelos | 4 reportes x 5 vectores, en `llama3.1` y `qwen2.5` | 40 | ~8 |
| | **Total** | **262** | **~36** |

Decisiones que esto implica y que conviene cerrar en equipo:

- **Modelo principal: `mistral:7b-instruct`** por costo (3x mas barato que `llama3.1`).
  La eleccion definitiva es de la Fase 2, cuando se compare la exactitud en limpio: si
  mistral acierta parecido, gana por velocidad.
- **Un solo objetivo de ataque** (`flip_to_benign`) en el experimento principal, con los
  otros tres objetivos medidos sobre una muestra pequena. Es el objetivo mas claro de
  medir y el mas vistoso para la sustentacion.
- **12 reportes en vez de 30.** Menos potencia estadistica, pero el etiquetado a mano de
  la Fase 1 tambien es trabajo humano y 30 reportes x 4 personas no es realista.
- Esto va tal cual a la seccion **"Alcance y limitaciones"** del informe: la restriccion
  de hardware es un resultado del proyecto, no una excusa.
