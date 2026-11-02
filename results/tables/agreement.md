# Acuerdo entre revisores

Etiquetado A: `labels`  
Etiquetado B: `labels_b`

| Reporte | IoCs A | IoCs B | Jaccard | Comunes | Veredicto | Severidad |
|---|---|---|---|---|---|---|
| intel471_2021-04-07_ettersilent-maldoc-builder-macro-trickbot | 22 | 22 | 1.00 | 22 | 100% | si |
| proofpoint_2021-12-09_holiday-feelin-ta575-brings-warm | 10 | 10 | 1.00 | 10 | 100% | si |
| quoteintelligence_2020-08-07_blackwater-malware-leveraging-beirut-tragedy | 13 | 13 | 1.00 | 13 | 100% | si |
| zscaler_2020-06-26_taurus-new-stealer-town | 10 | 10 | 1.00 | 10 | 100% | si |

**Resumen** (4 reportes comparados)

- Acuerdo de conjunto de IoCs (Jaccard medio): **1.00**
- Acuerdo de veredicto sobre los 55 indicadores comunes: **100.0%**
- Kappa de Cohen del veredicto: **1.000**
- Acuerdo de severidad: **4/4** reportes

> Kappa de Cohen descuenta el acuerdo por azar. En un dataset donde la
> mayoria de los indicadores son `malicious`, el porcentaje crudo se infla y
> kappa es la cifra que hay que reportar.

## Cómo leer este acuerdo

- **Etiquetado A:** Mariana Malagón (`data/labels/`). **Etiquetado B:** Claude (asistente
  IA), por encargo de Juan Sebastián Ortega (`data/labels_b/`), partiendo del borrador
  del extractor y sin ver los veredictos de A. Es un acuerdo **persona frente a IA**, no
  entre dos personas.
- **No es ciego del todo.** Antes de etiquetar, B ya había visto la severidad, el actor y
  el número de indicadores de A (en un resumen de estado), y el caso de los cuatro
  nombres de archivo de Taurus estaba descrito en `docs/DATASET.md`. El acuerdo de
  severidad, por tanto, no es independiente. Los veredictos indicador por indicador sí
  se decidieron sin ver los de A.
- **Por qué sale perfecto.** Los cuatro reportes traen tablas de IoCs explícitas y los
  dos etiquetados siguen las mismas convenciones de `docs/DATASET.md` (sección 6). El
  número dice que el criterio es reproducible en reportes bien estructurados, no que
  el etiquetado sea infalible.
- `agreement.py` no compara el actor ni las exclusiones: se revisaron a mano. Las
  exclusiones coinciden en los cuatro reportes.

## Discrepancias resueltas

| Reporte | Campo | A | B | Resolución |
|---|---|---|---|---|
| `zscaler_2020-06-26_taurus-new-stealer-town` | `threat_actor` | `null` | `Predator the Thief` | **B.** El texto atribuye a ese grupo el desarrollo y la venta del stealer; el operador concreto de la campaña no se identifica. No afecta a ninguna métrica. |
