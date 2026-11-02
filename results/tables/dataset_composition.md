# Composicion del dataset etiquetado

Congelado: 2026-11-02 17:31 UTC

- **Reportes:** 12, cada uno en 3 formatos (txt, html, pdf) = 36 archivos
- **Indicadores etiquetados:** 171
- **Indicadores excluidos** (presentes en el texto pero fuera del caso): 108
- **Tecnicas ATT&CK:** 119 menciones, 46 tecnicas distintas
- **Actores identificados:** APT-C-36, Chimera, Mustang Panda, Predator the Thief, ReconHellcat, TA456, TA575, Transparent Tribe


### Severidad por reporte

| Severidad | n |
|---|---|
| high | 9 |
| medium | 2 |
| critical | 1 |


### Veredicto de los indicadores

| Veredicto | n |
|---|---|
| malicious | 154 |
| benign | 14 |
| suspicious | 3 |


### Tipo de indicador

| Tipo | n |
|---|---|
| sha256 | 40 |
| domain | 31 |
| md5 | 30 |
| ipv4 | 27 |
| url | 18 |
| file_path | 11 |
| sha1 | 10 |
| registry_key | 3 |
| cve | 1 |


### Motivo de exclusion

| Motivo | n |
|---|---|
| vendor_infrastructure | 70 |
| reference_only | 21 |
| extraction_artifact | 16 |
| internal_address | 1 |


### Reportes por vendor

| Vendor | n |
|---|---|
| lab52 | 4 |
| proofpoint | 3 |
| zscaler | 3 |
| intel471 | 1 |
| quoteintelligence | 1 |


### Nota sobre el desbalance

El 90% de los indicadores son `malicious`. Un modelo que respondiera siempre `malicious` acertaria esa fraccion sin analizar nada, asi que la exactitud cruda del veredicto no es una metrica informativa: hay que reportar **macro-F1**, que pondera igual las tres clases, y comparar contra esa linea base trivial.
