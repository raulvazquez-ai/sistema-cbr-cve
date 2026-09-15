# Valoración Automática de Vulnerabilidades CVE mediante Sistemas CBR 🛡️🤖

Este repositorio contiene un prototipo de herramienta inteligente diseñada para la clasificación y evaluación automática de informes de vulnerabilidad de software (CVE). 

El sistema emplea el paradigma de Razonamiento Basado en Casos (CBR) para predecir el nivel de severidad (Score CVSS) y la forma de explotación (Attack Vector) de nuevas amenazas, basándose en la experiencia acumulada en registros históricos.

## ⚙️ Arquitectura del Ciclo CBR

El sistema está implementado sobre una arquitectura orientada a objetos en `core.py` y adaptado al dominio de la ciberseguridad en `revisor_cve.py`, completando el ciclo estándar:

1.  **Recuperar:** Utiliza la librería `cbrkit` para calcular una similitud global compuesta mediante una media ponderada. Integra métricas de Wu-Palmer para la taxonomía CWE, Isolated Mapping (Levenshtein) para los productos afectados, y similitud del coseno sobre *embeddings* vectoriales generados con *Sentence Transformers* para la descripción textual.
2.  **Reutilizar:** Infiere el *score* a través de la media ponderada de los vecinos más cercanos, y predice el *attack Vector* seleccionando la moda (el valor más frecuente).
3.  **Revisar:** Audita la predicción aplicando las reglas del estándar CVSS v3.1, validando aciertos exactos o determinando éxitos por niveles de severidad adyacentes.
4.  **Retener:** Consolida el conocimiento almacenando en la base de datos tanto los casos de éxito total como aquellos que requirieron corrección experta.

## 🛠️ Tecnologías Utilizadas

*   **Python 3.12**
*   **`cbrkit[nlp,transformers]` (v0.28.5):** Motor principal para la recuperación semántica y métricas de similitud.
*   **`numpy`:** Soporte para computación matemática en el cálculo de predicciones ponderadas.
*   **SQLite:** Actúa como motor de caché persistente para los *embeddings*, eliminando la latencia de inferencia en tiempo real.

## 🚀 Ejecución y Uso

El flujo principal se gestiona a través del script `main_cve.py`, que permite parametrizar la ejecución mediante `argparse`.

```bash
pip install -r requirements.txt
python main_cve.py --base_casos datos/cve.base_casos.json --casos datos/cve.casos_a_resolver.json --num_similares 5 --debug
```

## 📊 Conclusiones del Análisis Experimental

Durante el desarrollo, se realizó un riguroso análisis de sensibilidad para optimizar el rendimiento y el coste computacional:

Transformers vs. Keywords: Se descubrió que, en el dominio de ciberseguridad, el coeficiente de Jaccard sobre keywords ofrece un poder predictivo individual superior (61% de acierto en Score y 84% en Vector de Ataque) frente al modelo de lenguaje profundo all-MiniLM-L6-v2.

Precisión Léxica: El análisis concluyó que la coincidencia léxica exacta de términos técnicos es más determinante que la semántica difusa global, permitiendo construir modelos más ligeros sin comprometer la eficacia.
