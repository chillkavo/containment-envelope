# containment-envelope
# Execution Envelope — contención verificable para agentes de IA

Apart AI Incident Response Sprint · Frente 1 · septiembre 2026

## Qué es
Un esquema declarativo de permisos para entornos de ejecución de
agentes, con un verificador que detecta divergencias entre lo
declarado y lo ocurrido usando solo artefactos públicos — sin
acceso a la red del laboratorio.

## Cómo correrlo
    python src/run.py

## Qué encontramos
De 10 clases de violación de contención, 6 son detectables desde
artefactos públicos, 1 es condicionada, 2 parciales y 1 no lo es.
Ver `results/matriz.md`.

## Limitaciones
Los envelopes y digests incluidos son ejemplos ilustrativos, no
configuraciones reales de ningún laboratorio. El verificador opera
sobre datos sintéticos.

## Licencia
MIT
