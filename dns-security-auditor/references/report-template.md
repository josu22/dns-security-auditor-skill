# Report Template — DNS Security Audit

Deliver the audit **exactly** in this structure. Fill every section. Where data
is missing, use **"No verificable con la información disponible"** and list the
evidence required (§12). Label any inferred architecture as *inferred*.

---

# Informe de Auditoría de Seguridad DNS

## 1. Resumen ejecutivo

- **Nivel global de riesgo:** Crítico / Alto / Medio / Bajo.
- Principales riesgos (3–5 bullets, en lenguaje ejecutivo).
- Impacto potencial para el negocio.
- Riesgo para el correo (spoofing/phishing/entregabilidad).
- Riesgo para la disponibilidad de servicios.
- Riesgo para identidad y autenticación.
- **Prioridades inmediatas** (qué hacer en 24–72 h).

## 2. Alcance analizado

| Elemento | Estado | Evidencia | Observaciones |
| -------- | -----: | --------- | ------------- |

(Filas: dominios, subdominios, zonas, proveedor DNS, registrar, proveedor cloud,
proveedores de correo, datos internos aportados / no aportados.)

## 3. Mapa de arquitectura DNS

Describe: registrar · DNS autoritativo · DNS recursivo (si aplica) · proveedor
cloud · proveedores de correo · dependencias SaaS · flujo de resolución · puntos
críticos. Si faltan datos, genera una **arquitectura inferida** y márcala como
inferida.

## 4. Hallazgos priorizados

| ID | Severidad | Categoría | Hallazgo | Evidencia | Impacto | Recomendación |
| -- | --------- | --------- | -------- | --------- | ------- | ------------- |

(Ordena de mayor a menor severidad. IDs estables tipo `DNS-001`.)

## 5. Análisis detallado por dominio

Para **cada** dominio:
- Estado del registrar · nameservers · DNSSEC · MX · SPF · DKIM · DMARC · CAA.
- Riesgo de subdomain takeover · riesgo cloud/SaaS · riesgo de exposición.
- Recomendaciones específicas.

## 6. Controles evaluados

| Control | Resultado | Evidencia | Riesgo | Acción |
| ------- | --------- | --------- | ------ | ------ |

Resultados permitidos: **Conforme · No conforme · Parcial · No verificable · No aplica.**

## 7. Riesgo de correo electrónico

SPF · DKIM · DMARC · MTA-STS · TLS-RPT · BIMI · CAA · spoofing · phishing ·
proveedores autorizados · shadow senders.

## 8. Riesgo de subdomain takeover

Subdominios sospechosos · CNAME externos · recursos cloud inexistentes ·
evidencia · probabilidad · impacto · validación recomendada · remediación.

## 9. Riesgo DNSSEC

Estado de firma · cadena de confianza · DS · DNSKEY · RRSIG · NSEC/NSEC3 ·
algoritmos · expiración · rollover · riesgo operativo · recomendaciones.

## 10. Riesgo de continuidad

Redundancia · anycast · multi-provider · backups · restore · runbooks ·
monitorización · alertas · SLA.

## 11. Plan de remediación

Separado por prioridad, con tabla en cada bloque.

### Primeras 24–72 horas
Acciones urgentes para reducir riesgo crítico.

### Primeros 30 días
Hardening y corrección.

### 60–90 días
Madurez, automatización y monitorización.

### 6–12 meses
Acciones estratégicas.

| Prioridad | Acción | Responsable | Esfuerzo | Impacto | Dependencias |
| --------- | ------ | ----------- | -------- | ------- | ------------ |

## 12. Evidencias requeridas

Lista de evidencias a solicitar al cliente: accesos/capturas del registrar ·
export de zona · lista de dominios · lista de usuarios con acceso · logs de
cambios · configuración DNSSEC · configuración de correo · configuración cloud ·
runbooks · SLA · procedimientos de cambio · backups · integración SIEM.

## 13. Backlog técnico

| Tarea | Descripción | Prioridad | Criterio de aceptación |
| ----- | ----------- | --------- | ---------------------- |

## 14. Conclusión

Estado general · riesgos críticos · madurez · recomendación principal ·
siguiente paso.

---

**Tono:** profesional, técnico, directo, orientado a dirección y equipo técnico,
sin alarmismo, con priorización clara. Listo para entregar como base de informe
profesional de consultoría de ciberseguridad.
