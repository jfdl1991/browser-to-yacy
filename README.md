# YaCy Auto-Indexer P2P — Userscript

Contribuye a la red de búsqueda descentralizada YaCy (P2P) de forma segura, automática y sin fugas de privacidad.

## ¿Qué hace este script?

Este Userscript de Tampermonkey detecta las páginas públicas que navegas activamente, las limpia (elimina rastreadores y datos sensibles) y las envía a tu nodo local de YaCy (`localhost:8090`) para indexarlas. El nodo YaCy luego comparte ese índice con la red P2P global.

**No envía datos privados. No envía credenciales. No envía tokens. No envía URLs locales.**

---

## Cómo usar la API de YaCy (para usuarios del script)

El script habla con la API `Crawler_p.html` de YaCy. No necesitas tocar la API manualmente — el script lo hace automáticamente — pero si quieres configurar tu nodo:

```
http://localhost:8090/Crawler_p.html
```

**Configuración recomendada del nodo YaCy:**
- `crawlingDepth = 0`: solo indexa la URL que envías (no rastrea todo el sitio).
- `indexText = on`: extrae texto de la página.
- `storeHTCache = off`: no guarda HTML en disco (privacidad y espacio).
- `crawlingQ = on`: encola la petición en segundo plano.
- `agentName`: usa un nombre discreto (como `Mozilla/5.0`) para evitar bloqueos.
- `crawlOrder`: `off` (el script mantiene esta configuración para no delegar a otros nodos sin autorización).

---

## Características del script (v1.2.2)

- ✅ **Zero-Leak**: bloquea IPs locales (`localhost`, `192.168.*`, `10.*`, `172.16-31.*`, `169.254.*`), credenciales embebidas (`usuario:contraseña`), dominios sensibles, y parámetros con datos privados (`token`, `auth`, `session`, etc.).
- ✅ **Sanitización**: elimina rastreadores (`utm_*`, `fbclid`, `gclid`, etc.) y fragmentos de URL (`#...`).
- ✅ **Anti-DDoS / Anti-CAPTCHA**: retraso de 3.5 segundos entre envíos y límite de ~30 segundos entre cada indexación.
- ✅ **SPA Navigation**: detecta cambios en apps modernas (React, Vue, Angular) sin recargar la página.
- ✅ **Retry con backoff exponencial**: si YaCy no responde, reintenta automáticamente (hasta 3 veces) con espera creciente (1s, 2s, 4s).
- ✅ **Timeout**: cada petición tiene un límite de 15 segundos para evitar bloqueos.
- ✅ **No envía cookies** ni encabezados sensibles al nodo YaCy.
- ✅ **Conserva `crawlOrder = off`**: no distribuye a otros nodos sin tu autorización explícita.

---

## Instalación (para usuarios normales)

1. Instala Tampermonkey (o Greasemonkey) en tu navegador.
2. Abre este archivo (`browser a yacy v1.2.2.js`) y cópialo como un nuevo Userscript.
3. Asegúrate de que tu nodo YaCy esté corriendo en `http://localhost:8090`.
4. Configura (opcional): si tu YaCy está en otra IP/puerto, usa `GM_getValue('YACY_HOST', ...)` o edita el script — busca la constante `YACY_HOST`.

---

## Qué NO hace este script

- ❌ No indexa repositorios de código (`github.com`, `gitlab.com`).
- ❌ No indexa sitios bancarios, médicos o de pago.
- ❌ No envía datos a servidores externos fuera de tu red local.
- ❌ No usa `agentName = 'yacybot'` (para evitar CAPTCHAs y bloqueos).
- ❌ No activa `crawlOrder = on` (para no delegar a otros nodos sin autorización).
- ❌ No guarda archivos fuera de tu computadora (todos los datos van a `localhost:8090`).

---

## Estructura del archivo del script

El archivo (`browser a yacy v1.2.2.js`) está organizado en secciones claras:

1. **Configuración** — constantes (host YaCy, delays, límites).
2. **Listas de seguridad** — dominios bloqueados, palabras sensibles, parámetros de rastreo.
3. **Estado de procesamiento** — evita duplicados y carreras.
4. **Seguridad (Zero-Leak)** — validación de URLs (protocolos, IPs, palabras clave, parámetros).
5. **Sanitización** — elimina fragmentos (`#...`), rastreadores, y parámetros sensibles.
6. **Envío a YaCy** — construye la URL de la API con los parámetros correctos, envía con retry.
7. **Procesador principal** — maneja la navegación inicial y los cambios de URL (SPA).
8. **Inicializador** — activa el script cuando el DOM está listo.
9. **Monitoreo** — detecta cambios de URL cada 5 segundos con límite de ~30 segundos entre envíos.

---

## Nota para desarrolladores

El código está escrito en JavaScript puro para Tampermonkey. No requiere compilación, no usa librerías externas, y funciona en Chrome, Firefox y Brave (con la extensión Tampermonkey instalada).

---

## Versión

- `v1.2.2` (corregido) — arreglos críticos: reset de estado (`isProcessing`), timeout, backoff exponencial, detección de URLs codificadas, `LOCALHOST_REGEX` refinado, `IP_PRIVATE_REGEX` con rango Carrier-Grade NAT (`100.64.*`), `MUST_NOT_MATCH_PATTERNS` convertido a `Set` para mantenimiento.

---

*Este proyecto es un script de código abierto para contribuir a la red descentralizada YaCy sin comprometer la privacidad del usuario.*
