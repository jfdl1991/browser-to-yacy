# YaCy Auto-Indexer P2P — Userscript

Contribuye a la red de búsqueda descentralizada YaCy (P2P) de forma segura, automática y sin fugas de privacidad, incluyendo captura de recortes con etiquetas canónicas para indexación local.

---

## ¿Qué hace este script?

Este Userscript de Tampermonkey detecta las páginas públicas que navegas activamente, las limpia (elimina rastreadores y datos sensibles) y las envía a tu nodo local de YaCy (`http://localhost:8090`) para indexarlas. Además, permite extraer fragmentos o snippets seleccionados ("Oro Puro") en archivos HTML locales equipados con etiquetas canónicas para que el rastreador de archivos de YaCy los indexe atribuyéndolos siempre a la URL pública real.

**No envía datos privados. No envía credenciales. No envía tokens. No envía URLs ni rutas locales.**

---

## Modos de Operación

### 1. Indexación Automática / Manual de URLs
Envía la URL actual limpia a la API de rastreo web de YaCy (`Crawler_p.html`). YaCy descarga la página web con su propio motor.

### 2. Captura de Snippets de Oro (Extractor Local)
Permite seleccionar texto o contenido en cualquier sitio web y guardarlo como un archivo HTML optimizado.
* **Fácil previsualización:** Abre un modal flotante e interactivo para revisar el contenido extraído antes de guardarlo.
* **Inyección Canónica (`<link rel="canonical">`):** Le indica a YaCy que el contenido pertenece a la web pública real y no a tu disco duro.
* **Soporte de Recursos (`<base href>`):** Evita que las imágenes o enlaces relativos dentro del snippet se rompan al abrir el archivo local.

---

## Configuración del Nodo YaCy

El script interactúa directamente con la API de YaCy. Para revisar o ajustar tu nodo, accede a:

```text
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

- `v1.7.1` Pide usuario y contraseña (necesarios para enviar la url a yacy) y las guarda localmente sin modificar el script. 
Permite seleccionar un contenido y  guardarlo como html cuando el contenido es muy util pero la url se filtra o yacy no lo indexa bien por asuntos de agente o cualquier otra razón indicando la url de la que proviene, el html se descarga pero aún así ese html debe ser crawleado manualmente ya que como archivo local se bloquea su crawleo por seguridad. (TO-DO)
(corregido) — arreglos críticos: reset de estado (`isProcessing`), timeout, backoff exponencial, detección de URLs codificadas, `LOCALHOST_REGEX` refinado, `IP_PRIVATE_REGEX` con rango Carrier-Grade NAT (`100.64.*`), `MUST_NOT_MATCH_PATTERNS` convertido a `Set` para mantenimiento.

---

*Este proyecto es un script de código abierto para contribuir a la red descentralizada YaCy sin comprometer la privacidad del usuario.*
