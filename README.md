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
