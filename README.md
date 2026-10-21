# browser a yacy — Indexador P2P para YaCy (Userscript)

Userscript para Tampermonkey/Violentmonkey que contribuye a la red de búsqueda
descentralizada **YaCy** indexando de forma segura, automática y sin fugas de
privacidad las páginas públicas que navegas.

> **Versión actual: v1.7.3** — ver [Estado de correcciones](#estado-de-correcciones-y-mejoras)
> para conocer qué se arregló, qué se quitó y por qué.

---

## Índice

1. [Qué hace](#qué-hace)
2. [Qué NO hace](#qué-no-hace)
3. [Instalación](#instalación)
4. [Configuración](#configuración)
5. [La API de YaCy, explicada](#la-api-de-yacy-explicada)
6. [Captura de snippets ("Oro Puro")](#captura-de-snippets-oro-puro)
7. [Modelo de seguridad](#modelo-de-seguridad)
8. [Estado de correcciones y mejoras](#estado-de-correcciones-y-mejoras)
9. [Verificación realizada](#verificación-realizada)
10. [Preguntas frecuentes](#preguntas-frecuentes)

---

## Qué hace

1. **Detecta la página que visitas.** En modo automático se evalúa cada vez que
   cambia la URL (incluidas SPAs de React/Vue/Angular) con un *debounce* de 4 s
   para no enviar la misma página decenas de veces.
2. **Limpia la URL antes de enviarla.** Elimina rastreadores, tokens, el
   fragmento `#...` y cualquier credencial embebida (`http://user:pass@host/`).
3. **Filtra lo que no debe indexarse.** Dominios sensibles, redes privadas e
   IPs locales, y URLs con datos privados.
4. **Envía la URL a tu nodo YaCy** mediante su API de rastreo.
5. **Extrae fragmentos ("Oro Puro")** a HTML local con etiquetas canónicas para
   que YaCy los indexe atribuyéndolos a la URL pública real.

---

## Qué NO hace

- ❌ No indexa repositorios de código (`github.com`, `gitlab.com`,
  `bitbucket.org`, `codeberg.org`).
- ❌ No indexa nube personal, redes sociales, plataformas de publicación,
  streaming ni servicios de pago/finanzas.
- ❌ No envía datos a servidores externos: el único destino posible es tu nodo
  YaCy.
- ❌ No usa `agentName = 'yacybot'` (dispara CAPTCHAs y bloqueos).
- ❌ No activa `crawlOrder = on` (no delega en otros nodos sin tu autorización).
- ❌ No envía cookies ni encabezados del navegador a YaCy.
- ❌ No guarda archivos fuera de tu equipo.

---

## Instalación

1. Instala **Tampermonkey** (o Violentmonkey) en tu navegador.
2. Abre `browser a yacy.js` y crea un nuevo userscript con su contenido.
3. Asegúrate de que YaCy esté corriendo en `http://localhost:8090`.
4. Configura tus credenciales desde el menú del script
   (**🔑 Configurar Credenciales de YaCy**).

### Menú del script

| Comando | Acción |
|---|---|
| 🕷️ Enviar URL a YaCy (Manual) | Indexa la página actual, tras pedir confirmación si contiene datos sensibles |
| ✂️ Capturar Selección (Oro Puro) | Extrae el texto seleccionado a HTML local |
| 🔑 Configurar Credenciales de YaCy | Guarda usuario y contraseña de administrador |
| 🌐 Configurar Nodo YaCy (Host) | Cambia la URL del nodo (útil si no está en localhost) |
| 🔄 Resetear Credenciales de YaCy | Borra las credenciales guardadas |

---

## Configuración

Las credenciales se guardan en el **almacén local del gestor de userscripts**
(en tu navegador). Nunca salen de tu equipo y nunca se escriben en el código.

YaCy exige autenticación de administrador para arrancar un rastreo, por eso el
script las pide una vez. Si el servidor devuelve `401`, las credenciales se
borran automáticamente para volver a pedirlas en el siguiente intento (así el
script no queda bloqueado con unas credenciales muertas).

### Credenciales con caracteres especiales

La cabecera `Authorization: Basic` se codifica en **UTF-8** (no con `btoa()`
a secas). Esto importa: una contraseña con `ñ`, tilde o eñe haría fallar el
envío con una codificación naïve.

### Host del nodo

Por defecto `http://localhost:8090`. Puedes cambiarlo desde el menú
(**🌐 Configurar Nodo YaCy**) si tu nodo está en otro equipo de tu red local.
La directiva `@connect *` del encabezado es lo que permite esa petición; el
script **nunca** contacta a ningún otro destino.

---

## La API de YaCy, explicada

### El endpoint correcto: `/Crawler_p.html`

La API de rastreo de YaCy es el servlet **`/Crawler_p.html`**. Es el punto de
entrada documentado: las páginas de interfaz (`/CrawlStartSite.html`,
`/CrawlStartExpert.html`) son formularios que al enviarse llaman a ese mismo
servlet.

> **Error corregido en v1.7.3.** Una versión anterior usaba
> `/CrawlStart_p.html`. Ese endpoint **no existe** en YaCy y devuelve
> **HTTP 404**, así que el script no llegaba a arrancar ningún rastreo. La
> confusión venía de un comentario obsoleto en el propio código fuente de YaCy
> (`CrawlStartSite.java` línea 1 dice `// CrawlStart_p.java`, pero esa clase no
> existe como servlet). Comprobado contra el código fuente de
> `yacy_search_server` y contra una instancia real en ejecución.

### Parámetros que se envían

Únicamente se envían parámetros que **existen de verdad** en el servlet
`Crawler_p` de YaCy, verificados contra
`yacy_search_server/source/net/yacy/htroot/Crawler_p.java`.

| Parámetro | Valor | Por qué |
|---|---|---|
| `crawlingstart` | `on` | Obligatorio: su presencia arranca el rastreo. El valor no se interpreta, pero `on` es el que usa la documentación oficial |
| `crawlingMode` | `url` | Rastrear desde la URL indicada (alternativas: `sitemap`, `sitelist`, `file`) |
| `crawlingURL` | URL limpiada | La página a indexar |
| `crawlingDepth` | `0` | **Solo indexa la propia página.** Sin esto YaCy seguiría enlaces y arrastraría medio sitio sin permiso |
| `crawlingDomMaxPages` | `10000` | Límite de páginas por dominio. Con profundidad 0 no aplica, pero deja explícito que no se indexa sin control |
| `indexText` | `on` | Extrae y indexa el texto de la página |
| `indexMedia` | `off` | No indexar multimedia |
| `storeHTCache` | `off` | No guardar copias en el caché de YaCy (privacidad y disco) |
| `crawlingQ` | `on` | Permite rastrear URLs con `?` (contenido dinámico), que YaCy evita por defecto |
| `recrawl` | `reload` | Recarga URLs ya indexadas que hayan cambiado |
| `cachePolicy` | `no cache` | No usar caché: contenido siempre fresco |
| `crawlOrder` | `off` | **No delegar en otros nodos P2P.** Es el valor por defecto, pero se declara a propósito: delegar páginas de tu navegación en terceros es una fuga que debes aceptar a sabiendas |
| `agentName` | `Random Browser` | Ver la siguiente sección |
| `ipMustnotmatch` | patrón | Segunda capa de defensa:IPs y redes que YaCy no debe rastrear |
| `mustnotmatch` | patrón | Segunda capa de defensa:protocolos peligrosos y parámetros con credenciales |

### Por qué `agentName = 'Random Browser'`

Este es el punto más delicado y el que más problemas causó.

**YaCy no acepta cadenas libres en `agentName`.** El valor se usa como clave de
un mapa de agentes predefinidos (`ClientIdentification.java`). Si el valor no
coincide con ninguna clave, YaCy **cae en silencio al agente por defecto:
`yacybot`**. No hay error: simplemente se indexa con la User-Agent de `yacybot`.

Las claves válidas son:

| Clave | User-Agent resultante |
|---|---|
| `YaCy Internet (cautious)` | `yacybot (...)` |
| `YaCy Intranet (greedy)` | `yacybot (...)` |
| `Googlebot` | `Mozilla/5.0 (compatible; Googlebot/2.1; ...)` |
| `Random Browser` | User-Agent de navegador real (p. ej. Chrome) |
| `Custom Agent` | La definida en `yacy.conf` (`crawler.userAgent.string`). **Si no está configurada, cae a `yacybot`** |

> **Error corregido en v1.7.3.** El script enviaba
> `'Mozilla/5.0 (compatible; YaCy-AutoIndexer)'`, que no es una clave válida, así
> que **YaCy indexaba con `yacybot`** — justo lo contrario de lo que se quería.
> Se cambió a `'Random Browser'`, que emite una User-Agent de navegador real y
> evita CAPTCHAs y bloqueos.
>
> Verificado de forma empírica: se montó un servidor local que registraba la
> User-Agent recibida y se lanzó el mismo rastreo con cada valor. Resultado:
>
> | `agentName` enviado | User-Agent real usada por YaCy |
> |---|---|
> | `Mozilla/5.0 (compatible; YaCy-AutoIndexer)` | `yacybot (freeworld/global; ...)` |
> | `Custom Agent` | `yacybot (freeworld/global; ...)` |
> | `Random Browser` | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/134.0.0.0 ...` |
> | `Googlebot` | `Mozilla/5.0 (compatible; Googlebot/2.1; ...)` |

### Parámetros eliminados en v1.7.3

Estos cinco parámetros se enviaban pero **no existen** en el servlet
`Crawler_p`. YaCy los ignora en silencio, así que no rompían el envío, pero
daban una falsa sensación de integración completa:

| Parámetro eliminado | Por qué no existe |
|---|---|
| `crawlingIfFileExists` | No aparece en ninguna parte del código de YaCy |
| `crawlingPost` | No existe; el equivalente real es `crawlingQ` |
| `crawlingFilter` | No existe; el filtro real es `mustmatch` |
| `crawlingDomFilterDepth` | No existe; el real es `crawlingDomMaxPages` |
| `crawlingAgentName` | No existe; el real es `agentName` |

Regla que conviene recordar: **un parámetro desconocido no produce error, se
ignora.** Por tanto, añadir "parámetros que parecen correctos" solo maquilla el
problema. Si algún día necesitas un comportamiento nuevo, comprueba antes que
la clave existe en `Crawler_p.java`.

---

## Captura de snippets ("Oro Puro")

A veces el contenido útil está en una URL que el filtro descarta (porque
contiene palabras sensibles) o que YaCy no indexa bien. Para eso está el
extractor de fragmentos.

1. Selecciona texto o un bloque con el ratón.
2. Ejecuta **✂️ Capturar Selección (Oro Puro)**.
3. Se abre un modal de previsualización.
4. Al confirmar, se descarga un archivo HTML local con:

```html
<link rel="canonical" href="https://ejemplo.com/pagina-real">
<base href="https://ejemplo.com/pagina-real">
```

- **`<link rel="canonical">`** le dice a YaCy que ese fragmento pertenece a la
  página pública real, no a un archivo de tu disco.
- **`<base href>`** evita que las imágenes y enlaces relativos del fragmento se
  rompan al abrir el archivo local.

### Nota importante

El HTML descargado es un **archivo local** y, por seguridad, YaCy bloquea el
rastreo de archivos locales. Ese archivo debe ser enviado al rastreador de
archivos de forma manual. Es una limitación conocida, no un fallo del script.

---

## Modelo de seguridad

El script aplica dos capas de filtrado independientes.

### Capa 1 — Filtrado local (en tu navegador)

Se aplica a cada URL antes de decidir si se envía:

| Regla | Qué cubre |
|---|---|
| `isIpPrivate()` | Redes locales: `10/8`, `172.16/12`, `192.168/16`, `169.254/16`, `100.64/10` (CGNAT), `127/8`, IPv6 `::1`, `fe80::`, `fc00::`, `fd00::` — **con y sin corchetes** |
| `LOCALHOST_REGEX` | Nombres de intranet: `localhost`, `*.local`, `intranet`, `internal`, `network` |
| `isDomainBlacklisted()` | Dominios excluidos (código, nube, redes, finanzas) |
| `hasSensitiveData()` | URLs con credenciales embebidas o con palabras/parámetros privados |
| `sanitizeUrl()` | Limpieza de la URL antes de enviarla |

La comprobación de IPv6 acepta **corchetes** (`[::1]`) porque el estándar WHATWG
devuelve los hosts IPv6 entre corchetes (`new URL('http://[::1]').hostname ===
'[::1]'`). Sin ese detalle, `::1` y los rangos `fc00::/7` se habrían colado por
el filtro y se habría intentado indexar red interna por IPv6.

### Capa 2 — Filtros en el propio rastreo de YaCy

Se entregan como `ipMustnotmatch` y `mustnotmatch` en la petición. Es una segunda
defensa: aunque algo se colara de la capa local, YaCy también lo rechaza.

### Qué se elimina de la URL

- **Credenciales embebidas**: `http://usuario:clave@host/` → se borran
  `username` y `password` explícitamente. `new URL()` las conserva al serializar
  y viajarían en la petición.
- **Rastreadores**: `utm_*`, `gclid`, `fbclid`, `msclkid`, `igshid`, etc.
- **Parámetros sensibles**: `token`, `auth`, `key`, `pwd`, `session`, `csrf`,
  `jwt`, `bearer`, …
- **El fragmento `#...`**: nunca llega al servidor y varía entre usuarios, así que
  eliminarlo evita duplicar páginas en el índice.
- **Valores de parámetro de más de 256 caracteres**: no son contenido indexable
  útil y casi siempre son tokens o datos codificados.

### Escape HTML en los snippets

El archivo HTML generado escapa (`escapeHtml`) la URL, el título y la fecha antes
de insertarlos. Sin eso, un carácter `"` en la URL rompería el atributo `href` y
permitiría inyectar HTML en el archivo descargado.

---

## Estado de correcciones y mejoras

### v1.7.3 — rama unificada y corregida

Parte de `main` (que era la única versión funcional) y retoma lo útil de los
trabajos anteriores, descartando lo inventado.

#### Corregido

| Problema | Causa | Solución |
|---|---|---|
| **El script no indexaba nada** | Usaba `/CrawlStart_p.html`, endpoint inexistente → HTTP 404 | Usar `/Crawler_p.html`, el servlet real de la API |
| **YaCy indexaba como `yacybot`** | `agentName` con un valor no reconocido cae al agente por defecto | Usar `agentName = 'Random Browser'` (User-Agent de navegador real) |
| **Parámetros inexistentes** | `crawlingIfFileExists`, `crawlingPost`, `crawlingFilter`, `crawlingDomFilterDepth`, `crawlingAgentName` no existen en `Crawler_p.java` | Eliminados. YaCy los ignoraba en silencio |
| **`crawlingstart = '1'`** | Valor no documentado | `crawlingstart = 'on'`, el de la documentación oficial |
| **Posible inyección HTML en snippets** | La URL y la fecha se insertaban sin escapar en el HTML | `escapeHtml()` aplicado a URL, título y fecha |
| **Posible fuga de credenciales** | `new URL()` conserva `username`/`password` embebidos | `sanitizeUrl()` los borra explícitamente |
| **Filtro IPv6 incompleto** | `new URL().hostname` devuelve `[::1]` con corchetes y el regex no los esperaba | Regex actualizado para aceptar corchetes opcionales |
| **`github.com` / `gitlab.com` no estaban excluidos** | La blacklist no los incluía pese a que la documentación decía que sí | Añadidos `github.com`, `gitlab.com`, `bitbucket.org`, `codeberg.org` |
| **`LOCALHOST_REGEX` corrupta** | Una versión tenía `\vert{}` en lugar de `\|` | Corregida a la expresión válida |
| **Autenticación rota con contraseñas en español** | `btoa()` lanza excepción con caracteres no Latin-1 | Codificación UTF-8 previa con `encodeURIComponent` |

#### Mejorado

| Mejora | Motivo |
|---|---|
| **Búsqueda en la blacklist por segmentos de subdominio** | La versión anterior recorría el `Set` entero con `endsWith('.' + domain)` en **cada** comprobación de URL (varias por segundo). Ahora se consultan segmentos con `Set.has()` (O(1)) sin crear cadenas intermedias |
| **Regex precompilado para parámetros sensibles** | `[...Set].some(...)` crea un array nuevo en cada comprobación. Ahora se compila una vez al cargar |
| **Compatibilidad con Violentmonkey** | Violentmonkey ejecuta el script en un sandbox y `window.history` apunta al sandbox, no a la página. Se usa `unsafeWindow` cuando está disponible |
| **`try/catch` en la envoltura de `history`** | Un fallo al envolver `pushState`/`replaceState` no debe tumbar el script entero |
| **Configuración del host desde el menú** | Antes solo era editable a mano en el código |
| **Comentarios explicativos en el código** | Cada decisión no obvia queda documentada con su porqué |
| **`String()` en `escapeHtml`** | Evita excepción si se pasa un valor no string |

#### Descartado a propósito

Los PRs previos contenían cambios que **no existían en la API real** o que
reintroducían el error del endpoint. Se revisaron uno a uno contra el código
fuente de YaCy y se descartaron. También se descartó un PR que era duplicado de
otro ya aplicado.

---

## Verificación realizada

Todo lo anterior está **comprobado contra el código fuente de YaCy**
(`yacy_search_server`, servlet `Crawler_p.java`) y contra una instancia real en
`http://localhost:8090`:

- `GET /Crawler_p.html` → **HTTP 200** (endpoint correcto)
- `GET /CrawlStart_p.html` → **HTTP 404** (endpoint inexistente)
- User-Agent real registrada por un servidor de prueba local para cada valor de
  `agentName` (tabla más arriba)
- Pruebas unitarias sobre las funciones de filtrado y sanitización (IPs privadas
  IPv4/IPv6, blacklist de dominios, detección de datos sensibles, limpieza de
  URL, escape HTML, host por defecto): **todas en verde**
- Validación de sintaxis del script completo

---

## Preguntas frecuentes

**¿Por qué no se indexa una página que visité?**
Puede estar en la blacklist de dominios, contener palabras/parámetros sensibles,
o ser una IP local. Revisa la consola del navegador: el script avisa cuando
omite el envío por credenciales no configuradas.

**¿Dónde se guardan mis credenciales?**
En el almacén local de Tampermonkey/Violentmonkey, dentro de tu navegador. No se
escriben en el código ni salen de tu equipo.

**¿Puedo cambiar el puerto o la IP de mi nodo YaCy?**
Sí, desde el menú **🌐 Configurar Nodo YaCy (Host)**.

**¿El script envía mis cookies o historial?**
No. Únicamente hace una petición a `GET /Crawler_p.html` en tu nodo, con la URL
de la página actual ya limpiada.

**¿Por qué `crawlingDepth = 0`?**
Para que el script indexe solo la página que visitas. Con una profundidad mayor,
YaCy seguiría los enlaces de esa página y empezaría a arrastrar el sitio sin que
lo pidieras.

---

## Estructura del código

| Sección | Contenido |
|---|---|
| 1. Configuración | Host del nodo, *debounce*, estado |
| 2. Listas de filtrado | Dominios, palabras sensibles, parámetros, rangos de IP |
| 3. Seguridad y sanitización | `sanitizeUrl`, `hasSensitiveData`, `isIpPrivate`, `isDomainBlacklisted`, `escapeHtml` |
| 4. Notificaciones | Avisos flotantes (`textContent`, nunca `innerHTML`) |
| 5. Credenciales y nodo | Configuración de usuario y host |
| 6. Envío a la API | Construcción de parámetros y petición a `Crawler_p.html` |
| 7. Snippets | Vista previa y guardado de HTML con canonical |
| 8. Detección y menús | Evaluación automática, envoltura de `history`, menús |

---

*Licencia: AGPL-3.0. Proyecto de código abierto para contribuir a la red
descentralizada YaCy sin comprometer la privacidad del usuario.*
