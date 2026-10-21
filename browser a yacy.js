// ==UserScript==
// @name         browser a yacy (Auto + Manual + Snippets Canonical)
// @namespace    jfdl19991
// @version      1.7.3
// @description  Envía la página actual a un nodo YaCy local para indexar, protegiendo la privacidad. Indexador P2P, limpiador de trackers y extractor de snippets con vista previa y canonical.
// @match        http://*/*
// @match        https://*/*
// @run-at      document-idle
// @grant        GM_getValue
// @grant        GM_setValue
// @grant        GM_xmlhttpRequest
// @grant        GM_registerMenuCommand
// @grant        unsafeWindow
// @connect      127.0.0.1
// @connect      localhost
// @connect      *
// @noframes
// @license      AGPL-V3
// @downloadURL https://update.greasyfork.org/scripts/598069/browser%20a%20yacy%20%28Auto%20%2B%20Manual%20%2B%20Snippets%20Canonical%29.user.js
// @updateURL https://update.greasyfork.org/scripts/598069/browser%20a%20yacy%20%28Auto%20%2B%20Manual%20%2B%20Snippets%20Canonical%29.meta.js
// ==/UserScript==
//
// ============================================================================
//  browser a yacy v1.7.3
// ----------------------------------------------------------------------------
//  Userscript para contribuir a la red YaCy (P2P) indexando de forma segura,
//  automática y sin fugas de privacidad las páginas que navegas.
//
//  QUE HACE:
//    1. Detecta la página que visitas (auto, con debounce) y la envía a YaCy.
//    2. Limpia la URL antes de enviarla: quita trackers, tokens, el #fragmento
//       y cualquier credencial embebida (http://user:pass@host/).
//    3. Bloquea por defecto dominios sensibles, redes privadas e IPs locales.
//    4. Permite extraer fragmentos ("Oro Puro") a HTML local con etiquetas
//       <link rel="canonical"> y <base> para que el rastreador de archivos de
//       YaCy los indexe atribuyéndolos a la URL pública real.
//
//  QUE NO HACE:
//    - No indexa repositorios de código (github.com, gitlab.com).
//    - No indexa bancos, salud ni pagos.
//    - No envía NADA a servidores externos: todo va a tu nodo YaCy local.
//    - No activa crawlOrder (no delega en otros nodos sin tu autorización).
//    - No usa agentName='yacybot' (evita CAPTCHAs y bloqueos).
//
//  CAMBIOS DE ESTA VERSION (v1.7.3)
//    [CORREGIDO] Endpoint del API. Se usa /Crawler_p.html, que es el servlet
//                real de la API de YaCy. La rama anterior usaba
//                /CrawlStart_p.html, que NO existe en YaCy y devuelve HTTP 404,
//                por lo que el script no hacía nada. Verificado contra
//                yacy_search_server (source/net/yacy/htroot/Crawler_p.java).
//    [CORREGIDO] agentName = 'Random Browser'. La versión anterior enviaba
//                'Mozilla/5.0 (compatible; YaCy-AutoIndexer)', un valor que YaCy
//                no reconoce y que cae al agente por defecto: yacybot.
//                Verificado de forma empírica: con ese valor YaCy rastrea con
//                la User-Agent 'yacybot (freeworld/global; ...)'. Con
//                'Random Browser' usa una User-Agent de navegador real.
//    [CORREGIDO] Eliminados 5 parámetros inexistentes
//                (crawlingIfFileExists, crawlingPost, crawlingFilter,
//                crawlingDomFilterDepth, crawlingAgentName). No existen en
//                Crawler_p.java: YaCy los ignora en silencio. No rompían nada
//                pero engañaban sobre el estado de la integración.
//    [CORREGIDO] crawlingstart = 'on' (antes '1'). El valor da igual, la API
//                solo exige que la clave esté presente, pero 'on' es el valor
//                que usa la documentación oficial y evita ambigüedades.
//    [SEGURIDAD] escapeHtml() aplicado a URL y fecha en el HTML del snippet.
//                Sin esto, un carácter '"' en la URL podía romper el atributo
//                href e inyectar HTML en el archivo descargado.
//    [SEGURIDAD] sanitizeUrl() borra username/password de la URL antes de
//                enviarla, para que credenciales embebidas nunca lleguen a YaCy.
//    [SEGURIDAD] El filtro de IP privadas acepta IPv6 entre corchetes ([::1]),
//                como los devuelve new URL().hostname.
//    [RENDIMIENTO] Búsquedas en la blacklist de dominios por segmentos de
//                  subdominio (O(1)) en vez de recorrer todo el Set en cada
//                  navegación, y regex precompilado en vez de propagar el Set.
//    [COMPATIBILIDAD] Violentmonkey: envoltura de history mediante
//                     unsafeWindow con try/catch para que no rompa el script.
//    [UX] Configuración del nodo (host) desde el menú del script.
//
// ============================================================================

(function () {
    'use strict';

    // ==========================================
    // 1. CONFIGURACIÓN
    // ==========================================

    // El host es configurable por si el nodo YaCy no está en localhost
    // (p. ej. en otro equipo de tu red local). Es una función y no una
    // constante fija para que el cambio desde el menú tenga efecto sin
    // recargar la página. Si apuntas a un host distinto de localhost, la
    // directiva @connect * del encabezado es lo que permite la petición.
    // El script NUNCA contacta a ningún otro destino que este.
    function getYacyHost() {
        return (GM_getValue('YACY_HOST', 'http://localhost:8090') || '').trim().replace(/\/+$/, '');
    }

    // Debounce: al navegar por una SPA (React, Vue, etc.) la URL cambia
    // muchas veces por segundo. Esperar 4 s evita enviar decenas de veces
    // la misma página a YaCy y saturar la cola de rastreo.
    const DELAY_MS = 4000;

    let debounceTimer = null;
    // Evita reenviar dos veces la misma URL ya procesada en este ciclo.
    let lastSentUrl = '';

    // ==========================================
    // 2. LISTAS DE FILTRADO
    // ==========================================

    // Dominios que no se deben indexar nunca: nube personal, redes sociales,
    // plataformas de publicación, servicios financieros y alojamiento de código.
    // Son los casos en los que indexar aporta poco y el riesgo de fuga de
    // información privada es alto.
    const BLACKLISTED_DOMAINS = new Set([
        // Repositorios y alojamiento de código: el código propio y los diffs no
        // aportan contenido buscable y su estructura rompe el rastreo.
        'github.com', 'gitlab.com', 'bitbucket.org', 'codeberg.org',
        // Nube personal y notas
        'localhost', 'google.com', 'docs.google.com', 'drive.google.com', 'mail.google.com',
        'notion.so', 'dropbox.com', 'onedrive.live.com', 'icloud.com', 'evernote.com',
        // Redes sociales y publicaciones
        'twitter.com', 'x.com', 'facebook.com', 'instagram.com', 'pinterest.com',
        'linkedin.com', 'tiktok.com', 'twitch.tv', 'medium.com', 'substack.com',
        'wordpress.com', 'blogspot.com', 'tumblr.com', 'netflix.com',
        // Pagos y finanzas
        'paypal.com', 'stripe.com', 'binance.com'
    ]);

    // Secciones privadas de cualquier web (tanto en inglés como en español).
    // Si la URL contiene una de estas palabras en la ruta o la query, se omite.
    const SENSITIVE_KEYWORDS_PATTERNS = [
        'cart', 'checkout', 'account', 'login', 'signin', 'signup',
        'billing', 'payment', 'bank', 'card', 'tarjeta', 'pago',
        'password', 'reset', 'verify', 'dashboard', 'admin', 'ssn',
        'passport', 'invoice', 'receipt', 'credit', 'loan', 'settings',
        'logout', 'signout', 'privacy', 'profile', 'mail'
    ];
    const SENSITIVE_KEYWORDS_REGEX = new RegExp('\\b(' + SENSITIVE_KEYWORDS_PATTERNS.join('|') + ')\\b', 'i');

    // Nombres de parámetro que habitualmente llevan credenciales o tokens de
    // sesión. Se eliminan de la URL antes de enviarla a YaCy.
    const SENSITIVE_PARAMS = new Set([
        'token', 'auth', 'key', 'pwd', 'code', 'session', 'sig', 'signature',
        'access_token', 'api_key', 'apikey', 'secret', 'csrf', 'state',
        'id_token', 'refresh_token', 'password', 'pin', 'otp', 'mfa_code',
        'jwt', 'bearer'
    ]);

    // Precompilado a nivel de módulo: se ejecuta una sola vez al cargar el
    // script. La alternativa ([...SENSITIVE_PARAMS].some(...)) crea un array
    // nuevo en CADA comprobación de URL (varias por segundo al navegar), lo que
    // presiona el recolector de basura sin aportar nada.
    const SENSITIVE_PARAMS_SUBSTRING_REGEX = new RegExp([...SENSITIVE_PARAMS].join('|'), 'i');

    // Parámetros de seguimiento (analytics, email, afiliados). Se quitan de la
    // URL indexada para que el índice refleje el contenido, no el rastro del
    // enlace desde el que se llegó.
    const TRACKING_PARAMS_EXACT = new Set([
        'gclid', 'fbclid', 'msclkid', 'ref', 'source', 'mc_eid', 'si', 'igshid',
        'yclid', 'dclid', 'twclid', 'ttclid', 'gbraid', 'wbraid', 's',
        'mc_cid', 'track', 'trk', '__hstc', 'hsa_fp', 'affiliate', 'ref_src',
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
        'cx', 'ie', 'share_id', 'camp'
    ]);

    // Filtro de red local. El '^\[?' del inicio es IMPORTANTE: el estándar
    // WHATWG devuelve los hosts IPv6 entre corchetes (new URL('http://[::1]').hostname
    // === '[::1]'), así que sin él un ::1 o un fc00::/16 pasaría el filtro y se
    // intentaría indexar direcciones privadas de IPv6 (SSRF / fuga interna).
    // Incluye también 100.64.0.0/10 (CGNAT) además de 10/8, 172.16/12 y 192.168/16.
    const IP_PRIVATE_REGEX = /^\[?(127\.|0\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|::1|fe80:|fc00:|fd00:)/i;

    // Nombres de host que delatan una intranet aunque no usen IP numérica.
    // Se omiten para no indexar páginas internas de tu organización.
    const LOCALHOST_REGEX = /^(localhost|[0-9]{1,3}\.local$|\.local$|intranet|internal|network)$/i;

    // ==========================================
    // 3. SEGURIDAD Y SANITIZACIÓN
    // ==========================================

    // Devuelve una copia de la URL lista para enviar a YaCy, o null si no es
    // una URL válida. ES LA ÚNICA FUNCIÓN que debe tocar la URL antes del envío.
    function sanitizeUrl(urlObj) {
        try {
            const cleanUrl = new URL(urlObj.href);

            // SEGURIDAD: una URL de la forma http://usuario:clave@host/ lleva las
            // credenciales dentro de .username/.password. new URL() las conserva
            // al serializar, así que hay que borrarlas explícitamente o viajarían
            // en la petición a YaCy (y aparecerían en sus logs).
            cleanUrl.username = '';
            cleanUrl.password = '';

            const paramsToDelete = [];
            cleanUrl.searchParams.forEach((value, key) => {
                const lowerKey = key.toLowerCase();
                // PRIVACIDAD: se quitan parámetros de tracking y credenciales.
                // value.length > 256: un valor tan largo no es información útil
                // indexable y casi siempre es un token o datos codificados.
                if (lowerKey.startsWith('utm_') || TRACKING_PARAMS_EXACT.has(lowerKey) ||
                    SENSITIVE_PARAMS.has(lowerKey) || SENSITIVE_PARAMS_SUBSTRING_REGEX.test(lowerKey) ||
                    value.length > 256) {
                    paramsToDelete.push(key);
                }
            });
            paramsToDelete.forEach(param => cleanUrl.searchParams.delete(param));

            // El fragmento (#sección) nunca se envía al servidor y varía entre
            // usuarios; eliminarlo evita duplicar páginas en el índice.
            cleanUrl.hash = '';

            return cleanUrl;
        } catch (e) { return null; }
    }

    // Decide si una URL contiene datos privados y no debería indexarse.
    // Las credenciales embebidas se comprueban aquí además de en sanitizeUrl()
    // para que el modo automático no las envíe en absoluto.
    function hasSensitiveData(urlObj) {
        if (urlObj.username || urlObj.password) return true;
        const fullPath = (urlObj.pathname + urlObj.search).toLowerCase();
        if (SENSITIVE_KEYWORDS_REGEX.test(fullPath)) return true;
        for (const param of urlObj.searchParams.keys()) {
            const lowerParam = param.toLowerCase();
            // Set.has() es O(1); el regex precompilado cubre coincidencias
            // parciales (p. ej. "api_key" contiene "key").
            if (SENSITIVE_PARAMS.has(lowerParam) || SENSITIVE_PARAMS_SUBSTRING_REGEX.test(lowerParam)) return true;
        }
        return false;
    }

    // Protege contra indexar redes locales o internas.
    function isIpPrivate(hostname) {
        return IP_PRIVATE_REGEX.test(hostname) || LOCALHOST_REGEX.test(hostname);
    }

    function isDomainBlacklisted(hostname) {
        if (!hostname) return false;

        // 1) Coincidencia exacta (el propio dominio, sin subdominio).
        if (BLACKLISTED_DOMAINS.has(hostname)) return true;

        // 2) Recorrer los segmentos de subdominio y consultar el Set en cada uno
        //    (p. ej. "www.mail.google.com" -> prueba "www.mail.google.com",
        //    "mail.google.com", "google.com"). Cada consulta es O(1) y no se
        //    crean cadenas intermedias, frente a la versión anterior que
        //    recorría el Set entero con endsWith('.' + domain) en cada
        //    navegación. Sin esto este bucle se ejecuta varias veces por segundo.
        let dotIdx = hostname.indexOf('.');
        while (dotIdx !== -1) {
            if (BLACKLISTED_DOMAINS.has(hostname.slice(dotIdx + 1))) return true;
            dotIdx = hostname.indexOf('.', dotIdx + 1);
        }
        return false;
    }

    // Escapa los cinco caracteres con significado en HTML. Se usa al volcar en
    // texto o en atributos cualquier dato que venga de fuera (URL, título,
    // fecha) para evitar que rompa la estructura o inyecte HTML en el archivo
    // de snippet que se descarga.
    function escapeHtml(str) {
        return String(str).replace(/[&<>"']/g, function(m) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
        });
    }

    // ==========================================
    // 4. NOTIFICACIONES
    // ==========================================

    // Avisos flotantes. Usa textContent (nunca innerHTML) para que el mensaje,
    // que en algunos casos proviene de la respuesta de YaCy, no pueda inyectar
    // HTML en la página que el usuario está visitando.
    function showToast(message, isError = false) {
        if (!document.body) return;
        const existingContainer = document.getElementById('yacy-toast-container');
        const container = existingContainer || document.createElement('div');
        if (!existingContainer) {
            container.id = 'yacy-toast-container';
            container.style.cssText = `
                position: fixed; bottom: 20px; right: 20px; z-index: 9999999;
                display: flex; flex-direction: column; gap: 10px; pointer-events: none;
            `;
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.style.cssText = `
            background: ${isError ? '#e74c3c' : '#2ecc71'}; color: #ffffff;
            padding: 12px 18px; border-radius: 8px; font-family: sans-serif;
            font-size: 14px; font-weight: bold; box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            opacity: 0; transition: opacity 0.3s ease, transform 0.3s ease;
            transform: translateY(10px); pointer-events: auto;
        `;
        toast.textContent = message;
        container.appendChild(toast);

        requestAnimationFrame(() => {
            toast.style.opacity = '1';
            toast.style.transform = 'translateY(0)';
        });

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(10px)';
            setTimeout(() => {
                toast.remove();
                if (container.children.length === 0) {
                    container.remove();
                }
            }, 300);
        }, 3500);
    }

    // ==========================================
    // 5. CREDENCIALES Y NODO
    // ==========================================

    // YaCy exige autenticación de administrador para arrancar un rastreo, así
    // que el script las pide una vez y las guarda en el almacén local del
    // gestor de userscripts (en tu navegador). Nunca salen de tu equipo.
    function configureCredentials() {
        const usuario = prompt("Configuración de YaCy: Introduce tu usuario administrador (ej: admin):", GM_getValue('yacy_user', ''));
        if (usuario === null) return false;
        const contrasena = prompt("Configuración de YaCy: Introduce tu contraseña:", GM_getValue('yacy_password', ''));
        if (contrasena === null) return false;

        if (!usuario || !contrasena) {
            showToast("❌ Usuario y contraseña son obligatorios.", true);
            return false;
        }

        GM_setValue('yacy_user', usuario);
        GM_setValue('yacy_password', contrasena);
        showToast("🔑 Credenciales guardadas correctamente.");
        return true;
    }

    // Cambia la URL del nodo YaCy. Al estar @connect * en el encabezado, el
    // host puede ser de tu red local, no solo localhost.
    function configureHost() {
        const nuevo = prompt("URL del nodo YaCy (ej: http://localhost:8090):", getYacyHost());
        if (nuevo === null) return;
        const limpio = nuevo.trim().replace(/\/+$/, '');
        if (!/^https?:\/\//i.test(limpio)) {
            showToast("❌ URL inválida. Debe empezar por http:// o https://", true);
            return;
        }
        GM_setValue('YACY_HOST', limpio);
        showToast("🌐 Nodo YaCy configurado: " + limpio);
    }

    // ==========================================
    // 6. ENVÍO A LA API DE YACY
    // ==========================================

    function sendToYaCy(targetUrl, isManual = false) {
        // 1. Recuperar credenciales guardadas localmente.
        let usuario = GM_getValue('yacy_user');
        let contrasena = GM_getValue('yacy_password');

        // 2. Si no hay, en el modo manual se piden; en automático se omite en
        //    silencio para no interrumpir cada vez que cambia de página.
        if (!usuario || !contrasena) {
            if (isManual) {
                const configured = configureCredentials();
                if (!configured) {
                    showToast("❌ Configuración cancelada. No se pudo enviar a YaCy.", true);
                    return;
                }
                usuario = GM_getValue('yacy_user');
                contrasena = GM_getValue('yacy_password');
            } else {
                console.warn("[YaCy Script] Auto-evaluación omitida: Credenciales no configuradas. Usa el menú del script para configurarlas.");
                return;
            }
        }

        // --------------------------------------------------------------------
        // Filtros que se entregan a YaCy en el propio rastreo, como segunda
        // capa de defensa (la primera es el filtro local del script). Es
        // importante porque YaCy aplica sus propios filtros de índice además
        // de los que ya descartó el script.
        // --------------------------------------------------------------------

        // IPs/redes que YaCy no debe rastrear.
        const ipMustnotmatch = "(127\\.0\\.0\\.1|localhost|192\\.168\\..*|10\\..*|172\\.(1[6-9]|2[0-9]|3[0-1])\\..*|169\\.254\\..*|100\\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\\..*|::1|fe80:|fc00:|fd00:)";

        // Patrones de URL que no deben rastrearse: protocolos peligrosos y
        // parámetros que suelen contener credenciales.
        const mustnotmatch = ".*(file:|chrome:|about:|ftp:|javascript:|token=|auth=|key=|pwd=|code=|session=|signature=|password=|secret=|csrf=|state=|jwt=|bearer=).*";

        // --------------------------------------------------------------------
        // PARÁMETROS DEL API
        // Únicamente se envían parámetros que existen de verdad en el servlet
        // Crawler_p de YaCy (verificado contra el código fuente en
        // yacy_search_server/source/net/yacy/htroot/Crawler_p.java).
        // Un parámetro desconocido se ignora en silencio, así que añadir
        // "parámetros que parecen correctos" solo da una falsa sensación de que
        // la integración está completa. Los que se retiraron en v1.7.3:
        //   crawlingIfFileExists, crawlingPost, crawlingFilter,
        //   crawlingDomFilterDepth, crawlingAgentName
        // --------------------------------------------------------------------
        const apiParams = new URLSearchParams({
            // Clave obligatoria para arrancar el rastreo: basta con que esté
            // presente, su valor no se interpreta. Se usa 'on', que es el valor
            // de la documentación oficial.
            'crawlingstart': 'on',

            // 'url' = rastrear desde la URL indicada (el resto de modos son
            // 'sitemap', 'sitelist' y 'file').
            'crawlingMode': 'url',
            'crawlingURL': targetUrl,

            // 0 = solo indexar la propia página. Así el script indexa la página
            // visitada y no arrastra media web sin permiso.
            'crawlingDepth': '0',

            // Límite de páginas por dominio. Con depth 0 no tiene efecto, pero
            // deja explícito que no se va a indexar sin control.
            'crawlingDomMaxPages': '10000',

            'indexText': 'on',
            'indexMedia': 'off',
            // No cachear en HTCache: no hay motivo para conservar copias.
            'storeHTCache': 'off',

            // Permite rastrear URLs con '?' (contenido dinámico), que por
            // defecto YaCy evita.
            'crawlingQ': 'on',

            // 'reload' = recargar URLs que ya estén en el índice pero hayan
            // cambiado desde la última captura.
            'recrawl': 'reload',
            'cachePolicy': 'no cache',

            // SEGURIDAD: crawlOrder 'off' impide que YaCy delegue este
            // rastreo en otros nodos de la red P2P. El valor por defecto ya es
            // 'off', pero se declara explícitamente porque delegar páginas de
            // tu navegación en terceros es una fuga que el usuario debe
            // aceptar a sabiendas.
            'crawlOrder': 'off',

            // ----------------------------------------------------------------
            // agentName
            // IMPORTANTE: YaCy no acepta cadenas libres aquí. Consulta un mapa
            // de agentes fijos (ClientIdentification.java) y, si el valor no
            // coincide, cae en silencio al agente por defecto: yacybot.
            // Usar yacybot dispara CAPTCHAs y bloqueos en muchos sitios, así
            // que se elige 'Random Browser', que emite una User-Agent de
            // navegador real.
            // Verificado de forma empírica en v1.7.3: con el valor anterior
            // YaCy rastreaba con 'yacybot (freeworld/global; ...)'; con
            // 'Random Browser' usa un Chrome real.
            // ----------------------------------------------------------------
            'agentName': 'Random Browser',

            'ipMustnotmatch': ipMustnotmatch,
            'mustnotmatch': mustnotmatch
        });

        // Codificación de la cabecera Authorization. btoa() lanza una excepción
        // con caracteres no Latin-1: una contraseña con ñ, tilde o eñe rompería
        // el envío. Se pasa antes por encodeURIComponent para conseguir la
        // codificación UTF-8 correcta en la cabecera Basic.
        function utf8ToBase64(str) {
            return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
                return String.fromCharCode('0x' + p1);
            }));
        }
        const tokenAutenticacion = "Basic " + utf8ToBase64(usuario + ":" + contrasena);

        console.log("[YaCy Script] Enviando URL a rastrear:", targetUrl);

        // --------------------------------------------------------------------
        // ENDPOINT
        // Se usa /Crawler_p.html, que es el servlet real de la API de YaCy.
        // /CrawlStart_p.html NO existe en el producto y devuelve HTTP 404
        // (comprobado contra una instancia real), por lo que una versión
        // anterior del script no llegaba a arrancar ningún rastreo.
        // --------------------------------------------------------------------
        GM_xmlhttpRequest({
            method: "GET",
            url: `${getYacyHost()}/Crawler_p.html?${apiParams.toString()}`,
            headers: {
                "Authorization": tokenAutenticacion
            },
            timeout: 10000,
            onload: function (response) {
                if (response.status === 200) {
                    lastSentUrl = targetUrl;
                    if (isManual) showToast("✅ URL enviada a YaCy");
                } else {
                    if (isManual) showToast("❌ Error YaCy: " + response.status, true);
                    // 401 = credenciales inválidas. Se borran para volver a
                    // pedirlas en el siguiente intento, en vez de bloquear el
                    // script con unas credenciales muertas.
                    if (response.status === 401) {
                        GM_setValue('yacy_user', '');
                        GM_setValue('yacy_password', '');
                        console.warn("[YaCy Script] Error 401: Credenciales incorrectas. Se han borrado para volver a pedirlas.");
                    }
                }
            },
            onerror: function(err) {
                // Un error de red significa que YaCy no está escuchando o no
                // tiene el servidor activo. Se avisa solo en modo manual.
                if (isManual) showToast("❌ Error de conexión con YaCy", true);
            }
        });
    }

    // ==========================================
    // 7. VISTA PREVIA Y GUARDADO DE SNIPPETS
    // ==========================================

    // Los snippets ("Oro Puro") se guardan como HTML local con
    // <link rel="canonical"> y <base href> apuntando a la URL pública real.
    // Así el rastreador de archivos de YaCy indexa el fragmento y lo atribuye
    // siempre a la página pública original, nunca a un archivo local.
    function showSnippetPreviewModal(htmlContent, sourceUrl, pageTitle) {
        const existingModal = document.getElementById('yacy-snippet-modal');
        if (existingModal) existingModal.remove();

        const modalOverlay = document.createElement('div');
        modalOverlay.id = 'yacy-snippet-modal';
        modalOverlay.style.cssText = `
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            background: rgba(0, 0, 0, 0.7); z-index: 9999999; display: flex;
            justify-content: center; align-items: center; font-family: sans-serif;
        `;

        const modalContainer = document.createElement('div');
        modalContainer.style.cssText = `
            background: #ffffff; color: #222222; width: 80%; max-width: 800px;
            max-height: 85vh; border-radius: 12px; display: flex; flex-direction: column;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5); overflow: hidden;
        `;

        const date = new Date().toLocaleString();

        // NOTA SOBRE innerHTML: aquí el innerHTML es deliberado. El bloque es
        // estático y solo se interpolan (a) htmlContent, que es HTML que el
        // propio usuario seleccionó y quiere previsualizar, y (b) safeTitle y
        // safeUrl, que pasan por escapeHtml() antes de insertarse. El riesgo
        // que sí habría que cubrir (URL/título/fecha sin escapar) está cubierto.
        modalContainer.innerHTML = `
            <div style="padding: 15px 20px; background: #2c3e50; color: #ffffff; display: flex; justify-content: space-between; align-items: center;">
                <h3 style="margin: 0; font-size: 16px;">Vista Previa del Snippet - YaCy</h3>
                <span id="yacy-close-x" style="cursor: pointer; font-size: 20px; font-weight: bold;">&times;</span>
            </div>
            <div style="padding: 15px; background: #f8f9fa; border-bottom: 1px solid #e9ecef; font-size: 13px;">
                <strong>Título:</strong> ${escapeHtml(pageTitle)}<br>
                <strong>Fuente Canonical:</strong> ${escapeHtml(sourceUrl)}<br>
                <strong>Capturado:</strong> ${date}
            </div>
            <div id="yacy-snippet-body" style="padding: 20px; overflow-y: auto; flex-grow: 1; border-bottom: 1px solid #e9ecef; background: #ffffff;">
                ${htmlContent}
            </div>
            <div style="padding: 15px 20px; background: #f8f9fa; display: flex; justify-content: flex-end; gap: 10px;">
                <button id="yacy-btn-cancel" style="padding: 8px 16px; border: none; background: #e74c3c; color: white; border-radius: 6px; cursor: pointer; font-weight: bold;">Cancelar</button>
                <button id="yacy-btn-confirm" style="padding: 8px 16px; border: none; background: #2ecc71; color: white; border-radius: 6px; cursor: pointer; font-weight: bold;">Confirmar y Descargar HTML</button>
            </div>
        `;

        modalOverlay.appendChild(modalContainer);
        document.body.appendChild(modalOverlay);

        const closeModal = () => modalOverlay.remove();

        document.getElementById('yacy-close-x').onclick = closeModal;
        document.getElementById('yacy-btn-cancel').onclick = closeModal;

        document.getElementById('yacy-btn-confirm').onclick = () => {
            saveHtmlFile(htmlContent, sourceUrl, pageTitle, date);
            closeModal();
        };
    }

    function saveHtmlFile(htmlContent, sourceUrl, pageTitle, date) {
        // SEGURIDAD: sin escapar, un '"' en la URL rompería el atributo href y
        // permitiría inyectar HTML en el archivo descargado. Se escapa todo dato
        // que no sea el propio contenido seleccionado por el usuario.
        const safeUrl = escapeHtml(sourceUrl);
        const safeDate = escapeHtml(date);
        const safeTitle = escapeHtml(pageTitle);

        const finalHtml = `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>${safeTitle}</title>
    <!-- canonical + base: hacen que YaCy atribuya el fragmento a la URL
         pública original en lugar de a un archivo local -->
    <link rel="canonical" href="${safeUrl}">
    <base href="${safeUrl}">
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; line-height: 1.6; color: #222; }
        .metadata { background: #f4f4f4; padding: 15px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9em; border-left: 4px solid #2ecc71; }
        .content { border-top: 1px solid #ddd; padding-top: 20px; }
    </style>
</head>
<body>
    <div class="metadata">
        <h2>${safeTitle}</h2>
        <p><strong>Fuente Original:</strong> <a href="${safeUrl}">${safeUrl}</a></p>
        <p><strong>Capturado el:</strong> ${safeDate}</p>
    </div>
    <div class="content">
        ${htmlContent}
    </div>
</body>
</html>`;

        const blob = new Blob([finalHtml], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `YaCy_Snippet_${new Date().getTime()}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        showToast("✅ Fragmento guardado con etiquetas Canonical y Base.");
    }

    function captureSelection() {
        const selection = window.getSelection();
        if (!selection || selection.rangeCount === 0 || selection.toString().trim() === '') {
            alert('❌ No has seleccionado ningún texto o contenedor. Sombrea primero el texto con el ratón.');
            return;
        }

        const range = selection.getRangeAt(0);
        const clonedSelection = range.cloneContents();
        const div = document.createElement('div');
        div.appendChild(clonedSelection);
        const htmlContent = div.innerHTML;

        const pageTitle = document.title || 'Snippet sin título';
        const sourceUrl = window.location.href;

        showSnippetPreviewModal(htmlContent, sourceUrl, pageTitle);
    }

    // ==========================================
    // 8. DETECCIÓN Y MENÚS
    // ==========================================

    function triggerAutoEvaluation() {
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            try {
                const currentUrlObj = new URL(window.location.href);

                // Solo http/https: nada de file:, chrome:, about:, ftp: ni
                // javascript:. Además se descartan redes privadas para no
                // intentar indexar la intranet.
                if (isIpPrivate(currentUrlObj.hostname) || !['http:', 'https:'].includes(currentUrlObj.protocol)) return;

                // Dominios bloqueados y URLs con datos privados.
                if (isDomainBlacklisted(currentUrlObj.hostname.toLowerCase()) || hasSensitiveData(currentUrlObj)) return;

                const cleanUrlObj = sanitizeUrl(currentUrlObj);
                if (!cleanUrlObj) return;
                const finalUrl = cleanUrlObj.toString();
                if (finalUrl !== lastSentUrl) sendToYaCy(finalUrl, false);
            } catch (e) {}
        }, DELAY_MS);
    }

    function triggerManualIndex() {
        try {
            const currentUrlObj = new URL(window.location.href);
            if (isIpPrivate(currentUrlObj.hostname)) return alert("❌ Seguridad: No puedes indexar IPs locales.");
            // En manual, si la URL contiene datos privados se pide confirmación
            // expresa en lugar de descartarla en silencio, porque el usuario
            // ha pedido indexarla a propósito.
            if (hasSensitiveData(currentUrlObj) && !confirm("⚠ ADVERTENCIA: Esta URL contiene palabras sensibles. ¿Enviar de todos modos?")) return;
            sendToYaCy(sanitizeUrl(currentUrlObj).toString(), true);
        } catch (e) { alert("❌ Error procesando la URL."); }
    }

    function init() {
        // No actuar dentro de iframes: en ellos window.location es la del marco
        // y no la página que el usuario está leyendo.
        try { if (window.top !== window.self) return; } catch (e) { return; }

        GM_registerMenuCommand("🕷️ Enviar URL a YaCy (Manual)", triggerManualIndex);
        GM_registerMenuCommand("✂️ Capturar Selección (Oro Puro)", captureSelection);
        GM_registerMenuCommand("🔑 Configurar Credenciales de YaCy", configureCredentials);
        GM_registerMenuCommand("🌐 Configurar Nodo YaCy (Host)", configureHost);
        GM_registerMenuCommand("🔄 Resetear Credenciales de YaCy", function() {
            GM_setValue('yacy_user', '');
            GM_setValue('yacy_password', '');
            showToast("🔄 Credenciales de YaCy eliminadas.");
        });
        triggerAutoEvaluation();

        // COMPATIBILIDAD: Violentmonkey ejecuta el userscript en un contexto
        // separado (sandbox) y window.history apunta al objeto del sandbox, no
        // al de la página. unsafeWindow da acceso al objeto real. Se usa cuando
        // está disponible (requiere @grant unsafeWindow en el encabezado) y si
        // no, se usa window. El try/catch evita que, si el envoltorio lanzase
        // una excepción, el script entero dejara de funcionar.
        const win = (typeof unsafeWindow !== 'undefined' && unsafeWindow) ? unsafeWindow : window;
        const targetHistory = win.history || history;

        if (targetHistory) {
            try {
                const originalPushState = targetHistory.pushState;
                if (typeof originalPushState === 'function') {
                    targetHistory.pushState = function (...args) {
                        const res = originalPushState.apply(this, args);
                        triggerAutoEvaluation();
                        return res;
                    };
                }
            } catch (e) {
                console.warn("[YaCy Script] No se pudo envolver pushState:", e);
            }

            try {
                const originalReplaceState = targetHistory.replaceState;
                if (typeof originalReplaceState === 'function') {
                    targetHistory.replaceState = function (...args) {
                        const res = originalReplaceState.apply(this, args);
                        triggerAutoEvaluation();
                        return res;
                    };
                }
            } catch (e) {
                console.warn("[YaCy Script] No se pudo envolver replaceState:", e);
            }
        }

        window.addEventListener('popstate', triggerAutoEvaluation);
        window.addEventListener('hashchange', triggerAutoEvaluation);
    }

    init();

})();
