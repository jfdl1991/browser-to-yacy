// ==UserScript==
// @name         Browser a YaCy
// @namespace    http://tampermonkey.net/
// @version      1.2.3
// @description  Envía la página actual a un nodo YaCy local para indexar, protegiendo la privacidad.
// @author       Jfdl1991
// @match        http://*/*
// @match        https://*/*
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @connect      localhost
// @connect      127.0.0.1:8090
// @run-at      document-idle
// @noframes
// @license MIT
// ==UserScript==

(function () {
    'use strict';

    // ==========================================
    // 1. CONFIGURACIÓN (GM persistence para host)
    // ==========================================
    const YACY_HOST = GM_getValue('YACY_HOST', 'http://localhost:8090');
    const DELAY_MS = 3500; // Delay anti-DDoS antes del primer envío
    const REQ_TIMEOUT_MS = 15000; // Timeout por request GM_xmlhttpRequest
    const MAX_RETRY_ATTEMPTS = 3; // Máximo reintentos en caso de fallo
    const POLL_INTERVAL_MS = 5000; // Intervalo para detectar cambios de URL (5s)
    const COOLDOWN_FACTOR = 6; // 1 envío cada 6 polls = ~30s (anti-CAPTCHA)
    let pollCounter = 0;

    // ==========================================
    // 2. LISTAS DE SEGURIDAD (Set para O(1) lookup)
    // ==========================================
    const BLACKLISTED_DOMAINS = new Set([
                'localhost', '[IP_ADDRESS]', // Placeholder para usuario (documentado)
                'google.com', 'docs.google.com', 'drive.google.com', 'mail.google.com', 'keep.google.com',
                'notion.so', 'dropbox.com', 'onedrive.live.com', 'icloud.com',
                'paypal.com', 'stripe.com', 'mercadopago.com',
                'github.com', 'gitlab.com', 'bitbucket.org'
            ]);

    const SENSITIVE_KEYWORDS_PATTERNS = [
        'cart', 'checkout', 'account', 'login', 'signin', 'signup',
        'billing', 'payment', 'bank', 'card', 'tarjeta', 'pago',
        'medico', 'health', 'medical', 'password', 'reset', 'verify',
        'auth', 'token', 'session', 'dashboard', 'admin',
        // Expandido para cobertura completa (HIGH)
        'ssn', 'dob', 'passport', 'insurance', 'diagnosis', 'prescription',
        'patient', 'npi', 'medicare', 'salary', 'payroll', 'w2', 'invoice',
        'receipt', 'credit', 'loan', 'mortgage', 'iban', 'swift', 'routing',
        'key', 'secret', 'csrf', 'nonce', 'state', 'refresh_token', 'id_token', 'pin', 'cvv', 'otp',
        'profile', 'settings', 'logout', 'signout', 'terms', 'privacy'
    ];
    const SENSITIVE_KEYWORDS_REGEX = new RegExp(SENSITIVE_KEYWORDS_PATTERNS.join('|'), 'i');

    const TRACKING_PARAMS_EXACT = new Set([
                'gclid', 'fbclid', 'msclkid', 'ref', 'source', '_hsenc', 'mc_eid',
                // Expandido para cobertura completa (MEDIUM)
                'yclid', 'dclid', 'twclid', 'ttclid', 'gbraid', 'wbraid',
                'mc_cid', 'sc_', 'track', 'trk', '__hstc', 'hsa_fp',
                'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
                'cx', 'ie', 'source', 'gac'
            ]);

    const SENSITIVE_PARAMS = new Set([
                'token', 'auth', 'key', 'pwd', 'code', 'session', 'sig', 'signature',
                'access_token', 'api_key', 'apikey', 'secret', 'csrf', 'state',
                'id_token', 'refresh_token', 'password', 'pin', 'cvv', 'otp', 'mfa_code',
                'session_id', 'viewer_id', 'user_id'
            ]);

    // MustNotMatch patterns as Set for O(1) lookup (replaces fragile monolithic regex)
    const MUST_NOT_MATCH_PATTERNS = new Set([
                'file:', 'chrome:', 'about:', 'ftp:', 'javascript:',
                '192.168.', 'localhost',
                'cart', 'checkout', 'account', 'login', 'signin', 'signup',
                'billing', 'payment', 'paypal', 'stripe', 'bank', 'card', 'tarjeta', 'pago',
                'medico', 'health', 'medical',
                'token=', 'auth=', 'key=', 'pwd=', 'code=', 'session=', 'signature=',
                'password=', 'secret=', 'csrf=', 'state=', 'refresh_token=', 'id_token=',
                'admin', 'dashboard', 'reset', 'verify'
            ]);

    // Regex pre-compilados (HIGH - IPv6, 169.254, .local, Carrier-Grade NAT 100.64.x.x)
    const IP_PRIVATE_REGEX = /^(127\.|0\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|::1|fe80:|fc00:|fd00:)/i;
    // LOCALHOST_REGEX: more precise - only match exact .local TLD, not any subdomain ending in .local
    const LOCALHOST_REGEX = /^(localhost|[0-9]{1,3}\.local$|\.local$|intranet|internal|network)$/i;

    // ==========================================
    // 3. ESTADO DE PROCESAMIENTO (evita carreras y duplicados)
    // ==========================================
    let isProcessing = false;
    let lastProcessedUrl = '';
    let pendingRequestAbortController = null;

    // ==========================================
    // 4. FUNCIONES DE SEGURIDAD (ZERO-LEAK)
    // ==========================================
    function isDomainBlacklisted(hostname) {
        return BLACKLISTED_DOMAINS.has(hostname) ||
        [...BLACKLISTED_DOMAINS].some(domain => hostname.endsWith('.' + domain));
    }

    function isIpPrivate(hostname) {
        const lower = hostname.toLowerCase();
        return IP_PRIVATE_REGEX.test(lower) || LOCALHOST_REGEX.test(lower);
    }

    function checkMustNotMatchPatterns(text) {
        const lower = text.toLowerCase();
        for (const pattern of MUST_NOT_MATCH_PATTERNS) {
            if (lower.includes(pattern))
                return true;
        }
        return false;
    }

    function isUrlSafe(urlObj) {
        try {
            // 4.1. Rechazar credenciales embebidas
            if (urlObj.username || urlObj.password)
                return false;

            // 4.2. Rechazar protocolos no web
            if (!['http:', 'https:'].includes(urlObj.protocol))
                return false;

            // 4.3. Rechazar IPs privadas y localhost
            const hostname = urlObj.hostname.toLowerCase();
            if (isIpPrivate(hostname))
                return false;

            // 4.4. Rechazar dominios en blacklist
            if (isDomainBlacklisted(hostname))
                return false;

            // 4.5. Rechazar keywords sensibles (case-insensitive) - check decoded path
            const fullPath = (urlObj.pathname + urlObj.search + urlObj.hash).toLowerCase();
            if (SENSITIVE_KEYWORDS_REGEX.test(fullPath))
                return false;

            // 4.5b. Also check RAW href for URL-encoded keywords (e.g., %22login%22)
            const rawHref = window.location.href.toLowerCase();
            if (checkMustNotMatchPatterns(rawHref))
                return false;

            // 4.6. Rechazar parámetros sensibles (nombre exacto y contenido)
            for (const param of urlObj.searchParams.keys()) {
                const lowerParam = param.toLowerCase();
                if (SENSITIVE_PARAMS.has(lowerParam))
                    return false;
                // Defensa extra: si el nombre del param contiene palabras sensibles (ej: access_token_key)
                if ([...SENSITIVE_PARAMS].some(s => lowerParam.includes(s)))
                    return false;
            }

            return true;
        } catch (e) {
            console.warn('[YaCy P2P] Error parsing URL:', e);
            return false;
        }
    }

    // ==========================================
    // 5. SANITIZACIÓN Y LIMPIEZA
    // ==========================================
    function sanitizeUrl(urlObj) {
        try {
            const cleanUrl = new URL(urlObj.href);

            // 5.1. Eliminar parámetros UTM y tracking exactos
            const paramsToDelete = [];
            cleanUrl.searchParams.forEach((value, key) => {
                const lowerKey = key.toLowerCase();
                if (lowerKey.startsWith('utm_') || TRACKING_PARAMS_EXACT.has(lowerKey)) {
                    paramsToDelete.push(key);
                }
            });

            // 5.2. Eliminar parámetros sensibles adicionales
            for (const param of cleanUrl.searchParams.keys()) {
                if (SENSITIVE_PARAMS.has(param.toLowerCase())) {
                    paramsToDelete.push(param);
                }
            }

            paramsToDelete.forEach(param => cleanUrl.searchParams.delete(param));

            // 5.3. Eliminar hash por seguridad (nunca enviar fragmentos)
            cleanUrl.hash = '';

            return cleanUrl.toString();
        } catch (e) {
            console.error('[YaCy P2P] Error sanitizando URL:', e);
            return null;
        }
    }

    // ==========================================
    // 6. ENVÍO AL NODO YACY (con retry exponencial y timeout)
    // ==========================================
    function buildYaCyParams(targetUrl) {
        const ipMustnotmatch = "(127\\\\\\\\.0\\\\\\\\.0\\\\\\\\.1|localhost|192\\\\\\\\.168\\\\\\\\..*|10\\\\\\\\..*|172\\\\\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\\\\\.\\\\.\\\\.)|(169\\\\\\\\.254\\\\\\\\..*)|(::1|fe80:|fc00:|fd00:))";
        // Build mustnotmatch from Set for YaCy server-side
        const mustnotmatchPatterns = [...MUST_NOT_MATCH_PATTERNS].join('|');
        const mustnotmatch = ".*(" + mustnotmatchPatterns + ").*";

        const apiParams = new URLSearchParams({
            'crawlingstart': '',
            'crawlingMode': 'url',
            'crawlingURL': targetUrl,
            'crawlingDepth': '0',
            'indexText': 'on',
            'indexMedia': 'off',
            'storeHTCache': 'off',
            'crawlingQ': 'on',
            'recrawl': 'reload',
            'reloadIfOlderNumber': '30',
            'reloadIfOlderUnit': 'day',
            'cachePolicy': 'no cache',
            'crawlOrder': 'off', // MANTENER OFF: usuario explícitamente NO quiere mandar a otros nodos
            'xsstopw': 'on',
            'agentName': 'Mozilla/5.0 (compatible; YaCy-AutoIndexer)', // Discreto para evitar CAPTCHAs
            'ipMustnotmatch': ipMustnotmatch,
            'mustnotmatch': mustnotmatch
        });

        return `${YACY_HOST}/Crawler_p.html?${apiParams.toString()}`;
    }

    function sendToYaCy(targetUrl, attempt = 1) {
        if (attempt > MAX_RETRY_ATTEMPTS) {
            console.error('[YaCy P2P] ? Falló después de ' + MAX_RETRY_ATTEMPTS + ' intentos');
            isProcessing = false; // Reset estado al fallar
            return Promise.reject(new Error('Max retries exceeded'));
        }

        const apiUrl = buildYaCyParams(targetUrl);

        // Configurar timeout y abort controller si es posible
        const timeoutId = setTimeout(() => {
            if (isProcessing && attempt < MAX_RETRY_ATTEMPTS) {
                console.warn('[YaCy P2P] Timeout attempt ' + attempt + '/' + MAX_RETRY_ATTEMPTS);
                setTimeout(() => {
                    if (isProcessing) {
                        sendToYaCy(targetUrl, attempt + 1);
                    }
                }, 1000 * Math.pow(2, attempt - 1)); // Backoff exponencial: 1s, 2s, 4s, 8s...
            } else if (attempt >= MAX_RETRY_ATTEMPTS) {
                console.error('[YaCy P2P] ? Timeout final tras múltiples intentos');
                isProcessing = false;
            }
        }, REQ_TIMEOUT_MS);

        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: "GET",
                url: apiUrl,
                timeout: REQ_TIMEOUT_MS, // Timeout nativo si está soportado
                ontimeout: function () {
                    clearTimeout(timeoutId);
                    if (isProcessing && attempt < MAX_RETRY_ATTEMPTS) {
                        console.warn('[YaCy P2P] Timeout nativo attempt ' + attempt + '/' + MAX_RETRY_ATTEMPTS);
                        setTimeout(() => {
                            if (isProcessing) {
                                sendToYaCy(targetUrl, attempt + 1).then(resolve).catch(reject);
                            }
                        }, 1000 * Math.pow(2, attempt - 1));
                    } else {
                        clearTimeout(timeoutId);
                        isProcessing = false;
                        reject(new Error('Request timeout'));
                    }
                },
                onload: function (response) {
                    clearTimeout(timeoutId);
                    if (response.status === 200) {
                        console.log('[YaCy P2P] ??? URL indexada: ' + targetUrl);
                        isProcessing = false; // IMPORTANTE: reset estado al éxito
                        resolve(response);
                    } else {
                        console.warn('[YaCy P2P] ?? YaCy respondió: ' + response.status);
                        if (isProcessing && attempt < MAX_RETRY_ATTEMPTS) {
                            setTimeout(() => {
                                if (isProcessing) {
                                    sendToYaCy(targetUrl, attempt + 1).then(resolve).catch(reject);
                                }
                            }, 1000 * Math.pow(2, attempt - 1));
                        } else {
                            isProcessing = false;
                            resolve(response);
                        }
                    }
                },
                onerror: function (err) {
                    clearTimeout(timeoutId);
                    if (isProcessing && attempt < MAX_RETRY_ATTEMPTS) {
                        console.warn('[YaCy P2P] Error attempt ' + attempt + '/' + MAX_RETRY_ATTEMPTS + ': ' + err.message);
                        setTimeout(() => {
                            if (isProcessing) {
                                sendToYaCy(targetUrl, attempt + 1).then(resolve).catch(reject);
                            }
                        }, 1000 * Math.pow(2, attempt - 1));
                    } else {
                        isProcessing = false;
                        console.error('[YaCy P2P] ? Error de conexión final: ' + err.message);
                        reject(err);
                    }
                }
            });
        });
    }

    // ==========================================
    // 7. PROCESAMÍNDICE PRINCIPAL (corregido)
    // ==========================================
    function scheduleIndex() {
        if (isProcessing)
            return; // Evita procesamiento concurrente

        const currentUrl = window.location.href;
        if (currentUrl === lastProcessedUrl)
            return; // Evita reprocesar la misma URL

        lastProcessedUrl = currentUrl;
        isProcessing = true; // IMPORTANTE: establecer bandera antes de procesar

        // Pequeño delay para permitir que la URL se estabilice tras navegación
        setTimeout(processIndex, 500);
    }

    function processIndex() {
        if (!isProcessing)
            return; // Doble check de seguridad

        try {
            const currentUrlObj = new URL(window.location.href);

            // Re-validar URL justo antes de enviar (maneja redirects durante delay)
            if (!isUrlSafe(currentUrlObj)) {
                console.log("[YaCy P2P] ??? URL omitida por políticas de privacidad (re-validada)");
                isProcessing = false;
                return;
            }

            const cleanUrl = sanitizeUrl(currentUrlObj);
            if (!cleanUrl) {
                console.error("[YaCy P2P] Error al sanitizar URL");
                isProcessing = false;
                return;
            }

            // Esperar a que la página esté completamente cargada antes de enviar
            if (document.readyState !== 'complete') {
                // Esperar hasta que esté completa
                const checkReady = () => {
                    if (document.readyState === 'complete') {
                        setTimeout(() => {
                            if (isProcessing) {
                                sendToYaCy(cleanUrl).catch(e => {
                                    console.error('[YaCy P2P] Error:', e);
                                    isProcessing = false;
                                });
                            }
                        }, 0);
                    } else {
                        setTimeout(checkReady, 100);
                    }
                };
                checkReady();
            } else {
                // Ya está completa, enviar inmediatamente
                setTimeout(() => {
                    if (isProcessing) {
                        sendToYaCy(cleanUrl).catch(e => {
                            console.error('[YaCy P2P] Error:', e);
                            isProcessing = false;
                        });
                    }
                }, 0);
            }
        } catch (e) {
            console.error('[YaCy P2P] Error procesando URL:', e);
            isProcessing = false;
        }
    }

    // ==========================================
    // 8. INICIALIZADOR PRINCIPAL
    // ==========================================
    function init() {
        // @noframes ya evita ejecutar en iframes, pero por si acaso (con try/catch para cross-origin)
        try {
            if (window.top !== window.self) {
                return;
            }
        } catch (e) {
            // Si hay error al acceder a window.top (cross-origin), asumimos que estamos en iframe
            return;
        }

        // Marcar carga inicial completada
        initialLoadComplete = true;

        // Procesar URL inicial (no inmediatamente, para permitir carga de página)
        setTimeout(scheduleIndex, DELAY_MS);
    }

    // Estado de carga inicial
    let initialLoadComplete = false;

    // Escuchar navegación SPA (History API)
    let initialPushState = true;
    window.addEventListener('popstate', () => {
        if (!initialPushState) {
            scheduleIndex();
        }
    });

    window.addEventListener('hashchange', () => {
        scheduleIndex();
    });

    // Soporte básico para pushState (sobrescribir para detectar cambios)
    const origPushState = history.pushState;
    history.pushState = function (...args) {
        origPushState.apply(this, args);
        // Pequeño delay para permitir que la URL se establezca
        setTimeout(() => {
            if (!initialPushState) {
                scheduleIndex();
            }
        }, 100);
    };

    // ==========================================
    // 9. MONITOREO DE CAMBIOS DE URL (para SPA y redirects lentos)
    // ==========================================
    let prevHref = location.href;
    setInterval(() => {
        // Guard: no procesar si la pestaña está oculta (ahorra CPU)
        if (document.hidden)
            return;

        if (location.href !== prevHref) {
            prevHref = location.href;
            pollCounter++;
            // Rate limiting: solo procesar cada COOLDOWN_FACTOR polls (~30s)
            if (pollCounter % COOLDOWN_FACTOR === 0) {
                // Verificar si es una URL segura antes de procesar
                try {
                    const urlObj = new URL(location.href);
                    if (isUrlSafe(urlObj)) {
                        const cleanUrl = sanitizeUrl(urlObj);
                        if (cleanUrl && !isProcessing) {
                            setTimeout(() => {
                                if (!isProcessing) {
                                    scheduleIndex();
                                }
                            }, 100);
                        }
                    }
                } catch (e) {
                    // URL malformada, ignorar silenciosamente
                }
            }
        }
    }, POLL_INTERVAL_MS);

    // ==========================================
    // 10. EJECUCIÓN INICIAL
    // ==========================================
    // Esperar a que el DOM esté listo antes de iniciar
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        // Ya cargado
        init();
    }

})();
