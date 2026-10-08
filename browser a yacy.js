// ==UserScript==
// @name         browser a yacy (Auto + Manual + Snippets Canonical)
// @namespace    jfdl19991
// @version      1.7.2
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



(function () {
    'use strict';

    // ==========================================
    // 1. CONFIGURACIÓN
    // ==========================================
    const YACY_HOST = GM_getValue('YACY_HOST', 'http://localhost:8090');
    const DELAY_MS = 4000;
    let debounceTimer = null;
    let lastSentUrl = '';

    // ==========================================
    // 2. LISTAS DE FILTRADO
    // ==========================================
    const BLACKLISTED_DOMAINS = new Set([
        'localhost', 'google.com', 'docs.google.com', 'drive.google.com', 'mail.google.com',
        'notion.so', 'dropbox.com', 'onedrive.live.com', 'icloud.com', 'evernote.com',
        'twitter.com', 'x.com', 'facebook.com', 'instagram.com', 'pinterest.com',
        'linkedin.com', 'tiktok.com', 'twitch.tv', 'medium.com', 'substack.com',
        'wordpress.com', 'blogspot.com', 'tumblr.com', 'netflix.com', 'paypal.com',
        'stripe.com', 'binance.com'
    ]);

    const SENSITIVE_KEYWORDS_PATTERNS = [
        'cart', 'checkout', 'account', 'login', 'signin', 'signup',
        'billing', 'payment', 'bank', 'card', 'tarjeta', 'pago',
        'password', 'reset', 'verify', 'dashboard', 'admin', 'ssn',
        'passport', 'invoice', 'receipt', 'credit', 'loan', 'settings',
        'logout', 'signout', 'privacy', 'profile', 'mail'
    ];
    const SENSITIVE_KEYWORDS_REGEX = new RegExp('\\b(' + SENSITIVE_KEYWORDS_PATTERNS.join('|') + ')\\b', 'i');

    const SENSITIVE_PARAMS = new Set([
        'token', 'auth', 'key', 'pwd', 'code', 'session', 'sig', 'signature',
        'access_token', 'api_key', 'apikey', 'secret', 'csrf', 'state',
        'id_token', 'refresh_token', 'password', 'pin', 'otp', 'mfa_code',
        'jwt', 'bearer'
    ]);
    // Pre-compile sensitive param substring matching regex at module level to avoid allocations on every URL evaluation
    const SENSITIVE_PARAMS_SUBSTRING_REGEX = new RegExp([...SENSITIVE_PARAMS].join('|'), 'i');

    const TRACKING_PARAMS_EXACT = new Set([
        'gclid', 'fbclid', 'msclkid', 'ref', 'source', 'mc_eid', 'si', 'igshid',
        'yclid', 'dclid', 'twclid', 'ttclid', 'gbraid', 'wbraid', 's',
        'mc_cid', 'track', 'trk', '__hstc', 'hsa_fp', 'affiliate', 'ref_src',
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
        'cx', 'ie', 'share_id', 'camp'
    ]);

    const IP_PRIVATE_REGEX = /^(127\.|0\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\.|::1|fe80:|fc00:|fd00:)/i;
    const LOCALHOST_REGEX = /(^|\.)(localhost|local|intranet|internal|network)$/i;

    // ==========================================
    // 3. SEGURIDAD Y SANITIZACIÓN
    // ==========================================
    function sanitizeUrl(urlObj) {
        try {
            const cleanUrl = new URL(urlObj.href);
            const paramsToDelete = [];
            cleanUrl.searchParams.forEach((value, key) => {
                const lowerKey = key.toLowerCase();
                if (lowerKey.startsWith('utm_') || TRACKING_PARAMS_EXACT.has(lowerKey) || value.length > 256) {
                    paramsToDelete.push(key);
                }
            });
            paramsToDelete.forEach(param => cleanUrl.searchParams.delete(param));
            cleanUrl.hash = '';
            return cleanUrl;
        } catch (e) { return null; }
    }

    function hasSensitiveData(urlObj) {
        if (urlObj.username || urlObj.password) return true;
        const fullPath = (urlObj.pathname + urlObj.search).toLowerCase();
        if (SENSITIVE_KEYWORDS_REGEX.test(fullPath)) return true;
        for (const param of urlObj.searchParams.keys()) {
            const lowerParam = param.toLowerCase();
            // Fast Set lookup first; pre-compiled regex for substring checks eliminates array spreading allocations
            if (SENSITIVE_PARAMS.has(lowerParam) || SENSITIVE_PARAMS_SUBSTRING_REGEX.test(lowerParam)) return true;
        }
        return false;
    }

    function isIpPrivate(hostname) {
        return IP_PRIVATE_REGEX.test(hostname) || LOCALHOST_REGEX.test(hostname);
    }

    function isDomainBlacklisted(hostname) {
        if (BLACKLISTED_DOMAINS.has(hostname)) return true;
        // Direct iteration over Set avoids Array spreading [...BLACKLISTED_DOMAINS] on every navigation check
        for (const domain of BLACKLISTED_DOMAINS) {
            if (hostname.endsWith('.' + domain)) return true;
        }
        return false;
    }

    function escapeHtml(str) {
        return str.replace(/[&<>"']/g, function(m) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m];
        });
    }

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
    // 4. NOTIFICACIONES Y ENVÍO API
    // ==========================================
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

    function sendToYaCy(targetUrl, isManual = false) {
        // 1. Intentar obtener el usuario y contraseña guardados localmente
        let usuario = GM_getValue('yacy_user');
        let contrasena = GM_getValue('yacy_password');

        // 2. Si no existen, pedir solo si es acción manual o notificar silenciosamente si es auto
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

        const ipMustnotmatch = "(127\\.0\\.0\\.1|localhost|192\\.168\\..*|10\\..*|172\\.(1[6-9]|2[0-9]|3[0-1])\\..*|169\\.254\\..*|100\\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\\..*|::1|fe80:|fc00:|fd00:)";
        const mustnotmatch = ".*(file:|chrome:|about:|ftp:|javascript:|token=|auth=|key=|pwd=|code=|session=|signature=|password=|secret=|csrf=|state=|jwt=|bearer=).*";

        const apiParams = new URLSearchParams({
            'crawlingstart': '1',
            'crawlingMode': 'url',
            'crawlingURL': targetUrl,
            'crawlingDepth': '0',
            'crawlingIfFileExists': 'override',
            'crawlingPost': 'on',
            'crawlingFilter': '.*',
            'crawlingDomFilterDepth': '0',
            'crawlingDomMaxPages': '10000',
            'indexText': 'on',
            'indexMedia': 'off',
            'storeHTCache': 'off',
            'crawlingQ': 'on',
            'recrawl': 'reload',
            'cachePolicy': 'no cache',
            'crawlOrder': 'off',
            'agentName': 'Mozilla/5.0 (compatible; YaCy-AutoIndexer)',
            'crawlingAgentName': 'Mozilla/5.0 (compatible; YaCy-AutoIndexer)',
            'ipMustnotmatch': ipMustnotmatch,
            'mustnotmatch': mustnotmatch
        });

        // Crear el token de autenticación con los datos recuperados o guardados (compatible con UTF-8)
        function utf8ToBase64(str) {
            return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function(match, p1) {
                return String.fromCharCode('0x' + p1);
            }));
        }
        const tokenAutenticacion = "Basic " + utf8ToBase64(usuario + ":" + contrasena);

        // Registro en la consola de la URL que se va a enviar
        console.log("[YaCy Script] Enviando URL a rastrear:", targetUrl);

        GM_xmlhttpRequest({
            method: "GET",
            url: `${YACY_HOST}/CrawlStart_p.html?${apiParams.toString()}`,
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
                    // Si el error es 401 (No autorizado), borramos los datos para que vuelva a preguntar la próxima vez
                    if (response.status === 401) {
                        GM_setValue('yacy_user', '');
                        GM_setValue('yacy_password', '');
                        console.warn("[YaCy Script] Error 401: Credenciales incorrectas. Se han borrado para volver a pedirlas.");
                    }
                }
            },
            onerror: function(err) {
                if (isManual) showToast("❌ Error de conexión con YaCy", true);
            }
        });
}
    // ==========================================
    // 5. VISTA PREVIA Y GUARDADO DE SNIPPETS
    // ==========================================
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
        const safeTitle = escapeHtml(pageTitle);
        const safeUrl = escapeHtml(sourceUrl);

        modalContainer.innerHTML = `
            <div style="padding: 15px 20px; background: #2c3e50; color: #ffffff; display: flex; justify-content: space-between; align-items: center;">
                <h3 style="margin: 0; font-size: 16px;">Vista Previa del Snippet - YaCy</h3>
                <span id="yacy-close-x" style="cursor: pointer; font-size: 20px; font-weight: bold;">&times;</span>
            </div>
            <div style="padding: 15px; background: #f8f9fa; border-bottom: 1px solid #e9ecef; font-size: 13px;">
                <strong>Título:</strong> ${safeTitle}<br>
                <strong>Fuente Canonical:</strong> ${safeUrl}<br>
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
        const finalHtml = `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>${escapeHtml(pageTitle)}</title>
    <link rel="canonical" href="${sourceUrl}">
    <base href="${sourceUrl}">
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; line-height: 1.6; color: #222; }
        .metadata { background: #f4f4f4; padding: 15px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9em; border-left: 4px solid #2ecc71; }
        .content { border-top: 1px solid #ddd; padding-top: 20px; }
    </style>
</head>
<body>
    <div class="metadata">
        <h2>${escapeHtml(pageTitle)}</h2>
        <p><strong>Fuente Original:</strong> <a href="${sourceUrl}">${sourceUrl}</a></p>
        <p><strong>Capturado el:</strong> ${date}</p>
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
    // 6. DETECCIÓN Y MENÚS
    // ==========================================
    function triggerAutoEvaluation() {
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            try {
                const currentUrlObj = new URL(window.location.href);
                if (isIpPrivate(currentUrlObj.hostname) || !['http:', 'https:'].includes(currentUrlObj.protocol)) return;
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
            if (hasSensitiveData(currentUrlObj) && !confirm("⚠ ADVERTENCIA: Esta URL contiene palabras sensibles. ¿Enviar de todos modos?")) return;
            sendToYaCy(sanitizeUrl(currentUrlObj).toString(), true);
        } catch (e) { alert("❌ Error procesando la URL."); }
    }

    function init() {
        try { if (window.top !== window.self) return; } catch (e) { return; }

        GM_registerMenuCommand("🕷️ Enviar URL a YaCy (Manual)", triggerManualIndex);
        GM_registerMenuCommand("✂️ Capturar Selección (Oro Puro)", captureSelection);
        GM_registerMenuCommand("🔑 Configurar Credenciales de YaCy", configureCredentials);
        GM_registerMenuCommand("🔄 Resetear Credenciales de YaCy", function() {
            GM_setValue('yacy_user', '');
            GM_setValue('yacy_password', '');
            showToast("🔄 Credenciales de YaCy eliminadas.");
        });
        triggerAutoEvaluation();

        // Soporte para Violentmonkey sandbox usando unsafeWindow cuando esté disponible
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
