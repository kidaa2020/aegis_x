/**
 * @file traffic.js
 * @description Gestión de la captura y visualización en tiempo real del tráfico HTTP/HTTPS.
 * Procesa mensajes del WebSocket, filtra registros, permite inspección profunda
 * de cabeceras/cuerpo y envía solicitudes al motor de auditoría IA.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Referencias al DOM
    const trafficTableBody = document.getElementById('traffic-table-body');
    const tableContainer = document.getElementById('traffic-table-container');
    const emptyRow = document.getElementById('empty-traffic-row');

    // Contadores
    const counterTotal = document.getElementById('counter-total-traffic');
    const counterFiltered = document.getElementById('counter-filtered-traffic');
    const counterAnalyzed = document.getElementById('counter-analyzed-traffic');

    // Filtros y Controles
    const targetFilter = document.getElementById('traffic-target-filter');
    const methodFilter = document.getElementById('traffic-method-filter');
    const searchInput = document.getElementById('traffic-search-input');
    const toggleAutoscroll = document.getElementById('toggle-autoscroll');
    const btnToggleStream = document.getElementById('btn-toggle-stream');
    const streamIcon = document.getElementById('stream-icon');
    const streamText = document.getElementById('stream-text');
    const btnClearTraffic = document.getElementById('btn-clear-traffic');

    // Estado local
    let isStreamPaused = false;
    let totalRequestsCount = 0;
    let analyzedRequestsCount = 0;
    const MAX_ROWS = 250; // Límite para evitar saturar el DOM del navegador
    let trafficItems = [];

    // ========================================================
    // INICIALIZACIÓN DE SELECTOR DE OBJETIVOS
    // ========================================================
    async function loadTargetsFilter() {
        try {
            const res = await fetch('/api/targets');
            if (!res.ok) return;
            const targets = await res.json();

            targetFilter.innerHTML = '<option value="">🎯 Todos los Objetivos</option>';
            targets.forEach(t => {
                const opt = document.createElement('option');
                opt.value = t.id;
                opt.textContent = `${t.domain || t.name} (#${t.id})`;
                targetFilter.appendChild(opt);
            });

            // Leer target_id de URL si existe
            const urlParams = new URLSearchParams(window.location.search);
            const paramTarget = urlParams.get('target_id');
            if (paramTarget) {
                targetFilter.value = paramTarget;
            }
        } catch (e) {
            console.warn('[Traffic] No se pudieron cargar los objetivos para el filtro:', e);
        }
    }

    // Cargar historial previo de tráfico si el backend lo ofrece
    async function loadInitialTraffic() {
        try {
            const res = await fetch('/api/traffic?limit=50');
            if (!res.ok) return;
            const data = await res.json();
            const items = Array.isArray(data) ? data : (data.items || []);

            if (items.length > 0) {
                if (emptyRow) emptyRow.remove();
                items.forEach(item => processNewTrafficEntry(item, false));
            }
        } catch (e) {
            console.log('[Traffic] Sin historial inicial o endpoint no disponible.');
        }
    }

    // ========================================================
    // PROCESAMIENTO Y RENDERIZADO DE NUEVAS ENTRADAS
    // ========================================================
    /**
     * Procesa y añade un nuevo registro de tráfico a la tabla.
     * @param {Object} entry Datos del paquete HTTP
     * @param {boolean} isLive Indica si proviene del WebSocket en vivo
     */
    function processNewTrafficEntry(entry, isLive = true) {
        if (isStreamPaused && isLive) return;

        totalRequestsCount++;
        if (counterTotal) counterTotal.textContent = totalRequestsCount;

        if (entry.analyzed || entry.has_analysis) {
            analyzedRequestsCount++;
            if (counterAnalyzed) counterAnalyzed.textContent = analyzedRequestsCount;
        }

        // Almacenar localmente
        trafficItems.unshift(entry);
        if (trafficItems.length > MAX_ROWS) {
            trafficItems.pop();
        }

        // Verificar si el registro pasa los filtros activos
        const passesFilter = checkFilters(entry);

        if (!passesFilter) {
            updateFilteredCounter();
            return;
        }

        if (emptyRow && emptyRow.parentNode) {
            emptyRow.remove();
        }

        // Crear la fila principal y la fila de detalle expandible
        const rowId = `traffic-row-${entry.id || totalRequestsCount}`;
        const detailId = `detail-row-${entry.id || totalRequestsCount}`;

        const methodBadge = getMethodBadgeHtml(entry.method || 'GET');
        const statusBadge = getStatusBadgeHtml(entry.status_code || entry.status || 200);
        const timeStr = entry.timestamp 
            ? new Date(entry.timestamp).toLocaleTimeString('es-ES', { hour12: false }) 
            : new Date().toLocaleTimeString('es-ES', { hour12: false });

        const mainRow = document.createElement('tr');
        mainRow.id = rowId;
        mainRow.className = 'hover:bg-gray-700/50 cursor-pointer transition border-b border-gray-700/40 text-xs';
        mainRow.innerHTML = `
            <td class="px-4 py-3 text-center text-gray-500 font-mono">${entry.id || totalRequestsCount}</td>
            <td class="px-4 py-3">${methodBadge}</td>
            <td class="px-4 py-3 max-w-md truncate text-gray-200 font-mono" title="${entry.url || '/'}">${entry.url || '/'}</td>
            <td class="px-4 py-3 text-center">${statusBadge}</td>
            <td class="px-4 py-3 text-gray-400 truncate max-w-[120px]">${entry.content_type || entry.response_type || 'text/html'}</td>
            <td class="px-4 py-3 text-gray-400 font-mono">${timeStr}</td>
            <td class="px-4 py-3 text-right space-x-2" onclick="event.stopPropagation()">
                <button 
                    onclick="analyzeWithAI('${entry.id || totalRequestsCount}', this)"
                    class="btn-ai-analyze inline-flex items-center space-x-1 px-2.5 py-1 bg-purple-900/60 hover:bg-purple-600 text-purple-200 hover:text-white border border-purple-700 rounded text-[11px] transition"
                >
                    <span>🤖</span>
                    <span>Analizar</span>
                </button>
            </td>
        `;

        // Fila expandible con detalle completo (Request & Response)
        const detailRow = document.createElement('tr');
        detailRow.id = detailId;
        detailRow.className = 'hidden bg-gray-950/90 border-b border-gray-700/60';
        detailRow.innerHTML = `
            <td colspan="7" class="p-4 space-y-4">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-[11px]">
                    <!-- Solicitud (Request) -->
                    <div class="bg-gray-900 border border-gray-800 rounded-lg p-3">
                        <h4 class="text-xs font-bold text-cyan-400 mb-2 flex items-center space-x-1">
                            <span>📤</span>
                            <span>Petición HTTP (Request)</span>
                        </h4>
                        <div class="text-gray-400 mb-2 font-bold">${entry.method || 'GET'} ${entry.url || '/'}</div>
                        <div class="text-gray-400 mb-1 text-[10px] uppercase font-semibold">Cabeceras:</div>
                        <pre class="bg-gray-950 p-2 rounded text-gray-300 max-h-32 overflow-y-auto whitespace-pre-wrap">${formatHeaders(entry.request_headers || entry.headers)}</pre>
                        ${entry.request_body || entry.body ? `
                            <div class="text-gray-400 mt-2 mb-1 text-[10px] uppercase font-semibold">Cuerpo (Body):</div>
                            <pre class="bg-gray-950 p-2 rounded text-emerald-300 max-h-32 overflow-y-auto whitespace-pre-wrap">${formatBody(entry.request_body || entry.body)}</pre>
                        ` : ''}
                    </div>

                    <!-- Respuesta (Response) -->
                    <div class="bg-gray-900 border border-gray-800 rounded-lg p-3">
                        <h4 class="text-xs font-bold text-emerald-400 mb-2 flex items-center space-x-1">
                            <span>📥</span>
                            <span>Respuesta HTTP (Response)</span>
                        </h4>
                        <div class="text-gray-400 mb-2 font-bold">Código: ${entry.status_code || entry.status || 200}</div>
                        <div class="text-gray-400 mb-1 text-[10px] uppercase font-semibold">Cabeceras:</div>
                        <pre class="bg-gray-950 p-2 rounded text-gray-300 max-h-32 overflow-y-auto whitespace-pre-wrap">${formatHeaders(entry.response_headers)}</pre>
                        ${entry.response_body ? `
                            <div class="text-gray-400 mt-2 mb-1 text-[10px] uppercase font-semibold">Cuerpo (Body):</div>
                            <pre class="bg-gray-950 p-2 rounded text-gray-300 max-h-32 overflow-y-auto whitespace-pre-wrap">${formatBody(entry.response_body)}</pre>
                        ` : ''}
                    </div>
                </div>
            </td>
        `;

        // Alternar expansión al hacer clic en la fila principal
        mainRow.addEventListener('click', () => {
            detailRow.classList.toggle('hidden');
        });

        // Insertar al inicio de la tabla (las más recientes arriba)
        if (trafficTableBody.firstChild) {
            trafficTableBody.insertBefore(detailRow, trafficTableBody.firstChild);
            trafficTableBody.insertBefore(mainRow, detailRow);
        } else {
            trafficTableBody.appendChild(mainRow);
            trafficTableBody.appendChild(detailRow);
        }

        // Truncar elementos sobrantes en el DOM
        while (trafficTableBody.children.length > MAX_ROWS * 2) {
            trafficTableBody.removeChild(trafficTableBody.lastChild);
        }

        // Auto-scroll si está habilitado
        if (toggleAutoscroll && toggleAutoscroll.checked && tableContainer) {
            tableContainer.scrollTop = 0;
        }

        updateFilteredCounter();
    }

    // ========================================================
    // FORMATO DE BADGES Y UTILIDADES
    // ========================================================
    function getMethodBadgeHtml(method) {
        const m = (method || 'GET').toUpperCase();
        switch (m) {
            case 'GET':
                return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">GET</span>';
            case 'POST':
                return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800 font-mono">POST</span>';
            case 'PUT':
                return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">PUT</span>';
            case 'DELETE':
                return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800 font-mono">DELETE</span>';
            case 'PATCH':
                return '<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-400 border border-purple-800 font-mono">PATCH</span>';
            default:
                return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-gray-800 text-gray-300 border border-gray-700 font-mono">${m}</span>`;
        }
    }

    function getStatusBadgeHtml(code) {
        const c = parseInt(code, 10) || 200;
        if (c >= 200 && c < 300) {
            return `<span class="text-emerald-400 font-bold font-mono">${c}</span>`;
        } else if (c >= 300 && c < 400) {
            return `<span class="text-cyan-400 font-bold font-mono">${c}</span>`;
        } else if (c >= 400 && c < 500) {
            return `<span class="text-amber-400 font-bold font-mono">${c}</span>`;
        } else {
            return `<span class="text-rose-400 font-bold font-mono">${c}</span>`;
        }
    }

    function formatHeaders(headers) {
        if (!headers) return 'Ninguna cabecera registrada.';
        if (typeof headers === 'string') return headers;
        if (typeof headers === 'object') {
            return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
        }
        return JSON.stringify(headers, null, 2);
    }

    function formatBody(body) {
        if (!body) return 'Cuerpo vacío.';
        if (typeof body === 'object') {
            return JSON.stringify(body, null, 2);
        }
        return body;
    }

    // ========================================================
    // FILTRADO DINÁMICO
    // ========================================================
    function checkFilters(entry) {
        const selectedTarget = targetFilter.value;
        const selectedMethod = methodFilter.value;
        const query = searchInput.value.toLowerCase().trim();

        if (selectedTarget && String(entry.target_id) !== selectedTarget) {
            return false;
        }

        if (selectedMethod && (entry.method || 'GET').toUpperCase() !== selectedMethod) {
            return false;
        }

        if (query) {
            const urlMatch = (entry.url || '').toLowerCase().includes(query);
            const methodMatch = (entry.method || '').toLowerCase().includes(query);
            if (!urlMatch && !methodMatch) return false;
        }

        return true;
    }

    function applyAllFilters() {
        trafficTableBody.innerHTML = '';
        const visibleItems = trafficItems.filter(checkFilters);

        if (visibleItems.length === 0) {
            trafficTableBody.innerHTML = `
                <tr>
                    <td colspan="7" class="px-6 py-12 text-center text-gray-500 font-mono">
                        No hay solicitudes que coincidan con los filtros aplicados.
                    </td>
                </tr>
            `;
        } else {
            visibleItems.forEach(item => processNewTrafficEntry(item, false));
        }

        updateFilteredCounter();
    }

    function updateFilteredCounter() {
        if (!counterFiltered) return;
        const filteredCount = trafficItems.filter(item => !checkFilters(item)).length;
        counterFiltered.textContent = filteredCount;
    }

    [targetFilter, methodFilter].forEach(el => el.addEventListener('change', applyAllFilters));
    searchInput.addEventListener('input', applyAllFilters);

    // ========================================================
    // ANALIZAR CON INTELIGENCIA ARTIFICIAL (IA)
    // ========================================================
    window.analyzeWithAI = async function(entryId, btnElement) {
        const originalText = btnElement.innerHTML;
        btnElement.disabled = true;
        btnElement.innerHTML = '<span>⏳</span><span>Analizando...</span>';

        try {
            const res = await fetch(`/api/analysis/analyze/${entryId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });

            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || 'Error al procesar solicitud con IA');
            }

            btnElement.innerHTML = '<span>✅</span><span>Analizado</span>';
            btnElement.className = 'inline-flex items-center space-x-1 px-2.5 py-1 bg-emerald-900/60 text-emerald-300 border border-emerald-700 rounded text-[11px]';
            
            analyzedRequestsCount++;
            if (counterAnalyzed) counterAnalyzed.textContent = analyzedRequestsCount;
        } catch (error) {
            console.error('[Traffic] Error al analizar con IA:', error);
            btnElement.disabled = false;
            btnElement.innerHTML = '<span>⚠️</span><span>Reintentar</span>';
            alert(`No se pudo completar el análisis de IA: ${error.message}`);
        }
    };

    // ========================================================
    // PAUSAR / REANUDAR Y LIMPIAR
    // ========================================================
    if (btnToggleStream) {
        btnToggleStream.addEventListener('click', () => {
            isStreamPaused = !isStreamPaused;
            if (isStreamPaused) {
                streamIcon.textContent = '▶️';
                streamText.textContent = 'Reanudar';
                btnToggleStream.classList.add('bg-yellow-800', 'hover:bg-yellow-700');
            } else {
                streamIcon.textContent = '⏸️';
                streamText.textContent = 'Pausar';
                btnToggleStream.classList.remove('bg-yellow-800', 'hover:bg-yellow-700');
            }
        });
    }

    if (btnClearTraffic) {
        btnClearTraffic.addEventListener('click', () => {
            trafficItems = [];
            totalRequestsCount = 0;
            analyzedRequestsCount = 0;
            if (counterTotal) counterTotal.textContent = '0';
            if (counterFiltered) counterFiltered.textContent = '0';
            if (counterAnalyzed) counterAnalyzed.textContent = '0';

            trafficTableBody.innerHTML = `
                <tr id="empty-traffic-row">
                    <td colspan="7" class="px-6 py-16 text-center text-gray-500">
                        <div class="flex flex-col items-center justify-center space-y-3">
                            <span class="text-3xl">📡</span>
                            <p class="text-sm font-sans text-gray-400">Tabla de tráfico vaciada.</p>
                        </div>
                    </td>
                </tr>
            `;
        });
    }

    // ========================================================
    // ESCUCHA DEL WEBSOCKET PARA TRÁFICO EN VIVO
    // ========================================================
    window.addEventListener('ws:message', (event) => {
        const data = event.detail;
        if (!data) return;

        // Detectar evento de nuevo paquete de tráfico capturado
        if (data.type === 'new_traffic' || data.event === 'traffic' || (data.method && data.url)) {
            processNewTrafficEntry(data.payload || data, true);
        }
    });

    // Iniciar
    loadTargetsFilter();
    loadInitialTraffic();
});
