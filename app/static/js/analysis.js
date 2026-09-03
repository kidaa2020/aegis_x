/**
 * @file analysis.js
 * @description Gestión de la vista de Análisis IA y auditorías heurísticas OWASP.
 * Consulta hallazgos por objetivo, actualiza métricas de consumo de tokens y
 * caché, y renderiza tarjetas de vulnerabilidad expandibles con guías de remediación.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Referencias al DOM
    const targetFilter = document.getElementById('analysis-target-filter');
    const riskFilter = document.getElementById('analysis-risk-filter');
    const btnRefresh = document.getElementById('btn-refresh-analysis');
    const cardsContainer = document.getElementById('analysis-cards-container');
    const emptyState = document.getElementById('analysis-empty-state');

    // Elementos de Estadísticas
    const statTotal = document.getElementById('stat-total-analyses');
    const statCache = document.getElementById('stat-cache-hit-rate');
    const statTokens = document.getElementById('stat-tokens-used');
    const statHigh = document.getElementById('stat-high-risk');
    const statMedium = document.getElementById('stat-medium-risk');
    const statLow = document.getElementById('stat-low-risk');

    let allAnalyses = [];

    // ========================================================
    // CARGA DE OBJETIVOS PARA FILTRADO
    // ========================================================
    async function loadTargets() {
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

            const urlParams = new URLSearchParams(window.location.search);
            const paramTarget = urlParams.get('target_id');
            if (paramTarget) {
                targetFilter.value = paramTarget;
            }
        } catch (e) {
            console.error('[Analysis] Error al cargar lista de objetivos:', e);
        }
    }

    // ========================================================
    // CONSULTA DE ESTADÍSTICAS Y RESULTADOS DE AUDITORÍA
    // ========================================================
    async function fetchStats() {
        try {
            const res = await fetch('/api/analysis/stats');
            if (!res.ok) return;
            const stats = await res.json();

            if (statTotal) statTotal.textContent = stats.total_analyses ?? stats.total ?? allAnalyses.length;
            if (statCache) statCache.textContent = `${stats.cache_hit_rate ?? stats.cache_rate ?? 0}%`;
            if (statTokens) statTokens.textContent = Number(stats.tokens_used ?? stats.tokens ?? 0).toLocaleString();
            if (statHigh) statHigh.textContent = stats.high_risk_count ?? stats.high_risk ?? 0;
            if (statMedium) statMedium.textContent = stats.medium_risk_count ?? stats.medium_risk ?? 0;
            if (statLow) statLow.textContent = stats.low_risk_count ?? stats.low_risk ?? 0;
        } catch (e) {
            console.warn('[Analysis] No se pudieron obtener estadísticas globales del backend:', e);
        }
    }

    async function fetchAnalyses() {
        const selectedTarget = targetFilter.value;
        const endpoint = selectedTarget 
            ? `/api/analysis/results/${selectedTarget}` 
            : '/api/analysis';

        try {
            const res = await fetch(endpoint);
            if (!res.ok) throw new Error(`Error en API (${res.status})`);
            const data = await res.json();
            
            allAnalyses = Array.isArray(data) ? data : (data.results || data.items || []);
            renderAnalyses(allAnalyses);
            fetchStats();
        } catch (err) {
            console.error('[Analysis] Error al obtener análisis:', err);
            cardsContainer.innerHTML = `
                <div class="bg-gray-800 border border-red-900/50 rounded-xl p-8 text-center text-red-400 font-mono text-xs">
                    ⚠️ Error al consultar los análisis de seguridad. Verifique el backend.
                </div>
            `;
        }
    }

    // ========================================================
    // RENDERIZADO DE TARJETAS EXPANDIBLES
    // ========================================================
    function renderAnalyses(items) {
        const selectedRisk = riskFilter.value;
        const filtered = items.filter(item => {
            if (!selectedRisk) return true;
            const itemRisk = (item.risk_level || item.severity || 'INFO').toUpperCase();
            return itemRisk === selectedRisk;
        });

        if (filtered.length === 0) {
            cardsContainer.innerHTML = '';
            if (emptyState) {
                cardsContainer.appendChild(emptyState);
            } else {
                cardsContainer.innerHTML = `
                    <div class="bg-gray-800 border border-gray-700 rounded-xl p-12 text-center text-gray-500">
                        <span class="text-3xl block mb-2">🔍</span>
                        <p class="text-gray-400">No se encontraron análisis que coincidan con los filtros.</p>
                    </div>
                `;
            }
            return;
        }

        cardsContainer.innerHTML = filtered.map((analysis, index) => {
            const cardId = `analysis-card-${analysis.id || index}`;
            const detailsId = `analysis-details-${analysis.id || index}`;
            const risk = (analysis.risk_level || analysis.severity || 'INFO').toUpperCase();
            const riskBadge = getRiskBadgeHtml(risk);
            const methodBadge = getMethodBadgeHtml(analysis.method || analysis.traffic_entry?.method || 'GET');
            const url = analysis.url || analysis.traffic_entry?.url || 'https://objetivo/api/endpoint';
            const timestamp = analysis.created_at ? new Date(analysis.created_at).toLocaleString('es-ES') : 'Reciente';

            // Parámetros detectados
            const params = analysis.parameters || analysis.detected_parameters || [];
            // Clasificación OWASP
            const owaspCategories = analysis.owasp_categories || analysis.vulnerabilities || [
                { category: analysis.owasp_category || 'A03:2021-Injection', confidence: analysis.confidence || '92%', description: analysis.summary || 'Posible inyección o validación deficiente de entrada.' }
            ];
            // Metodología de Verificación
            const verificationSteps = analysis.verification_steps || analysis.testing_methodology || [
                'Enviar cadenas de prueba con comillas simples y dobles para evaluar control de errores.',
                'Comprobar la respuesta HTTP frente a discrepancias en el tiempo de procesamiento (Time-based).',
                'Verificar si los encabezados de respuesta neutralizan la ejecución arbitraria (CSP, X-Content-Type-Options).'
            ];
            // Remediación
            const remediationSteps = analysis.remediation || analysis.defensive_recommendations || [
                'Implementar consultas parametrizadas y uso estricto de ORM con binding de tipos.',
                'Aplicar validación exhaustiva de esquemas mediante listas blancas para todos los parámetros de entrada.',
                'Codificar las salidas en el contexto adecuado antes de incrustarlas en la respuesta HTML/JSON.'
            ];

            return `
                <div class="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden shadow-lg hover:border-gray-600 transition duration-150">
                    <!-- Cabecera de la Tarjeta (Clic para desplegar) -->
                    <button 
                        type="button"
                        onclick="toggleAnalysisCard('${detailsId}', '${cardId}-arrow')"
                        class="w-full px-6 py-4 flex flex-col md:flex-row md:items-center justify-between gap-4 text-left bg-gray-850 hover:bg-gray-800/80 transition"
                    >
                        <div class="flex items-center space-x-3 overflow-hidden flex-1">
                            ${methodBadge}
                            <span class="font-mono text-sm text-gray-200 truncate font-semibold">${url}</span>
                        </div>

                        <div class="flex items-center space-x-4 flex-shrink-0">
                            ${riskBadge}
                            <span class="text-xs text-gray-500 font-mono hidden sm:inline">${timestamp}</span>
                            <span id="${cardId}-arrow" class="text-gray-400 transform transition-transform duration-200">▼</span>
                        </div>
                    </button>

                    <!-- Detalle Expandido -->
                    <div id="${detailsId}" class="hidden p-6 border-t border-gray-700 bg-gray-900 space-y-6">
                        
                        <!-- 1. Parámetros Detectados -->
                        <div>
                            <h4 class="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-3 flex items-center space-x-1.5 font-mono">
                                <span>📋</span>
                                <span>Parámetros Detectados</span>
                            </h4>
                            ${params.length > 0 ? `
                                <div class="overflow-x-auto border border-gray-800 rounded-lg">
                                    <table class="w-full text-left text-xs text-gray-300 font-mono">
                                        <thead class="bg-gray-950 text-gray-400 uppercase tracking-wider border-b border-gray-800">
                                            <tr>
                                                <th class="px-4 py-2.5">Nombre del Parámetro</th>
                                                <th class="px-4 py-2.5">Ubicación</th>
                                                <th class="px-4 py-2.5">Tipo de Riesgo Identificado</th>
                                            </tr>
                                        </thead>
                                        <tbody class="divide-y divide-gray-800 bg-gray-900/60">
                                            ${params.map(p => `
                                                <tr>
                                                    <td class="px-4 py-2 text-cyan-300 font-bold">${p.name || p}</td>
                                                    <td class="px-4 py-2 text-gray-400">${p.location || 'Query String / Body'}</td>
                                                    <td class="px-4 py-2 text-amber-300">${p.risk_type || 'Posible vector de entrada dinámico'}</td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                </div>
                            ` : '<p class="text-xs text-gray-500 font-mono">No se desglosaron parámetros individuales específicos.</p>'}
                        </div>

                        <!-- 2. Clasificación de Riesgo OWASP -->
                        <div>
                            <h4 class="text-xs font-bold uppercase tracking-wider text-purple-400 mb-3 flex items-center space-x-1.5 font-mono">
                                <span>🛡️</span>
                                <span>Clasificación de Riesgo & Categoría OWASP</span>
                            </h4>
                            <div class="space-y-3">
                                ${owaspCategories.map(cat => `
                                    <div class="bg-gray-950 p-4 rounded-lg border border-gray-800">
                                        <div class="flex items-center justify-between mb-1.5">
                                            <span class="font-bold text-white text-sm">${cat.category || 'Vulnerabilidad OWASP'}</span>
                                            <span class="px-2 py-0.5 text-[10px] font-mono rounded bg-purple-950 text-purple-300 border border-purple-800">
                                                Confianza: ${cat.confidence || 'Alta'}
                                            </span>
                                        </div>
                                        <p class="text-xs text-gray-400">${cat.description || 'Evaluación heurística basada en patrones de parámetros y respuestas.'}</p>
                                    </div>
                                `).join('')}
                            </div>
                        </div>

                        <!-- 3. Metodología de Verificación -->
                        <div>
                            <h4 class="text-xs font-bold uppercase tracking-wider text-amber-400 mb-2 flex items-center space-x-1.5 font-mono">
                                <span>🧪</span>
                                <span>Metodología de Verificación (Pruebas Sugeridas)</span>
                            </h4>
                            <ul class="list-disc list-inside space-y-1.5 text-xs text-gray-300 bg-gray-950/60 p-4 rounded-lg border border-gray-800 font-mono">
                                ${(Array.isArray(verificationSteps) ? verificationSteps : [verificationSteps]).map(step => `
                                    <li>${step}</li>
                                `).join('')}
                            </ul>
                        </div>

                        <!-- 4. Remediación -->
                        <div>
                            <h4 class="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2 flex items-center space-x-1.5 font-mono">
                                <span>🔒</span>
                                <span>Remediación & Medidas Defensivas</span>
                            </h4>
                            <ul class="list-disc list-inside space-y-1.5 text-xs text-gray-300 bg-emerald-950/20 p-4 rounded-lg border border-emerald-900/40">
                                ${(Array.isArray(remediationSteps) ? remediationSteps : [remediationSteps]).map(rem => `
                                    <li class="text-emerald-300">${rem}</li>
                                `).join('')}
                            </ul>
                        </div>

                    </div>
                </div>
            `;
        }).join('');
    }

    // ========================================================
    // HELPERS DE BADGES DE RIESGO Y MÉTODOS
    // ========================================================
    function getRiskBadgeHtml(risk) {
        switch (risk) {
            case 'CRITICO':
            case 'CRITICAL':
                return '<span class="px-2.5 py-1 text-[11px] font-bold rounded-full bg-red-950 text-red-300 border border-red-700 shadow-sm shadow-red-900/40 font-mono">🔥 CRÍTICO</span>';
            case 'ALTO':
            case 'HIGH':
                return '<span class="px-2.5 py-1 text-[11px] font-bold rounded-full bg-red-950/80 text-red-400 border border-red-800 font-mono">🔴 ALTO</span>';
            case 'MEDIO':
            case 'MEDIUM':
                return '<span class="px-2.5 py-1 text-[11px] font-bold rounded-full bg-amber-950/80 text-amber-400 border border-amber-800 font-mono">🟡 MEDIO</span>';
            case 'BAJO':
            case 'LOW':
                return '<span class="px-2.5 py-1 text-[11px] font-bold rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-800 font-mono">🟢 BAJO</span>';
            default:
                return '<span class="px-2.5 py-1 text-[11px] font-bold rounded-full bg-blue-950/80 text-blue-400 border border-blue-800 font-mono">🔵 INFO</span>';
        }
    }

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
            default:
                return `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-gray-800 text-gray-300 border border-gray-700 font-mono">${m}</span>`;
        }
    }

    // Alternar colapsable
    window.toggleAnalysisCard = function(detailsId, arrowId) {
        const details = document.getElementById(detailsId);
        const arrow = document.getElementById(arrowId);
        if (!details) return;

        if (details.classList.contains('hidden')) {
            details.classList.remove('hidden');
            if (arrow) arrow.classList.add('rotate-180');
        } else {
            details.classList.add('hidden');
            if (arrow) arrow.classList.remove('rotate-180');
        }
    };

    // Event listeners
    if (targetFilter) targetFilter.addEventListener('change', fetchAnalyses);
    if (riskFilter) riskFilter.addEventListener('change', () => renderAnalyses(allAnalyses));
    if (btnRefresh) btnRefresh.addEventListener('click', fetchAnalyses);

    // Escuchar WebSocket para actualizar en vivo cuando se complete un análisis
    window.addEventListener('ws:message', (event) => {
        const data = event.detail;
        if (data && (data.type === 'analysis_completed' || data.event === 'analysis')) {
            console.log('[Analysis] Nuevo análisis recibido por WebSocket:', data);
            fetchAnalyses();
        }
    });

    // Iniciar carga
    loadTargets();
    fetchAnalyses();
});
