/**
 * @file recon.js
 * @description Manejo de la lógica de reconocimiento y auditoría de superficie de ataque:
 * selección de objetivos, ejecución de escaneos (DNS, puertos, tecnologías, JS)
 * y visualización reactiva con componentes interactivos.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Referencias del DOM
    const targetSelect = document.getElementById('target-select');
    const scanStatusBanner = document.getElementById('recon-scan-status');
    const scanStatusMsg = document.getElementById('scan-status-message');

    // Botones de Escaneo
    const btnSubdomains = document.getElementById('btn-scan-subdomains');
    const btnPorts = document.getElementById('btn-scan-ports');
    const btnTech = document.getElementById('btn-scan-tech');
    const btnJs = document.getElementById('btn-scan-js');

    // Contenedores de Pestañas
    const tabButtons = document.querySelectorAll('.tab-button');
    const tabContents = document.querySelectorAll('.tab-content');

    // Badges de Conteo
    const badgeSubdomains = document.getElementById('badge-subdomains-count');
    const badgePorts = document.getElementById('badge-ports-count');
    const badgeTech = document.getElementById('badge-tech-count');
    const badgeJs = document.getElementById('badge-js-count');

    // Tablas y Contenedores de Datos
    const subdomainsBody = document.getElementById('subdomains-table-body');
    const portsBody = document.getElementById('ports-table-body');
    const techGrid = document.getElementById('technologies-grid');
    const jsContainer = document.getElementById('jsfiles-container');

    let currentTargetId = null;

    // ========================================================
    // GESTIÓN DE PESTAÑAS (TAB SWITCHING)
    // ========================================================
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');

            // Resetear estilos activos de botones
            tabButtons.forEach(btn => {
                btn.className = 'tab-button px-5 py-3.5 text-sm font-medium border-b-2 border-transparent text-gray-400 hover:text-gray-200 flex items-center space-x-2';
            });

            // Activar botón seleccionado
            button.className = 'tab-button px-5 py-3.5 text-sm font-medium border-b-2 border-cyan-400 text-cyan-400 flex items-center space-x-2';

            // Ocultar todas las secciones y mostrar la activa
            tabContents.forEach(content => {
                content.classList.add('hidden');
                content.classList.remove('block');
            });

            const activeContent = document.getElementById(`tab-${targetTab}`);
            if (activeContent) {
                activeContent.classList.remove('hidden');
                activeContent.classList.add('block');
            }
        });
    });

    // ========================================================
    // CARGA DE OBJETIVOS Y SELECCIÓN INICIAL
    // ========================================================
    async function loadTargets() {
        try {
            const res = await fetch('/api/targets');
            if (!res.ok) throw new Error('Error al cargar objetivos');
            const targets = await res.json();

            targetSelect.innerHTML = '<option value="">-- Seleccione un objetivo para auditar --</option>';
            targets.forEach(t => {
                const opt = document.createElement('option');
                opt.value = t.id;
                opt.textContent = `${t.domain || t.name} (ID: ${t.id})`;
                targetSelect.appendChild(opt);
            });

            // Verificar si hay target_id en los parámetros de la URL
            const urlParams = new URLSearchParams(window.location.search);
            const paramTargetId = urlParams.get('target_id');

            if (paramTargetId) {
                targetSelect.value = paramTargetId;
                onTargetSelected(paramTargetId);
            }
        } catch (err) {
            console.error('[Recon] Error cargando lista de objetivos:', err);
        }
    }

    targetSelect.addEventListener('change', (e) => {
        const selectedId = e.target.value;
        onTargetSelected(selectedId);
    });

    function onTargetSelected(targetId) {
        currentTargetId = targetId;
        const hasTarget = !!targetId;

        // Habilitar / deshabilitar botones de escaneo
        [btnSubdomains, btnPorts, btnTech, btnJs].forEach(btn => {
            if (btn) btn.disabled = !hasTarget;
        });

        if (hasTarget) {
            // Actualizar URL sin recargar
            const newUrl = new URL(window.location);
            newUrl.searchParams.set('target_id', targetId);
            window.history.pushState({}, '', newUrl);

            // Cargar datos de reconocimiento existentes
            fetchReconResults(targetId);
        } else {
            resetUI();
        }
    }

    function resetUI() {
        badgeSubdomains.textContent = '0';
        badgePorts.textContent = '0';
        badgeTech.textContent = '0';
        badgeJs.textContent = '0';

        subdomainsBody.innerHTML = '<tr><td colspan="4" class="px-6 py-8 text-center text-gray-500">Seleccione un objetivo y ejecute "Enumerar Subdominios".</td></tr>';
        portsBody.innerHTML = '<tr><td colspan="4" class="px-6 py-8 text-center text-gray-500">Seleccione un objetivo y ejecute "Escanear Puertos".</td></tr>';
        techGrid.innerHTML = '<div class="col-span-full py-8 text-center text-gray-500 font-mono text-sm">Seleccione un objetivo y ejecute "Detectar Tecnologías".</div>';
        jsContainer.innerHTML = '<div class="py-8 text-center text-gray-500 font-mono text-sm">Seleccione un objetivo y ejecute "Analizar JS".</div>';
    }

    // ========================================================
    // CONSULTA Y RENDERIZADO DE RESULTADOS DE RECONOCIMIENTO
    // ========================================================
    async function fetchReconResults(targetId) {
        if (!targetId) return;

        try {
            // Consultar datos consolidados del objetivo o sub-rutas
            const [targetRes, subRes, portsRes, techRes, jsRes] = await Promise.allSettled([
                fetch(`/api/targets/${targetId}`).then(r => r.ok ? r.json() : null),
                fetch(`/api/recon/subdomains/${targetId}`).then(r => r.ok ? r.json() : []),
                fetch(`/api/recon/ports/${targetId}`).then(r => r.ok ? r.json() : []),
                fetch(`/api/recon/technologies/${targetId}`).then(r => r.ok ? r.json() : []),
                fetch(`/api/recon/js/${targetId}`).then(r => r.ok ? r.json() : [])
            ]);

            const targetData = targetRes.status === 'fulfilled' ? targetRes.value : null;
            const subdomains = (subRes.status === 'fulfilled' && subRes.value) ? subRes.value : (targetData?.subdomains || []);
            const ports = (portsRes.status === 'fulfilled' && portsRes.value) ? portsRes.value : (targetData?.ports || []);
            const tech = (techRes.status === 'fulfilled' && techRes.value) ? techRes.value : (targetData?.technologies || []);
            const jsFiles = (jsRes.status === 'fulfilled' && jsRes.value) ? jsRes.value : (targetData?.js_files || []);

            renderSubdomains(subdomains);
            renderPorts(ports);
            renderTechnologies(tech);
            renderJsFiles(jsFiles);
        } catch (err) {
            console.error('[Recon] Error cargando resultados consolidados:', err);
        }
    }

    // 1. Render Subdominios
    function renderSubdomains(subdomains) {
        badgeSubdomains.textContent = subdomains ? subdomains.length : 0;

        if (!subdomains || subdomains.length === 0) {
            subdomainsBody.innerHTML = '<tr><td colspan="4" class="px-6 py-6 text-center text-gray-500">No se han descubierto subdominios para este objetivo.</td></tr>';
            return;
        }

        subdomainsBody.innerHTML = subdomains.map(s => `
            <tr class="hover:bg-gray-700/40 transition">
                <td class="px-6 py-3 font-semibold text-emerald-400">
                    <a href="http://${s.subdomain || s.name || s}" target="_blank" rel="noopener noreferrer" class="hover:underline flex items-center space-x-1.5">
                        <span>🔗</span>
                        <span>${s.subdomain || s.name || s}</span>
                    </a>
                </td>
                <td class="px-6 py-3 text-gray-400 font-mono">${s.ip_address || s.ip || 'No resuelta'}</td>
                <td class="px-6 py-3 text-gray-500 text-[11px]">${s.created_at ? new Date(s.created_at).toLocaleString('es-ES') : 'Reciente'}</td>
                <td class="px-6 py-3 text-right">
                    <button class="text-xs px-2.5 py-1 bg-gray-700/80 hover:bg-cyan-600 text-cyan-200 hover:text-white rounded transition" onclick="copyToClipboard('${s.subdomain || s.name || s}')">
                        Copiar
                    </button>
                </td>
            </tr>
        `).join('');
    }

    // 2. Render Puertos
    function renderPorts(ports) {
        badgePorts.textContent = ports ? ports.length : 0;

        if (!ports || ports.length === 0) {
            portsBody.innerHTML = '<tr><td colspan="4" class="px-6 py-6 text-center text-gray-500">No hay puertos abiertos detectados.</td></tr>';
            return;
        }

        portsBody.innerHTML = ports.map(p => `
            <tr class="hover:bg-gray-700/40 transition">
                <td class="px-6 py-3 font-mono font-bold text-amber-400">${p.port || p.port_number}</td>
                <td class="px-6 py-3 uppercase text-xs text-gray-400 font-mono">${p.protocol || 'TCP'}</td>
                <td class="px-6 py-3 text-gray-300 font-semibold">${p.service || 'Desconocido'}</td>
                <td class="px-6 py-3 text-gray-400 text-xs font-mono">${p.banner || p.version || 'Sin banner registrado'}</td>
            </tr>
        `).join('');
    }

    // 3. Render Tecnologías
    function renderTechnologies(tech) {
        badgeTech.textContent = tech ? tech.length : 0;

        if (!tech || tech.length === 0) {
            techGrid.innerHTML = '<div class="col-span-full py-6 text-center text-gray-500 font-mono text-sm">No se detectaron tecnologías específicas en el fingerprinting.</div>';
            return;
        }

        techGrid.innerHTML = tech.map(t => `
            <div class="bg-gray-900/80 border border-gray-700/80 rounded-lg p-4 hover:border-purple-500/50 transition">
                <div class="flex items-start justify-between">
                    <div>
                        <h4 class="font-bold text-white text-sm">${t.name}</h4>
                        <span class="inline-block mt-1 px-2 py-0.5 text-[10px] font-mono rounded bg-purple-950 text-purple-300 border border-purple-800">
                            ${t.category || 'General'}
                        </span>
                    </div>
                    <span class="text-xl">⚙️</span>
                </div>
                ${t.version ? `<div class="mt-3 text-xs text-gray-400 font-mono">Versión: <span class="text-purple-400 font-bold">${t.version}</span></div>` : ''}
            </div>
        `).join('');
    }

    // 4. Render Archivos JS & Secretos (Colapsables)
    function renderJsFiles(jsFiles) {
        badgeJs.textContent = jsFiles ? jsFiles.length : 0;

        if (!jsFiles || jsFiles.length === 0) {
            jsContainer.innerHTML = '<div class="py-6 text-center text-gray-500 font-mono text-sm">No se han analizado archivos JavaScript aún.</div>';
            return;
        }

        jsContainer.innerHTML = jsFiles.map((file, idx) => {
            const endpoints = file.endpoints || [];
            const secrets = file.secrets || [];

            return `
                <div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden transition-all duration-200">
                    <button 
                        class="w-full px-5 py-3.5 flex items-center justify-between text-left bg-gray-850 hover:bg-gray-800 transition"
                        onclick="toggleCollapse('js-card-${idx}')"
                    >
                        <div class="flex items-center space-x-3 overflow-hidden">
                            <span class="text-lg">📜</span>
                            <span class="font-mono text-xs text-cyan-300 truncate max-w-xl">${file.url || file.filename || 'Script #' + idx}</span>
                        </div>
                        <div class="flex items-center space-x-3 text-xs">
                            <span class="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800 font-mono">
                                ${endpoints.length} endpoints
                            </span>
                            <span class="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-mono">
                                ${secrets.length} secretos
                            </span>
                            <span id="arrow-js-card-${idx}" class="text-gray-400 transform transition-transform duration-200">▼</span>
                        </div>
                    </button>

                    <div id="js-card-${idx}" class="hidden p-5 border-t border-gray-700/60 bg-gray-900 space-y-4">
                        <!-- Endpoints extraídos -->
                        <div>
                            <h5 class="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 font-mono">🔗 Endpoints Descubiertos</h5>
                            ${endpoints.length > 0 ? `
                                <div class="bg-gray-950 p-3 rounded border border-gray-800 space-y-1 font-mono text-xs max-h-40 overflow-y-auto">
                                    ${endpoints.map(ep => `<div class="text-emerald-400 hover:text-white cursor-pointer select-all">• ${ep}</div>`).join('')}
                                </div>
                            ` : '<p class="text-xs text-gray-500 font-mono">Ningún endpoint relevante identificado.</p>'}
                        </div>

                        <!-- Secretos / Tokens expuestos -->
                        <div>
                            <h5 class="text-xs font-semibold text-red-400 uppercase tracking-wider mb-2 font-mono">🔑 Posibles Secretos & Tokens</h5>
                            ${secrets.length > 0 ? `
                                <div class="bg-red-950/20 border border-red-900/50 p-3 rounded space-y-2 font-mono text-xs max-h-40 overflow-y-auto">
                                    ${secrets.map(sec => `
                                        <div class="p-2 bg-red-950/40 rounded border border-red-800/40">
                                            <div class="text-red-300 font-bold">${sec.type || 'Clave Secreta Detectada'}:</div>
                                            <div class="text-red-200 break-all select-all mt-0.5">${sec.value || sec.match || sec}</div>
                                        </div>
                                    `).join('')}
                                </div>
                            ` : '<p class="text-xs text-emerald-500 font-mono">✅ No se detectaron secretos o tokens evidentes.</p>'}
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }

    // ========================================================
    // DISPARO DE TAREAS DE ESCANEO (API CALLS)
    // ========================================================
    async function triggerScan(endpoint, buttonEl, taskName) {
        if (!currentTargetId) return;

        const spinner = buttonEl.querySelector('.spinner');
        const icon = buttonEl.querySelector('.icon');

        // Estado visual de carga
        buttonEl.disabled = true;
        if (spinner) spinner.classList.remove('hidden');
        if (icon) icon.classList.add('hidden');

        if (scanStatusBanner && scanStatusMsg) {
            scanStatusMsg.textContent = `Iniciando tarea: ${taskName}...`;
            scanStatusBanner.classList.remove('hidden');
        }

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_id: parseInt(currentTargetId, 10) })
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => ({}));
                throw new Error(errData.detail || `Error al ejecutar escaneo (${response.status})`);
            }

            if (scanStatusMsg) {
                scanStatusMsg.textContent = `Tarea de ${taskName} enviada al motor de escaneo.`;
            }

            // Recargar resultados después de lanzar
            setTimeout(() => {
                fetchReconResults(currentTargetId);
            }, 1500);
        } catch (err) {
            console.error(`[Recon] Error en ${taskName}:`, err);
            if (scanStatusMsg) {
                scanStatusMsg.textContent = `Error: ${err.message}`;
            }
        } finally {
            buttonEl.disabled = false;
            if (spinner) spinner.classList.add('hidden');
            if (icon) icon.classList.remove('hidden');
        }
    }

    // Asignar listeners a los 4 botones
    if (btnSubdomains) {
        btnSubdomains.addEventListener('click', () => triggerScan('/api/recon/subdomains', btnSubdomains, 'Enumeración de Subdominios'));
    }
    if (btnPorts) {
        btnPorts.addEventListener('click', () => triggerScan('/api/recon/ports', btnPorts, 'Escaneo de Puertos'));
    }
    if (btnTech) {
        btnTech.addEventListener('click', () => triggerScan('/api/recon/technologies', btnTech, 'Detección de Tecnologías'));
    }
    if (btnJs) {
        btnJs.addEventListener('click', () => triggerScan('/api/recon/js', btnJs, 'Análisis de Archivos JS'));
    }

    // ========================================================
    // FUNCIONES AUXILIARES GLOBALES
    // ========================================================
    window.toggleCollapse = function(cardId) {
        const el = document.getElementById(cardId);
        const arrow = document.getElementById(`arrow-${cardId}`);
        if (!el) return;

        if (el.classList.contains('hidden')) {
            el.classList.remove('hidden');
            if (arrow) arrow.classList.add('rotate-180');
        } else {
            el.classList.add('hidden');
            if (arrow) arrow.classList.remove('rotate-180');
        }
    };

    window.copyToClipboard = function(text) {
        navigator.clipboard.writeText(text).then(() => {
            console.log('[Recon] Copiado al portapapeles:', text);
        });
    };

    // Escuchar WebSocket para actualizar automáticamente resultados cuando termine una tarea
    window.addEventListener('ws:message', (event) => {
        const msg = event.detail;
        if (msg && currentTargetId && (msg.target_id == currentTargetId || !msg.target_id)) {
            console.log('[Recon] Notificación de escaneo vía WebSocket:', msg);
            fetchReconResults(currentTargetId);
        }
    });

    // Carga inicial de objetivos
    loadTargets();
});
