/**
 * @file dashboard.js
 * @description Gestión de la interfaz del Panel de Control (Dashboard),
 * incluyendo la consulta de objetivos, adición de nuevos dominios y actualización
 * reactiva de estadísticas de reconocimiento.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Referencias al DOM
    const addTargetForm = document.getElementById('add-target-form');
    const domainInput = document.getElementById('target-domain-input');
    const descInput = document.getElementById('target-desc-input');
    const btnAddTarget = document.getElementById('btn-add-target');
    const btnSpinner = document.getElementById('btn-spinner');
    const btnRefresh = document.getElementById('btn-refresh-targets');
    const targetsTableBody = document.getElementById('targets-table-body');
    const alertBox = document.getElementById('dashboard-alert');

    // Elementos de Estadísticas
    const statTargets = document.getElementById('stat-targets');
    const statSubdomains = document.getElementById('stat-subdomains');
    const statPorts = document.getElementById('stat-ports');
    const statTech = document.getElementById('stat-technologies');
    const statJs = document.getElementById('stat-js');
    const statTraffic = document.getElementById('stat-traffic');

    /**
     * Muestra una alerta visual temporal en el panel de control.
     * @param {string} message Mensaje a mostrar
     * @param {'success'|'error'|'info'} type Tipo de alerta
     */
    function showAlert(message, type = 'info') {
        if (!alertBox) return;

        alertBox.className = 'p-4 rounded-lg text-sm font-medium transition-all duration-300 block ';
        if (type === 'success') {
            alertBox.className += 'bg-emerald-950/80 border border-emerald-700 text-emerald-300';
        } else if (type === 'error') {
            alertBox.className += 'bg-red-950/80 border border-red-700 text-red-300';
        } else {
            alertBox.className += 'bg-cyan-950/80 border border-cyan-700 text-cyan-300';
        }

        alertBox.textContent = message;
        alertBox.classList.remove('hidden');

        setTimeout(() => {
            alertBox.classList.add('hidden');
        }, 5000);
    }

    /**
     * Consulta la API para obtener el listado de objetivos y sus métricas asociadas.
     */
    async function fetchTargets() {
        try {
            const response = await fetch('/api/targets');
            if (!response.ok) {
                throw new Error(`Error en el servidor: ${response.status}`);
            }

            const targets = await response.json();
            renderTargets(targets);
            calculateAndRenderStats(targets);
        } catch (error) {
            console.error('[Dashboard] Error al consultar objetivos:', error);
            if (targetsTableBody) {
                targetsTableBody.innerHTML = `
                    <tr>
                        <td colspan="6" class="px-6 py-6 text-center text-red-400 font-mono text-xs">
                            ⚠️ No se pudieron cargar los objetivos. Verifique la conexión con el backend.
                        </td>
                    </tr>
                `;
            }
        }
    }

    /**
     * Renderiza las filas de la tabla de objetivos recientes.
     * @param {Array<Object>} targets Lista de objetivos devueltos por el backend
     */
    function renderTargets(targets) {
        if (!targetsTableBody) return;

        if (!targets || targets.length === 0) {
            targetsTableBody.innerHTML = `
                <tr>
                    <td colspan="6" class="px-6 py-8 text-center text-gray-500 text-sm">
                        No hay objetivos registrados todavía. ¡Agregue uno arriba para comenzar!
                    </td>
                </tr>
            `;
            return;
        }

        targetsTableBody.innerHTML = targets.map(target => {
            const dateStr = target.created_at ? new Date(target.created_at).toLocaleString('es-ES') : 'Reciente';
            const statusBadge = target.status === 'completed' 
                ? '<span class="px-2 py-0.5 text-[11px] rounded bg-emerald-900/60 text-emerald-400 border border-emerald-700">COMPLETADO</span>'
                : target.status === 'scanning'
                ? '<span class="px-2 py-0.5 text-[11px] rounded bg-yellow-900/60 text-yellow-400 border border-yellow-700 animate-pulse">ESCANEANDO</span>'
                : '<span class="px-2 py-0.5 text-[11px] rounded bg-gray-700 text-gray-300">LISTO</span>';

            return `
                <tr class="hover:bg-gray-700/40 transition duration-150">
                    <td class="px-6 py-4 font-mono text-gray-400">#${target.id}</td>
                    <td class="px-6 py-4">
                        <div class="flex items-center space-x-2">
                            <span class="text-cyan-400 font-semibold">${target.domain || target.name || 'Sin nombre'}</span>
                            ${target.ip ? `<span class="text-xs text-gray-500">(${target.ip})</span>` : ''}
                        </div>
                    </td>
                    <td class="px-6 py-4 text-xs text-gray-400">${target.description || 'Sin descripción'}</td>
                    <td class="px-6 py-4 text-xs text-gray-400">${dateStr}</td>
                    <td class="px-6 py-4">${statusBadge}</td>
                    <td class="px-6 py-4 text-right space-x-2">
                        <a href="/recon?target_id=${target.id}" class="inline-flex items-center px-2.5 py-1.5 bg-gray-700 hover:bg-emerald-600 text-white rounded text-xs transition">
                            🔍 Recon
                        </a>
                        <a href="/traffic?target_id=${target.id}" class="inline-flex items-center px-2.5 py-1.5 bg-gray-700 hover:bg-cyan-600 text-white rounded text-xs transition">
                            📡 Tráfico
                        </a>
                        <button onclick="window.deleteTarget(${target.id})" class="inline-flex items-center px-2 py-1.5 bg-gray-700/50 hover:bg-red-700 text-gray-300 hover:text-white rounded text-xs transition" title="Eliminar objetivo">
                            🗑️
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
    }

    /**
     * Calcula y actualiza las métricas de las tarjetas resumen del Dashboard.
     * @param {Array<Object>} targets Lista de objetivos
     */
    function calculateAndRenderStats(targets) {
        if (!targets) return;

        let totalTargets = targets.length;
        let totalSubdomains = 0;
        let totalPorts = 0;
        let totalTech = 0;
        let totalJs = 0;
        let totalTraffic = 0;

        targets.forEach(t => {
            if (t.subdomains_count) totalSubdomains += t.subdomains_count;
            if (t.subdomains && Array.isArray(t.subdomains)) totalSubdomains += t.subdomains.length;

            if (t.ports_count) totalPorts += t.ports_count;
            if (t.ports && Array.isArray(t.ports)) totalPorts += t.ports.length;

            if (t.technologies_count) totalTech += t.technologies_count;
            if (t.technologies && Array.isArray(t.technologies)) totalTech += t.technologies.length;

            if (t.js_files_count) totalJs += t.js_files_count;
            if (t.js_files && Array.isArray(t.js_files)) totalJs += t.js_files.length;

            if (t.traffic_count) totalTraffic += t.traffic_count;
        });

        if (statTargets) statTargets.textContent = totalTargets;
        if (statSubdomains) statSubdomains.textContent = totalSubdomains;
        if (statPorts) statPorts.textContent = totalPorts;
        if (statTech) statTech.textContent = totalTech;
        if (statJs) statJs.textContent = totalJs;
        if (statTraffic) statTraffic.textContent = totalTraffic;
    }

    /**
     * Maneja el envío del formulario para agregar un nuevo objetivo de auditoría.
     */
    if (addTargetForm) {
        addTargetForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const domain = domainInput.value.trim();
            const description = descInput.value.trim();

            if (!domain) {
                showAlert('Por favor ingrese un dominio o dirección IP válida.', 'error');
                return;
            }

            // Bloquear botón y mostrar spinner de carga
            btnAddTarget.disabled = true;
            if (btnSpinner) btnSpinner.classList.remove('hidden');

            try {
                const response = await fetch('/api/targets', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        domain: domain,
                        description: description
                    })
                });

                if (!response.ok) {
                    const errData = await response.json().catch(() => ({}));
                    throw new Error(errData.detail || `Error al crear objetivo (${response.status})`);
                }

                showAlert(`Objetivo "${domain}" registrado exitosamente.`, 'success');
                domainInput.value = '';
                descInput.value = '';
                fetchTargets();
            } catch (error) {
                console.error('[Dashboard] Error al crear objetivo:', error);
                showAlert(error.message || 'Error inesperado al crear el objetivo.', 'error');
            } finally {
                btnAddTarget.disabled = false;
                if (btnSpinner) btnSpinner.classList.add('hidden');
            }
        });
    }

    /**
     * Elimina un objetivo mediante llamada DELETE a la API.
     * @param {number|string} targetId ID del objetivo
     */
    window.deleteTarget = async function(targetId) {
        if (!confirm(`¿Está seguro de eliminar el objetivo #${targetId} y todos sus datos de reconocimiento asociados?`)) {
            return;
        }

        try {
            const response = await fetch(`/api/targets/${targetId}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                throw new Error(`Error al eliminar: ${response.status}`);
            }

            showAlert(`Objetivo #${targetId} eliminado correctamente.`, 'info');
            fetchTargets();
        } catch (error) {
            console.error('[Dashboard] Error al eliminar objetivo:', error);
            showAlert('No se pudo eliminar el objetivo.', 'error');
        }
    };

    // Botón refrescar
    if (btnRefresh) {
        btnRefresh.addEventListener('click', fetchTargets);
    }

    // Escucha de eventos WebSocket para actualizaciones en vivo
    window.addEventListener('ws:message', (event) => {
        const data = event.detail;
        if (data && (data.type === 'target_updated' || data.type === 'scan_completed' || data.type === 'new_target')) {
            console.log('[Dashboard] Evento de actualización recibido vía WS:', data);
            fetchTargets();
        }
    });

    // Carga inicial de datos
    fetchTargets();
});
