// IAM: ciclo de vida de contas, auditoria de privilégios e contas administrativas.

// --- Painel: Ciclo de Vida de Contas (tab-lifecycle) ---

// event_id do Windows -> rótulo em português para a coluna "Tipo".
const lifecycleEventLabels = {
  4720: "Criada",
  4722: "Ativada",
  4725: "Desativada",
  4726: "Eliminada",
  4740: "Bloqueada",
};

function lifecycleEventTypeLabel(eventId) {
  return lifecycleEventLabels[eventId] || String(eventId);
}

// Guarda o último resultado do fetch para os filtros (tipo/utilizador)
// filtrarem client-side sem precisar de um novo pedido ao backend.
let lastLifecycleEvents = [];

function renderLifecycleEventsTable(events) {
  const tbody = document.getElementById("lifecycle-events-body");
  tbody.innerHTML = "";

  if (!events || events.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty-state">Sem eventos neste período</td></tr>';
    return;
  }

  events.forEach((ev) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td class="mono">${escapeHtml(formatTimestamp(ev.timestamp))}</td>
      <td>${escapeHtml(lifecycleEventTypeLabel(ev.event_id))}</td>
      <td>${escapeHtml(ev.target_user)}</td>
      <td>${escapeHtml(ev.executed_by)}</td>
      <td>${escapeHtml(ev.agent_name)}</td>
    `;
    tbody.appendChild(tr);
  });
}

function applyLifecycleFilters() {
  const typeFilter = document.getElementById("lifecycle-type-filter").value;
  const userFilter = document.getElementById("lifecycle-user-filter").value.trim().toLowerCase();

  let filtered = lastLifecycleEvents;
  if (typeFilter) {
    filtered = filtered.filter((ev) => String(ev.event_id) === typeFilter);
  }
  if (userFilter) {
    filtered = filtered.filter((ev) => (ev.target_user || "").toLowerCase().includes(userFilter));
  }
  renderLifecycleEventsTable(filtered);
}

function renderLifecycleTimelineChart(timeline) {
  const data = timeline || [];
  renderChart("chart-lifecycle-timeline", {
    type: "line",
    data: {
      labels: data.map((t) => t.date),
      datasets: [
        { label: "Criadas", data: data.map((t) => t.created), borderColor: chartColor("--cat-1"), backgroundColor: chartColor("--cat-1", 0.08), fill: false, tension: 0.25 },
        { label: "Ativadas", data: data.map((t) => t.activated), borderColor: chartColor("--cat-3"), backgroundColor: chartColor("--cat-3", 0.08), fill: false, tension: 0.25 },
        { label: "Desativadas", data: data.map((t) => t.disabled), borderColor: chartColor("--cat-4"), backgroundColor: chartColor("--cat-4", 0.08), fill: false, tension: 0.25 },
        { label: "Eliminadas", data: data.map((t) => t.deleted), borderColor: chartColor("--cat-8"), backgroundColor: chartColor("--cat-8", 0.08), fill: false, tension: 0.25 },
        { label: "Bloqueadas", data: data.map((t) => t.locked), borderColor: chartColor("--cat-7"), backgroundColor: chartColor("--cat-7", 0.08), fill: false, tension: 0.25 },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

async function loadLifecyclePanel(days) {
  try {
    const data = await fetchJSON(`/api/lifecycle?days=${days}`);
    renderPanelError("#lifecycle-panel", null);

    const counts = data.counts || {};
    document.getElementById("kpi-lifecycle-created").textContent = counts.created ?? 0;
    document.getElementById("kpi-lifecycle-activated").textContent = counts.activated ?? 0;
    document.getElementById("kpi-lifecycle-disabled").textContent = counts.disabled ?? 0;
    document.getElementById("kpi-lifecycle-deleted").textContent = counts.deleted ?? 0;
    document.getElementById("kpi-lifecycle-locked").textContent = counts.locked ?? 0;

    renderLifecycleTimelineChart(data.timeline || []);

    lastLifecycleEvents = data.events || [];
    applyLifecycleFilters();

    renderDetections("lifecycle-detections", data.detections || []);
  } catch (err) {
    console.error(err);
    renderPanelError("#lifecycle-panel", panelErrorText(err, "Erro ao carregar o painel de ciclo de vida."));
  }
}

document.getElementById("lifecycle-type-filter").addEventListener("change", applyLifecycleFilters);
document.getElementById("lifecycle-user-filter").addEventListener("input", applyLifecycleFilters);

// --- Painel: Auditoria de Privilégios (tab-privileges) ---

function renderPrivilegesDeviationsTable(deviations) {
  const tbody = document.getElementById("privileges-deviations-body");
  tbody.innerHTML = "";

  if (!deviations || deviations.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Sem desvios ao baseline neste período</td></tr>';
    return;
  }

  deviations.forEach((d) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(d.user)}</td>
      <td>${escapeHtml(d.cargo)}</td>
      <td>${escapeHtml(d.group)}</td>
      <td class="wrap">${escapeHtml(d.reason)}</td>
      <td>${escapeHtml(d.executed_by)}</td>
      <td class="mono">${escapeHtml(formatTimestamp(d.timestamp))}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Bloco de destaque (sempre visível, ver .critical-additions-block em
// style.css) para adições a grupos críticos — zero é informação de auditoria,
// por isso nunca escondemos o bloco, só mudamos a mensagem.
function renderCriticalAdditionsBlock(additions) {
  const container = document.getElementById("privileges-critical-block");

  if (!additions || additions.length === 0) {
    container.innerHTML = '<p class="empty-state">Nenhuma adição a grupo crítico neste período</p>';
    return;
  }

  container.innerHTML = additions
    .map(
      (a) => `
        <div class="bf-item">
          <span><strong>${escapeHtml(a.user)}</strong> adicionado a <strong>${escapeHtml(a.group)}</strong> por ${escapeHtml(a.executed_by)}</span>
          <span>${escapeHtml(formatTimestamp(a.timestamp))}</span>
        </div>
      `
    )
    .join("");
}

function renderPrivilegesGroupsChart(groupRanking) {
  const sorted = [...(groupRanking || [])].sort((a, b) => b.count - a.count).slice(0, 10);

  renderChart("chart-privileges-groups", {
    type: "bar",
    data: {
      labels: sorted.map((g) => g.group),
      datasets: [{ label: "Movimentações", data: sorted.map((g) => g.count), backgroundColor: chartColor("--accent") }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

async function loadPrivilegesPanel(days) {
  try {
    const data = await fetchJSON(`/api/privileges?days=${days}`);
    renderPanelError("#privileges-panel", null);

    document.getElementById("kpi-privileges-total").textContent = data.total_movements ?? 0;
    document.getElementById("kpi-privileges-deviations").textContent = (data.deviations || []).length;
    document.getElementById("kpi-privileges-critical").textContent = (data.critical_additions || []).length;

    renderPrivilegesGroupsChart(data.group_ranking || []);
    renderPrivilegesDeviationsTable(data.deviations || []);
    renderCriticalAdditionsBlock(data.critical_additions || []);
  } catch (err) {
    console.error(err);
    renderPanelError("#privileges-panel", panelErrorText(err, "Erro ao carregar o painel de privilégios."));
  }
}

// --- Painel: Contas Privilegiadas (tab-admin-activity) ---

function renderAdminEventComparisonChart(eventCounts) {
  const admin = eventCounts?.admin ?? 0;
  const normal = eventCounts?.normal ?? 0;

  renderChart("chart-admin-event-comparison", {
    type: "doughnut",
    data: {
      labels: ["Administrativos", "Normais"],
      datasets: [{ data: [admin, normal], backgroundColor: [chartColor("--cat-7"), chartColor("--cat-1")], borderWidth: 0 }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
    },
  });
}

// Procura o timestamp mais recente entre scheduled_tasks/processes cujo user
// corresponda à conta indicada; devolve null se não encontrar nenhum (nunca
// inventamos um valor, a coluna "Última Atividade" mostra "—" nesse caso).
function findLastActivity(user, scheduledTasks, processes) {
  const events = [...(scheduledTasks || []), ...(processes || [])].filter(
    (e) => e.user === user && e.timestamp
  );
  if (events.length === 0) return null;
  return events.reduce((latest, e) => (new Date(e.timestamp) > new Date(latest.timestamp) ? e : latest)).timestamp;
}

function renderAdminAccountsTable(accounts, specialPrivilegesByUser, scheduledTasks, processes) {
  const tbody = document.getElementById("admin-accounts-body");
  tbody.innerHTML = "";

  if (!accounts || accounts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty-state">Nenhuma conta administrativa identificada neste período</td></tr>';
    return;
  }

  accounts.forEach((user) => {
    const count = specialPrivilegesByUser?.[user] ?? 0;
    const lastActivity = findLastActivity(user, scheduledTasks, processes);
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(user)}</td>
      <td>${escapeHtml(count)}</td>
      <td class="mono">${lastActivity ? escapeHtml(formatTimestamp(lastActivity)) : "—"}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderAdminScheduledTasksTable(tasks) {
  const tbody = document.getElementById("admin-scheduled-tasks-body");
  tbody.innerHTML = "";

  if (!tasks || tasks.length === 0) {
    tbody.innerHTML = '<tr><td colspan="3" class="empty-state">Sem tarefas agendadas por contas administrativas neste período</td></tr>';
    return;
  }

  tasks.forEach((t) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(t.user)}</td>
      <td class="mono">${escapeHtml(formatTimestamp(t.timestamp))}</td>
      <td>${escapeHtml(t.agent_name)}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadAdminActivityPanel(days) {
  try {
    const data = await fetchJSON(`/api/admin-activity?days=${days}`);
    renderPanelError("#admin-activity-panel", null);

    renderAdminEventComparisonChart(data.event_counts || {});
    renderAdminAccountsTable(
      data.admin_accounts || [],
      data.special_privileges_by_user || {},
      data.scheduled_tasks || [],
      data.processes || []
    );
    renderAdminScheduledTasksTable(data.scheduled_tasks || []);
    renderDetections("admin-activity-detections", data.detections || []);
  } catch (err) {
    console.error(err);
    renderPanelError("#admin-activity-panel", panelErrorText(err, "Erro ao carregar o painel de contas administrativas."));
  }
}

