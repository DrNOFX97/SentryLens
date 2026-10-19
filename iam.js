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
  tbody.replaceChildren();

  if (!events || events.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="5" class="empty-state">Sem eventos neste período</td></tr>`);
    return;
  }

  events.forEach((ev) => {
    const tr = document.createElement("tr");
    htmRender(tr, htmlT`
      <td class="mono">${formatTimestamp(ev.timestamp)}</td>
      <td>${lifecycleEventTypeLabel(ev.event_id)}</td>
      <td>${ev.target_user}</td>
      <td>${ev.executed_by}</td>
      <td>${ev.agent_name}</td>
    `);
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

// Cinco categorias numa paleta categórica (azul, verde-água, rosa, violeta, laranja): as
// cores de estado (vermelho/amarelo/verde) ficam reservadas para severidade e saúde.
const IAM_LIFECYCLE_SERIES = [
  { key: "created", label: "Criadas", token: "--cat-1" },
  { key: "activated", label: "Ativadas", token: "--cat-3" },
  { key: "disabled", label: "Desativadas", token: "--cat-5" },
  { key: "deleted", label: "Eliminadas", token: "--cat-7" },
  { key: "locked", label: "Bloqueadas", token: "--cat-2" },
];

function renderLifecycleTimelineChart(timeline) {
  const data = timeline || [];
  const empty = !slHasAnyValue(IAM_LIFECYCLE_SERIES.map((s) => data.map((t) => t[s.key])));
  const totals = IAM_LIFECYCLE_SERIES.map((s) => ({ label: s.label, value: fmtNumber(data.reduce((acc, t) => acc + (Number(t[s.key]) || 0), 0)) }));
  renderChart("chart-lifecycle-timeline", {
    type: "bar",
    data: {
      labels: data.map((t) => t.date),
      datasets: IAM_LIFECYCLE_SERIES.map((s) => ({ label: s.label, data: data.map((t) => t[s.key]), backgroundColor: chartColor(s.token), maxBarThickness: 28 })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } },
      scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } },
    },
  }, {
    title: empty ? "Ciclo de vida de contas: sem dados nesta janela" : slChartAriaLabel("Ciclo de vida de contas, totais da janela", totals),
    empty,
    columns: ["Dia", ...IAM_LIFECYCLE_SERIES.map((s) => s.label)],
    rows: data.map((t) => [t.date, ...IAM_LIFECYCLE_SERIES.map((s) => fmtNumber(t[s.key]))]),
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
  tbody.replaceChildren();

  if (!deviations || deviations.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="6" class="empty-state">Sem desvios ao baseline neste período</td></tr>`);
    return;
  }

  deviations.forEach((d) => {
    const tr = document.createElement("tr");
    htmRender(tr, htmlT`
      <td>${d.user}</td>
      <td>${d.cargo}</td>
      <td>${d.group}</td>
      <td class="wrap">${d.reason}</td>
      <td>${d.executed_by}</td>
      <td class="mono">${formatTimestamp(d.timestamp)}</td>
    `);
    tbody.appendChild(tr);
  });
}

// Bloco de destaque (sempre visível, ver .critical-additions-block em
// style.css) para adições a grupos críticos — zero é informação de auditoria,
// por isso nunca escondemos o bloco, só mudamos a mensagem.
function renderCriticalAdditionsBlock(additions) {
  const container = document.getElementById("privileges-critical-block");

  if (!additions || additions.length === 0) {
    sttShowEmpty(container, "Nenhuma adição a grupo crítico neste período");
    return;
  }

  htmRender(container, htmlT`${additions.map((a) => htmlT`
        <div class="bf-item">
          <span><strong>${a.user}</strong> adicionado a <strong>${a.group}</strong> por ${a.executed_by}</span>
          <span>${formatTimestamp(a.timestamp)}</span>
        </div>
      `)}`);
}

function renderPrivilegesGroupsChart(groupRanking) {
  const rows = [...(groupRanking || [])]
    .filter((g) => Number(g.count) > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, 10)
    .map((g) => ({ label: g.group, value: Number(g.count) }));

  renderChart("chart-privileges-groups", {
    type: "bar",
    data: {
      labels: rows.map((r) => r.label),
      datasets: [{ label: "Movimentações", data: rows.map((r) => r.value), backgroundColor: chartColor("--accent"), maxBarThickness: 18 }],
    },
    options: chartHBarOptions(rows.map((r) => r.label)),
    plugins: [chartValueLabels],
  }, {
    title: rows.length ? slChartAriaLabel("Grupos mais movimentados", rows.map((r) => ({ label: r.label, value: fmtNumber(r.value) }))) : "Grupos mais movimentados: sem dados nesta janela",
    empty: rows.length === 0,
    columns: ["Grupo", "Movimentações"],
    rows: rows.map((r) => [r.label, fmtNumber(r.value)]),
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

// Dois números não pedem um gráfico: um KPI com a parte e o total.
function renderAdminShare(eventCounts) {
  const admin = Number(eventCounts?.admin);
  const normal = Number(eventCounts?.normal);
  const valueEl = document.getElementById("admin-share-value");
  const detailEl = document.getElementById("admin-share-detail");
  const total = (Number.isFinite(admin) ? admin : 0) + (Number.isFinite(normal) ? normal : 0);
  if (!Number.isFinite(admin) || !Number.isFinite(normal) || total === 0) {
    valueEl.textContent = FMT_EMPTY;
    detailEl.textContent = "Sem dados nesta janela";
    return;
  }
  valueEl.textContent = fmtPct((admin / total) * 100, { decimals: 0 });
  detailEl.textContent = `${fmtNumber(admin)} de ${fmtNumber(total)} eventos são de contas administrativas`;
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
  tbody.replaceChildren();

  if (!accounts || accounts.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="3" class="empty-state">Nenhuma conta administrativa identificada neste período</td></tr>`);
    return;
  }

  accounts.forEach((user) => {
    const count = specialPrivilegesByUser?.[user] ?? 0;
    const lastActivity = findLastActivity(user, scheduledTasks, processes);
    const tr = document.createElement("tr");
    htmRender(tr, htmlT`
      <td>${user}</td>
      <td>${count}</td>
      <td class="mono">${lastActivity ? formatTimestamp(lastActivity) : "—"}</td>
    `);
    tbody.appendChild(tr);
  });
}

function renderAdminScheduledTasksTable(tasks) {
  const tbody = document.getElementById("admin-scheduled-tasks-body");
  tbody.replaceChildren();

  if (!tasks || tasks.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="3" class="empty-state">Sem tarefas agendadas por contas administrativas neste período</td></tr>`);
    return;
  }

  tasks.forEach((t) => {
    const tr = document.createElement("tr");
    htmRender(tr, htmlT`
      <td>${t.user}</td>
      <td class="mono">${formatTimestamp(t.timestamp)}</td>
      <td>${t.agent_name}</td>
    `);
    tbody.appendChild(tr);
  });
}

async function loadAdminActivityPanel(days) {
  try {
    const data = await fetchJSON(`/api/admin-activity?days=${days}`);
    renderPanelError("#admin-activity-panel", null);

    renderAdminShare(data.event_counts || {});
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

