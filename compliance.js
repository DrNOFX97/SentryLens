// Painel Conformidade (RGPD/NIS2/AI Act).

// --- Painel: Conformidade (tab-compliance) ---

function renderComplianceTable(alerts) {
  const tbody = document.getElementById("compliance-body");
  tbody.replaceChildren();

  if (!alerts || alerts.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="7" class="empty-state">Sem alertas neste período</td></tr>`);
    return;
  }

  alerts.forEach((a) => {
    const tr = document.createElement("tr");
    const c = a.compliance || {};
    const cell = (v) => {
      const { label, title } = slComplianceVerdict(v);
      return htmlT`<td title="${title}">${label}</td>`;
    };
    htmRender(tr, htmlT`
      <td class="mono">${formatTimestamp(a.timestamp)}</td>
      <td>${a.agent_name}</td>
      <td>${a.friendly_name}</td>
      <td>${htmlRaw(severityBadge(a.severity))}</td>
      ${cell(c.rgpd)}
      ${cell(c.nis2)}
      ${cell(c.ai_act)}
    `);
    tbody.appendChild(tr);
  });
}

async function loadCompliancePanel(hours) {
  try {
    const data = await fetchJSON(`/api/compliance?hours=${hours}`);
    renderPanelError("#compliance-panel", null);

    document.getElementById("kpi-compliance-total").textContent = data.total ?? 0;
    document.getElementById("kpi-compliance-rgpd").textContent = (data.summary && data.summary.rgpd && data.summary.rgpd.aplicavel) ?? 0;
    document.getElementById("kpi-compliance-nis2").textContent = (data.summary && data.summary.nis2 && data.summary.nis2.aplicavel) ?? 0;
    document.getElementById("kpi-compliance-ai-act").textContent = (data.summary && data.summary.ai_act && data.summary.ai_act.aplicavel) ?? 0;

    const profile = data.org_profile || {};
    const orgNote = document.getElementById("compliance-org-note");
    if (orgNote) {
      orgNote.textContent =
        `Perfil da organização: ${profile.nome || "-"} — ` +
        `sujeita a NIS2: ${profile.estatuto_nis2_aplicavel ? "sim" : "não"}, ` +
        `componentes de IA ativos: ${profile.tem_componentes_ia_ativos ? "sim" : "não"}.`;
    }

    renderComplianceTable(data.alerts || []);
  } catch (err) {
    console.error(err);
    renderPanelError("#compliance-panel", panelErrorText(err, "Erro ao carregar o painel de conformidade."));
  }
}

