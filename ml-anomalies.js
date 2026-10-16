// Painel ML Anomalias.

// --- Painel: ML Anomalias (tab-ml-anomalies) ---

function renderMlAnomaliesTable(results) {
  const tbody = document.getElementById("ml-anomalies-body");
  tbody.innerHTML = "";

  if (!results || results.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Sem eventos neste período</td></tr>';
    return;
  }

  results.forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = r.agreement === "diverge" ? "row-diverge" : "";
    const mlScore = slNumberOrNull(r.ml_score);
    const agreementLabel = r.agreement === "agree" ? "✅ Concorda" : r.agreement === "diverge" ? "⚡ Diverge" : "—";
    tr.innerHTML = `
      <td class="mono">${escapeHtml(formatTimestamp(r.timestamp))}</td>
      <td>${escapeHtml(r.agent_name)}</td>
      <td>${escapeHtml(r.target_user)}</td>
      <td>${escapeHtml(String(r.windows_event_id))}</td>
      <td>${severityBadge(r.severity)}</td>
      <td class="mono">${escapeHtml(mlScore === null ? "—" : mlScore.toFixed(4))}</td>
      <td>${r.ml_is_anomaly ? "⚠️ Sim" : "Não"}</td>
      <td><span class="agreement-badge agreement-${escapeHtml(String(r.agreement))}">${escapeHtml(agreementLabel)}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadMlAnomaliesPanel(hours) {
  try {
    const data = await fetchJSON(`/api/ml-anomalies?hours=${hours}`);
    renderPanelError("#ml-anomalies-panel", null);

    document.getElementById("kpi-ml-total").textContent = data.total ?? 0;
    document.getElementById("kpi-ml-anomalies").textContent = data.ml_anomalies_count ?? 0;
    document.getElementById("kpi-ml-rule-flagged").textContent = data.rule_flagged_count ?? 0;
    document.getElementById("kpi-ml-agreement").textContent = slAgreementText(data.agree_count, data.total);
    document.getElementById("kpi-ml-diverge").textContent = data.diverge_count ?? 0;

    renderMlAnomaliesTable(data.results || []);
  } catch (err) {
    console.error(err);
    if (err.status === 503) {
      renderPanelError("#ml-anomalies-panel", "Modelo de ML ainda não foi treinado. Corre scripts/train_anomaly_model.py.");
    } else {
      renderPanelError("#ml-anomalies-panel", panelErrorText(err, "Erro ao carregar o painel de ML."));
    }
  }
}

