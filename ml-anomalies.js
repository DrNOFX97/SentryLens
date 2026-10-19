// Painel ML Anomalias.

// --- Painel: ML Anomalias (tab-ml-anomalies) ---

function renderMlAnomaliesTable(results) {
  const tbody = document.getElementById("ml-anomalies-body");
  tbody.replaceChildren();

  if (!results || results.length === 0) {
    htmRender(tbody, htmlT`<tr><td colspan="8" class="empty-state">Sem eventos neste período</td></tr>`);
    return;
  }

  results.forEach((r) => {
    const tr = document.createElement("tr");
    tr.className = r.agreement === "diverge" ? "row-diverge" : "";
    const mlScore = slNumberOrNull(r.ml_score);
    const agreementLabel = r.agreement === "agree" ? "✅ Concorda" : r.agreement === "diverge" ? "⚡ Diverge" : "—";
    htmRender(tr, htmlT`
      <td class="mono">${formatTimestamp(r.timestamp)}</td>
      <td>${r.agent_name}</td>
      <td>${r.target_user}</td>
      <td>${String(r.windows_event_id)}</td>
      <td>${htmlRaw(severityBadge(r.severity))}</td>
      <td class="mono">${mlScore === null ? "—" : mlScore.toFixed(4)}</td>
      <td>${r.ml_is_anomaly ? "⚠️ Sim" : "Não"}</td>
      <td><span class="agreement-badge agreement-${String(r.agreement)}">${agreementLabel}</span></td>
    `);
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

