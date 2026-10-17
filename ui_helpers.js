// ui_helpers.js — helpers puros do frontend (sem DOM, sem fetch).
//
// Regras deste ficheiro:
//  - Só funções puras: nada toca em document/window no topo, para poderem ser
//    testadas em Node (scripts/test_ui_helpers.cjs, via scripts/test_ui_helpers.py).
//  - Os scripts do dashboard são clássicos e partilham o escopo global, por isso
//    todo o identificador de topo daqui começa por "sl" e nunca repete nomes de app.js.
//  - Carregado em index.html entre config.js e app.js.

// O Wazuh devolve datas como "2026-10-16T10:00:00.000+0000"; Firefox/Safari
// rejeitam o sufixo sem dois pontos. Converte ±HHMM em ±HH:MM e devolve
// um Date, ou null se o valor estiver vazio ou não for uma data válida.
function slParseDate(ts) {
  if (ts === null || ts === undefined || ts === "") return null;
  const valor = typeof ts === "string"
    ? ts.trim().replace(/([+-]\d{2})(\d{2})$/, "$1:$2")
    : ts;
  const data = new Date(valor);
  return Number.isNaN(data.getTime()) ? null : data;
}

// Data/hora legível em pt-PT, ou "—" quando não há valor válido.
function slFormatTimestamp(ts) {
  const data = slParseDate(ts);
  return data ? data.toLocaleString("pt-PT") : "—";
}

// Texto e classe CSS do indicador do cabeçalho, a partir de /api/siem/health.
// `health` é a resposta (ou null); `failed` indica que o pedido falhou.
// Com resposta, `failed` é ignorado.
function slHeaderStatus(health, failed) {
  if (health === null || health === undefined) {
    return failed
      ? { text: "● sem ligação ao backend", cls: "status-error" }
      : { text: "● a verificar", cls: "status-unknown" };
  }
  switch (health.status) {
    case "ok": return { text: "● Wazuh operacional", cls: "status-ok" };
    case "degraded": return { text: "● Wazuh degradado", cls: "status-warn" };
    case "down": return { text: "● Wazuh em baixo", cls: "status-error" };
    default: return { text: "● estado do Wazuh desconhecido", cls: "status-unknown" };
  }
}

// Indicador do cabeçalho quando o pedido a /api/siem/health lança erro:
// 401 é chave da API inválida (o backend respondeu), o resto é falta de ligação.
function slHeaderErrorStatus(err) {
  if (err && err.status === 401) return { text: "● chave da API inválida", cls: "status-error" };
  return slHeaderStatus(null, true);
}

// Número finito ou null. Rejeita null/undefined/""/booleanos/NaN/Infinity,
// para que "sem valor" nunca vire 0.
function slNumberOrNull(v) {
  if (v === null || v === undefined || v === "" || typeof v === "boolean") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

// Percentagem formatada ("12%") ou "—" sem valor.
function slFmtPct(v, digits = 0) {
  const n = slNumberOrNull(v);
  return n === null ? "—" : `${n.toFixed(digits)}%`;
}

// Largura CSS de uma barra de progresso: "0%" sem valor, senão limitada a 0-100.
function slProgressWidth(v) {
  const n = slNumberOrNull(v);
  return n === null ? "0%" : `${Math.min(100, Math.max(0, n))}%`;
}

// Concordância regra/ML em percentagem inteira, ou "—" sem amostra válida.
function slAgreementText(agree, total) {
  const a = slNumberOrNull(agree);
  const t = slNumberOrNull(total);
  if (a === null || t === null || t <= 0) return "—";
  return `${Math.round((a / t) * 100)}%`;
}

// Veredito de conformidade de uma norma: rótulo visível + justificação (tooltip).
// Estado em falta ou desconhecido nunca é apresentado como "não aplicável".
function slComplianceVerdict(v) {
  const hasVerdict = v !== null && v !== undefined && typeof v === "object";
  const estado = hasVerdict ? v.estado : undefined;
  let label = "❔ Indeterminado";
  if (estado === "aplicavel") label = "✅ Aplicável";
  else if (estado === "verificado_e_nao_aplicavel") label = "➖ Não aplicável";
  let title = "";
  if (!hasVerdict) title = "Sem veredito do motor de conformidade";
  else if (typeof v.justificacao === "string") title = v.justificacao;
  return { label, title };
}

// Filtro "Estado" dos analistas. O backend só conhece active_only; "Inativos"
// pede todos (activeOnly=false) e filtra no cliente (onlyInactive=true).
function slAnalystActiveFilter(value) {
  if (value === "1") return { activeOnly: true, onlyInactive: false };
  if (value === "0") return { activeOnly: false, onlyInactive: true };
  return { activeOnly: false, onlyInactive: false };
}

// Janela global (W5.3): um só seletor, em horas. Cada fonte tem o seu teto
// (alertas 168 h, incidentes e ataques 720 h, contas 90 dias); a janela efetiva
// é o mínimo dos dois e a aba diz qual foi, nunca recorta em silêncio.
// Valor não numérico, infinito ou <= 0 usa a janela por omissão de 168 h.
function slWindowHours(selected) {
  const h = Number(selected);
  return Number.isFinite(h) && h > 0 ? h : 168;
}

// { hours, clamped } para uma fonte com teto `maxHours`.
function slEffectiveWindow(selected, maxHours) {
  const want = slWindowHours(selected);
  return { hours: Math.min(want, maxHours), clamped: want > maxHours };
}

// Dias inteiros (>= 1) para as rotas que pedem `days` (ciclo de vida, backfill).
function slWindowDays(hours) {
  return Math.max(1, Math.ceil(hours / 24));
}

// "últimos 7 dias", "última hora"... para a nota «A mostrar».
function slWindowLabel(hours) {
  if (hours === 1) return "última hora";
  if (hours < 24) return `últimas ${hours} horas`;
  if (hours % 24 !== 0) return `últimas ${hours} horas`;
  const d = hours / 24;
  return d === 1 ? "últimas 24 horas" : `últimos ${d} dias`;
}

// Texto da nota de janela de uma aba: «A mostrar: últimos 7 dias (máximo desta fonte)».
function slWindowNote(selected, maxHours) {
  const w = slEffectiveWindow(selected, maxHours);
  return `A mostrar: ${slWindowLabel(w.hours)}${w.clamped ? " (máximo desta fonte)" : ""}`;
}

// --- Dados dos gráficos (W6) ---
// Tudo puro: o desenho (Chart.js, DOM) fica em overview-alerts.js (renderChart).

// Granularidade dos baldes de um gráfico de alertas ao longo do tempo.
function slBucketGranularity(hours) {
  const h = slWindowHours(hours);
  if (h <= 1) return "5min";
  if (h <= 6) return "30min";
  if (h <= 48) return "hour";
  return "day";
}

function slBucketFloor(date, gran) {
  const d = new Date(date.getTime());
  if (gran === "day") d.setHours(0, 0, 0, 0);
  else if (gran === "hour") d.setMinutes(0, 0, 0);
  else {
    const step = gran === "5min" ? 5 : 30;
    d.setMinutes(Math.floor(d.getMinutes() / step) * step, 0, 0);
  }
  return d;
}

function slBucketNext(date, gran) {
  const d = new Date(date.getTime());
  if (gran === "day") d.setDate(d.getDate() + 1);
  else d.setTime(d.getTime() + (gran === "hour" ? 3600000 : gran === "5min" ? 300000 : 1800000));
  return d;
}

function slPad2(n) {
  return n < 10 ? "0" + n : String(n);
}

function slBucketLabel(date, gran, hours) {
  const dia = `${slPad2(date.getDate())}/${slPad2(date.getMonth() + 1)}`;
  if (gran === "day") return dia;
  const hora = slPad2(date.getHours());
  if (gran === "hour") return hours <= 24 ? `${hora} h` : `${dia} ${hora} h`;
  return `${hora}:${slPad2(date.getMinutes())}`;
}

// Baldes CONTÍNUOS da janela [agora - horas, agora]: uma hora (ou dia) sem
// alertas vale 0 em vez de desaparecer, para o ritmo não ficar deformado.
// Devolve [{ startMs, label, count }]; timestamps inválidos ou fora da janela são ignorados.
function slBucketSeries(timestamps, hours, nowMs) {
  const h = slWindowHours(hours);
  const gran = slBucketGranularity(h);
  const buckets = [];
  const index = new Map();
  for (let d = slBucketFloor(new Date(nowMs - h * 3600000), gran); d.getTime() <= nowMs; d = slBucketNext(d, gran)) {
    index.set(d.getTime(), buckets.length);
    buckets.push({ startMs: d.getTime(), label: slBucketLabel(d, gran, h), count: 0 });
  }
  (Array.isArray(timestamps) ? timestamps : []).forEach((ts) => {
    const d = slParseDate(ts);
    if (!d) return;
    const i = index.get(slBucketFloor(d, gran).getTime());
    if (i !== undefined) buckets[i].count += 1;
  });
  return buckets;
}

// Severidades na ordem fixa Crítico -> Info, com zeros (uma barra vazia é uma contagem real).
function slSeverityBars(bySeverity) {
  const order = [["critical", "Crítico"], ["high", "Alto"], ["medium", "Médio"], ["low", "Baixo"], ["info", "Info"]];
  const rows = order.map(([key, label]) => ({ key, label, value: Number(bySeverity && bySeverity[key]) || 0 }));
  return { rows, total: rows.reduce((acc, r) => acc + r.value, 0) };
}

// «4625 · Logon falhado», ordenado por contagem e limitado a `limit` (10 por omissão).
function slEventBars(topEvents, limit) {
  const max = Number.isInteger(limit) && limit > 0 ? limit : 10;
  return (Array.isArray(topEvents) ? topEvents : [])
    .filter((e) => e && Number(e.count) > 0)
    .map((e) => ({ label: e.name ? `${e.event_id} · ${e.name}` : String(e.event_id), value: Number(e.count) }))
    .sort((a, b) => b.value - a.value)
    .slice(0, max);
}

// Texto longo cortado com reticências (rótulos de eixo); o tooltip mostra o completo.
function slTruncate(text, max) {
  const t = String(text === null || text === undefined ? "" : text);
  return t.length <= max ? t : t.slice(0, Math.max(1, max - 1)) + "…";
}

// true se alguma série tem algum valor numérico > 0 (para o estado vazio).
function slHasAnyValue(seriesList) {
  return (Array.isArray(seriesList) ? seriesList : []).some((serie) =>
    (Array.isArray(serie) ? serie : []).some((v) => Number(v) > 0));
}

// aria-label de um gráfico: título + os primeiros pontos, nunca a imagem sozinha.
function slChartAriaLabel(title, rows) {
  const pts = Array.isArray(rows) ? rows : [];
  if (pts.length === 0) return `${title}: sem dados nesta janela`;
  const lista = pts.slice(0, 6).map((r) => `${r.label} ${r.value}`).join(", ");
  return `${title}: ${lista}${pts.length > 6 ? ` e mais ${pts.length - 6}` : ""}`;
}

// --- Matriz de cobertura e faixa ataque -> deteção (W6.4, W6.5) ---
// Dados: itens de GET /api/attacks (expected.detection, actual.achieved, mttd_*).

const SL_SENSORS = ["rule", "ml", "network"];
const SL_SENSOR_LABELS = { rule: "Regra", ml: "ML", network: "Rede" };

// Matriz cenário x sensor. Por célula: n = tentativas que ESPERAVAM o sensor, k = as que o
// alcançaram. Veredito "unknown" (correlação indisponível) não conta: não é falha nem sucesso.
// state: hit (k=n) | partial | miss (k=0) | extra (não esperado mas alcançado) | none.
function slCoverageMatrix(attacks) {
  const byScenario = new Map();
  let unknown = 0;
  (Array.isArray(attacks) ? attacks : []).forEach((a) => {
    if (!a || !a.actual || a.actual.verdict === "unknown") { unknown += 1; return; }
    let row = byScenario.get(a.scenario);
    if (!row) {
      row = { scenario: a.scenario, attempts: 0, cells: {} };
      SL_SENSORS.forEach((s) => { row.cells[s] = { n: 0, k: 0, extra: 0, state: "none" }; });
      byScenario.set(a.scenario, row);
    }
    row.attempts += 1;
    const expected = (a.expected && a.expected.detection) || [];
    const achieved = a.actual.achieved || [];
    SL_SENSORS.forEach((s) => {
      const c = row.cells[s];
      if (expected.includes(s)) { c.n += 1; if (achieved.includes(s)) c.k += 1; }
      else if (achieved.includes(s)) c.extra += 1;
    });
  });
  const rows = [...byScenario.values()].sort((x, y) => String(x.scenario).localeCompare(String(y.scenario)));
  rows.forEach((r) => SL_SENSORS.forEach((s) => {
    const c = r.cells[s];
    if (c.n > 0) c.state = c.k === c.n ? "hit" : c.k === 0 ? "miss" : "partial";
    else c.state = c.extra > 0 ? "extra" : "none";
  }));
  return { rows, unknown };
}

// Texto da célula (nunca só cor) e descrição longa para leitores de ecrã.
function slMatrixCellText(cell) {
  if (cell.state === "hit") return { text: `✔ ${cell.k}/${cell.n}`, label: `esperado e alcançado em ${cell.k} de ${cell.n}` };
  if (cell.state === "partial") return { text: `◐ ${cell.k}/${cell.n}`, label: `esperado, alcançado em ${cell.k} de ${cell.n}` };
  if (cell.state === "miss") return { text: `✘ 0/${cell.n}`, label: `esperado e não alcançado em ${cell.n}` };
  if (cell.state === "extra") return { text: "＋ extra", label: "não esperado, mas alcançado" };
  return { text: "—", label: "não esperado" };
}

// Faixa: uma linha por ataque (mais antigo primeiro), eixo comum em segundos desde o lançamento.
// Regra e ML partilham mttd_seconds (o backend só calcula um); a rede tem o seu.
function slAttackStrip(attacks) {
  const list = (Array.isArray(attacks) ? attacks : []).filter((a) => a && a.actual)
    .sort((x, y) => (slParseDate(x.timestamp) || 0) - (slParseDate(y.timestamp) || 0));
  let max = 0;
  const rows = list.map((a, i) => {
    const achieved = a.actual.achieved || [];
    const points = [];
    achieved.forEach((s) => {
      const sec = s === "network" ? a.actual.mttd_network_seconds : a.actual.mttd_seconds;
      if (Number.isFinite(sec) && sec >= 0) { points.push({ sensor: s, seconds: sec }); if (sec > max) max = sec; }
    });
    return {
      key: a.id === null || a.id === undefined ? `i${i}` : String(a.id),
      label: `${a.id === null || a.id === undefined ? "" : "#" + a.id + " "}${a.scenario}`,
      verdict: a.actual.verdict,
      detected: achieved.length > 0,
      points,
    };
  });
  const step = max <= 60 ? 20 : max <= 600 ? 120 : 1200; // eixo divisível por 4 (ticks redondos)
  return { rows, maxSeconds: Math.max(step, Math.ceil(max / step) * step) };
}

// Valor de um token CSS (custom property). `style` é um CSSStyleDeclaration
// (getComputedStyle(document.documentElement)) ou qualquer objeto com
// getPropertyValue; devolve "" se o token não existir. Puro: o DOM fica com o chamador.
function slCssToken(style, name) {
  if (!style || typeof style.getPropertyValue !== "function") return "";
  const v = style.getPropertyValue(name);
  return typeof v === "string" ? v.trim() : "";
}

// Aplica transparência a uma cor de token (#rgb ou #rrggbb) -> color(srgb r g b / a),
// que o canvas aceita. Qualquer outro formato (ou alpha inválido) devolve-se como veio.
function slColorAlpha(color, alpha) {
  const m = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(typeof color === "string" ? color.trim() : "");
  const a = Number(alpha);
  if (!m || !Number.isFinite(a) || a < 0 || a > 1) return color;
  let h = m[1];
  if (h.length === 3) h = h.split("").map((c) => c + c).join("");
  const ch = [0, 2, 4].map((i) => +(parseInt(h.slice(i, i + 2), 16) / 255).toFixed(4));
  return `color(srgb ${ch[0]} ${ch[1]} ${ch[2]} / ${a})`;
}

// Severidade -> token CSS (--sev-*). Desconhecida cai em --sev-info.
function slSeverityToken(sev) {
  const ok = ["critical", "high", "medium", "low", "info"];
  return "--sev-" + (ok.includes(sev) ? sev : "info");
}

// Série categórica (índice 0-based) -> token --cat-1..--cat-8, com volta ao início.
function slCategoryToken(index) {
  const i = Number.isInteger(index) && index >= 0 ? index : 0;
  return "--cat-" + ((i % 8) + 1);
}

// Foco preso dentro de um modal aberto (WCAG 2.4.3). Pura: recebe os elementos focáveis
// e o ativo; devolve o elemento que deve receber o foco, ou null para deixar o Tab seguir.
function slModalTabTarget(focusables, active, shiftKey) {
  if (!Array.isArray(focusables) || focusables.length === 0) return null;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  const idx = focusables.indexOf(active);
  if (idx === -1) return shiftKey ? last : first;
  if (shiftKey && active === first) return last;
  if (!shiftKey && active === last) return first;
  return null;
}

// ----- MTTD: fonte única (GET /api/metrics, soc_metrics.build_metrics_report) -----
// Overview, Incidentes, Red vs Blue e Métricas mostram todos a MESMA mediana da
// MESMA janela (hours=SL_MTTD_WINDOW_HOURS, o máximo da rota) com o mesmo rótulo.
const SL_MTTD_WINDOW_HOURS = 168;

function slFormatDuration(value) {
  if (value === null || value === undefined) return "—";
  const s = Number(value);
  if (!Number.isFinite(s)) return "—";
  if (s < 60) return `${s.toFixed(1)} s`;
  if (s < 3600) return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
  return `${Math.floor(s / 3600)} h ${Math.round((s % 3600) / 60)} min`;
}

function slMttdLabel(hours) {
  const h = Number(hours) || SL_MTTD_WINDOW_HOURS;
  return h % 24 === 0 ? `MTTD (mediana, ${h / 24} dias)` : `MTTD (mediana, ${h} h)`;
}

// metrics = resposta de /api/metrics (ou null); error = o pedido falhou.
// Devolve {value, label, sub}; sem amostra é sempre "—", nunca 0.
function slMttdView(metrics, error) {
  if (!metrics) {
    return { value: "—", label: slMttdLabel(), sub: error ? "Fonte indisponível" : "A carregar…" };
  }
  const label = slMttdLabel(metrics.window_hours);
  const m = metrics.mttd || {};
  if (m.available === false || m.median_s === null || m.median_s === undefined) {
    return { value: "—", label, sub: m.reason === "source_unavailable" ? "Fonte indisponível" : "Sem dados" };
  }
  const sub = `n=${m.n}${m.small_sample ? " · amostra pequena" : ""}${metrics.alerts_truncated ? " · limite inferior (alertas truncados)" : ""}`;
  return { value: slFormatDuration(m.median_s), label, sub };
}

// Liga o Tab preso a qualquer .modal visível. Só corre no browser (guarda por typeof document).
function slInstallModalFocusTrap() {
  document.addEventListener("keydown", (ev) => {
    if (ev.key !== "Tab") return;
    const modal = document.querySelector(".modal:not([hidden])");
    if (!modal) return;
    const sel = "a[href], button:not([disabled]), input:not([disabled]):not([type=hidden]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex=\"-1\"])";
    const focusables = Array.from(modal.querySelectorAll(sel)).filter((el) => !el.hidden && el.offsetParent !== null);
    const target = slModalTabTarget(focusables, document.activeElement, ev.shiftKey);
    if (target) { ev.preventDefault(); target.focus(); }
  });
}
if (typeof document !== "undefined") slInstallModalFocusTrap();
