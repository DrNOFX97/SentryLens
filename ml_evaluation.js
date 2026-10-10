// Aba "📐 Evaluation" (marco R9, Fase 2 — avaliação ligada à versão).
// Carregado DEPOIS de app.js e de ml_models.js: reutiliza os globais de
// app.js (API_BASE, API_KEY, escapeHtml, renderPanelError) e os helpers puros
// de ml_models.js (mlmErrorText, mlmCodeFromResponse) — não redeclara nenhum
// deles, porque os scripts clássicos partilham um só escopo global.
//
// TODOS os identificadores de topo começam por mle/MLE_ (Pitfall 9): um nome
// repetido com ml_models.js (mlm/MLM_) ou com app.js rebentava o script
// inteiro no browser. O teste node:vm carrega os DOIS ficheiros no mesmo
// contexto de propósito, para que essa colisão fosse um teste vermelho.
//
// Duas camadas, como ml_models.js, para a lógica ser testável sem browser
// (test_ml_models_ui.py + test_ml_models_ui.cjs carregam este ficheiro num
// node:vm sem document):
//
//   1. camada pura — sem DOM, sem fetch, devolve strings (mlePercent,
//      mleMetricCell, mleBuildEvalRows, mleEvalNoticeText, mleEmptyState);
//   2. camada DOM — só chamada a partir de mleInit().
//
// Nenhuma linha de topo toca em `document`: é o que permite ao teste Node
// carregar o ficheiro. O arranque é a ÚLTIMA instrução, com a guarda
// `typeof document !== "undefined"`.
//
// Cada linha lê o `evaluation` da SUA PRÓPRIA entrada: nunca um valor global.
// Com duas versões com avaliações diferentes, a linha de cada uma tem de
// trazer as métricas dela (Pitfall 1 — o critério 2 do ROADMAP). Todo o texto
// que vem do metadata.json do utilizador passa por escapeHtml.

// ======================= camada pura (sem DOM) ==============================

const MLE_EMPTY_TEXT = "Sem dados — ainda não há modelos registados.";
const MLE_SEM_AVALIACAO =
  'Sem avaliação — corre "python model_registry.py evaluate vN --events <ficheiro>"';

// Uma percentagem pt-PT, com uma casa. Um valor em falta nunca é desenhado
// como 0 %: sem amostra é "—", não um número inventado (D-10/Pitfall 3).
function mlePercent(value) {
  if (typeof value !== "number" && typeof value !== "string") return "—";
  if (typeof value === "string" && value.trim() === "") return "—";
  const numero = Number(value);
  if (!Number.isFinite(numero)) return "—";
  return `${(numero * 100).toFixed(1).replace(".", ",")} %`;
}

// As três métricas de um lado (ML ou regras) numa célula. Sem objeto, "—".
function mleMetricCell(metrics) {
  if (!metrics || typeof metrics !== "object") return "—";
  return [
    ["P", metrics.precision],
    ["R", metrics.recall],
    ["F", metrics.f1],
  ].map(([sigla, valor]) =>
    `<span class="mle-metric"><span class="mle-metric-label">${sigla}</span> ${mlePercent(valor)}</span>`
  ).join(" ");
}

function mleEmptyState(colspan, texto) {
  const col = Number(colspan) > 0 ? Number(colspan) : 1;
  return `<tr><td colspan="${col}" class="empty-state">${escapeHtml(texto)}</td></tr>`;
}

// Uma linha por versão: Versão | Ativa | ML | Regras. Quando a versão não tem
// avaliação, uma linha extra diz "Sem avaliação" — a distinção tem de ser
// VISÍVEL, não um "—" que se lê como zero (EVAL-03).
function mleBuildEvalRows(report) {
  const versions = (report && report.versions) || [];
  if (!versions.length) return mleEmptyState(4, MLE_EMPTY_TEXT);
  return versions.map((entry) => {
    const ativa = entry.active ? '<span class="mlm-badge mlm-badge-active">ativa</span>' : "—";
    const versao = escapeHtml(entry.id || entry.label || "");
    const avaliacao = entry.evaluation;
    const linha = `<tr>
      <td>${versao}</td>
      <td>${ativa}</td>
      <td>${mleMetricCell(avaliacao && avaliacao.ml)}</td>
      <td>${mleMetricCell(avaliacao && avaliacao.rules)}</td>
    </tr>`;
    if (avaliacao !== null && avaliacao !== undefined) return linha;
    return linha + mleEmptyState(4, MLE_SEM_AVALIACAO);
  }).join("");
}

// Uma frase com as contagens que o analista precisa antes de ler números:
// quantas versões há e quantas ainda não foram avaliadas.
function mleEvalNoticeText(report) {
  const versions = (report && report.versions) || [];
  const semAvaliacao = versions.filter(
    (v) => v.evaluation === null || v.evaluation === undefined).length;
  return `${versions.length} versão(ões). ${semAvaliacao} sem avaliação.`;
}

// ======================= camada DOM (só via mleInit) ========================

let mleEvalTab = null;
let mleEvalWasShown = false;
let mleLoading = false;
let mleLastReport = null;

// Pedido próprio (nome próprio, `mlmRequest` é de ml_models.js): a resposta é
// a mesma, mas o ciclo de dados desta aba é independente — ml_models.js só
// redesenha a aba Models.
async function mleRequest(path) {
  const response = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!response.ok) {
    let corpo = null;
    try {
      corpo = await response.json();
    } catch (_) { /* corpo não-JSON: fica só o código HTTP */ }
    throw new Error(mlmCodeFromResponse(response.status, corpo));
  }
  return response.json();
}

function mleRenderEvaluation(report) {
  document.getElementById("mlm-eval-body").innerHTML = mleBuildEvalRows(report);
  document.getElementById("mlm-eval-notice").textContent = mleEvalNoticeText(report);
}

async function mleRefresh() {
  if (mleLoading) return;
  mleLoading = true;
  try {
    const report = await mleRequest("/api/ml/models");
    renderPanelError("#ml-evaluation-panel", "");
    mleLastReport = report;
    mleRenderEvaluation(report);
  } catch (err) {
    // O `detail` da resposta nunca entra no DOM: entra como chave de lookup
    // em mlmErrorText e sai já traduzido.
    const texto = mlmErrorText(err.message);
    mleLastReport = null;
    renderPanelError("#ml-evaluation-panel", "Não foi possível carregar as avaliações: " + texto);
    document.getElementById("mlm-eval-body").innerHTML =
      mleEmptyState(4, `Sem dados — ${texto}`);
  } finally {
    mleLoading = false;
  }
}

function mleIsShown(tab) {
  return tab.classList.contains("active") && document.visibilityState === "visible";
}

// Recarrega SEMPRE que a aba passa de escondida a visível, como ml_models.js
// faz com a Models: um `evaluate` pode ter corrido entretanto e o backend
// só passa a usar a versão nova depois de reiniciado.
function mleOnTabChange() {
  const shown = mleEvalTab ? mleIsShown(mleEvalTab) : false;
  if (shown && !mleEvalWasShown) mleRefresh();
  mleEvalWasShown = shown;
}

function mleInit() {
  mleEvalTab = document.getElementById("tab-ml-evaluation");
  if (mleEvalTab) {
    const observer = new MutationObserver(mleOnTabChange);
    observer.observe(mleEvalTab, { attributes: true, attributeFilter: ["class"] });
  }
  document.addEventListener("visibilitychange", mleOnTabChange);
  const reload = document.getElementById("mlm-eval-reload");
  if (reload) reload.addEventListener("click", () => mleRefresh());
  // Deep link #ml-evaluation: o applyHash de app.js corre antes deste script.
  mleOnTabChange();
}

if (typeof document !== "undefined") { mleInit(); }