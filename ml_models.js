// Abas "📦 Models" e "📐 Evaluation" (marco R9, registo de modelos).
// Carregado depois de app.js e metrics.js: reutiliza os seus globais
// (API_BASE, API_KEY, escapeHtml, renderPanelError) — não redeclarar nenhum
// aqui. Um só pedido a GET /api/ml/models alimenta as duas abas.
//
// TODOS os identificadores de topo começam por mlm ou MLM_: os scripts
// clássicos partilham um só escopo global e um nome repetido rebenta o
// script inteiro (RESEARCH, Pitfall 8).
//
// Duas camadas, para a lógica ser testável sem browser (test_ml_models_ui.py
// + test_ml_models_ui.cjs carregam este ficheiro num node:vm sem document):
//
//   1. camada pura — sem DOM, sem fetch, devolve strings (mlmErrorText,
//      mlmCodeFromResponse, mlmCell, mlmBuildModelsRows, ...);
//   2. camada DOM — só chamada a partir de mlmInit().
//
// O backend nunca envia texto de erro, só um código da lista fechada de D-06
// (ver model_registry.ERROR_CODES): o `detail` da resposta serve apenas de
// chave de lookup em MLM_ERROR_TEXT e nunca entra no DOM.

// ======================= camada pura (sem DOM) ==============================

// Mensagens acionáveis em PT: dizem o que fazer. Nenhuma repete o próprio
// código — o analista vê a consequência e a acção, não um identificador.
const MLM_ERROR_TEXT = {
  invalid_version_id:
    "models/ACTIVE ou uma pasta de versão tem um nome inválido (o formato é vN, por exemplo v1). " +
    "Corrige models/ACTIVE à mão, ou volta a registar o modelo com 'python model_registry.py adopt'.",
  active_not_found:
    "models/ACTIVE aponta para uma versão que não existe em scripts/models/. " +
    "Cria a pasta da versão, ou aponta models/ACTIVE para uma versão que exista.",
  metadata_missing:
    "Esta versão não tem metadata.json, por isso não pode ser carregada nem avaliada. " +
    "Volta a registar o modelo com 'python model_registry.py adopt'.",
  metadata_invalid:
    "O metadata.json desta versão não corresponde ao schema esperado (SHA-256 em falta, " +
    "versão diferente da pasta, ou outro campo inválido), por isso a versão não pode ser carregada. " +
    "Volta a registá-la com 'python model_registry.py adopt'.",
  artifact_missing:
    "Falta isolation_forest.pkl ou scaler.pkl dentro da pasta desta versão. " +
    "Reinstala o modelo, ou volta a registá-lo com 'python model_registry.py adopt'.",
  hash_mismatch:
    "O ficheiro do modelo foi alterado desde que foi registado (SHA-256 não bate), por isso não " +
    "foi carregado. Restaura-o a partir da cópia legada em scripts/models/, ou volta a adotar/treinar.",
  already_adopted:
    "O modelo já está registado numa pasta de versão, por isso não há nada a adotar. " +
    "Para criar uma versão nova, treina o modelo com 'python train_anomaly_model.py'.",
  no_legacy_model:
    "Não há modelo legado para adotar: faltam os ficheiros soltos em scripts/models/. " +
    "Treina primeiro um modelo com 'python train_anomaly_model.py'.",
  registry_unavailable:
    "Não foi possível ler a pasta de modelos no servidor. " +
    "Verifica as permissões de scripts/models/ e o backend.log.",
  unauthorized:
    "API key inválida ou em falta — confirma SENTRYLENS_API_KEY.",
};

const MLM_GENERIC_ERROR = "Erro inesperado ao ler o registo de modelos.";

// Só isto é aceite como código vindo do `detail`; qualquer outra coisa
// (HTML, caminho, texto de exceção) cai no genérico ou no código HTTP.
const MLM_CODE_RE = /^[a-z_]{1,64}$/;

function mlmErrorText(code) {
  if (typeof code !== "string") return MLM_GENERIC_ERROR;
  if (!Object.prototype.hasOwnProperty.call(MLM_ERROR_TEXT, code)) return MLM_GENERIC_ERROR;
  return MLM_ERROR_TEXT[code];
}

function mlmCodeFromResponse(status, body) {
  if (status === 401) return "unauthorized";
  const detail = body ? body.detail : null;
  if (typeof detail === "string" && MLM_CODE_RE.test(detail)) return detail;
  return "http_" + status;
}

function mlmCell(value) {
  if (value === null || value === undefined || value === "") return "desconhecido";
  return escapeHtml(String(value));
}

function mlmBuildModelsRows(report) {
  const versions = (report && report.versions) || [];
  if (!versions.length) {
    return '<tr><td colspan="5" class="empty-state">Sem dados — ainda não há modelos registados.</td></tr>';
  }
  return versions.map((entry) => {
    const ativa = entry.active ? '<span class="mlm-badge mlm-badge-active">ativa</span> ' : "";
    const estado = entry.status === "ok"
      ? "OK"
      : `<span class="mlm-badge mlm-badge-error">${escapeHtml(mlmErrorText(entry.error_code))}</span>`;
    const avaliacao = entry.evaluation === null || entry.evaluation === undefined
      ? "Sem avaliação"
      : "Registada";
    const meta = entry.metadata || {};
    return `<tr>
      <td>${escapeHtml(entry.id || entry.label || "")}</td>
      <td>${ativa}${estado}</td>
      <td>${mlmCell(meta.origin)}</td>
      <td>${mlmCell(meta.trained_at)}</td>
      <td>${avaliacao}</td>
    </tr>`;
  }).join("");
}

function mlmModelsNoticeText(report) {
  const versions = (report && report.versions) || [];
  const ativa = report && report.active ? report.active : "nenhuma";
  let texto = `${versions.length} versão(ões) registada(s). Ativa: ${ativa}.`;
  if (report && report.active_error) {
    texto += ` Aviso: ${mlmErrorText(report.active_error)}`;
  }
  return texto;
}

// Avaliação por versão (D-05). Nesta fase nenhuma versão tem avaliação, por
// isso a coluna só distingue "não há" de "há": mostrar as métricas de uma
// versão é trabalho da Fase 2, com o cuidado de nunca mostrar números de
// outra versão.
function mlmBuildEvalRows(report) {
  const versions = (report && report.versions) || [];
  if (!versions.length) {
    return '<tr><td colspan="3" class="empty-state">Sem dados — ainda não há modelos registados.</td></tr>';
  }
  return versions.map((entry) => {
    const ativa = entry.active ? '<span class="mlm-badge mlm-badge-active">ativa</span>' : "—";
    const avaliacao = entry.evaluation === null || entry.evaluation === undefined
      ? "Sem avaliação"
      : "Avaliação registada no metadata.json; a apresentação das métricas chega na Fase 2.";
    return `<tr>
      <td>${escapeHtml(entry.id || entry.label || "")}</td>
      <td>${ativa}</td>
      <td>${escapeHtml(avaliacao)}</td>
    </tr>`;
  }).join("");
}

// ======================= camada DOM (só via mlmInit) ========================

let mlmModelsTab = null;
let mlmModelsWasShown = false;
let mlmEvalTab = null;
let mlmEvalWasShown = false;
let mlmLoading = false;

async function mlmRequest(path) {
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

function mlmRenderModels(report) {
  document.getElementById("mlm-models-body").innerHTML = mlmBuildModelsRows(report);
  document.getElementById("mlm-models-notice").textContent = mlmModelsNoticeText(report);
}

function mlmRenderEvaluation(report) {
  document.getElementById("mlm-eval-body").innerHTML = mlmBuildEvalRows(report);
  const versions = (report && report.versions) || [];
  const semAvaliacao = versions.filter(
    (v) => v.evaluation === null || v.evaluation === undefined).length;
  document.getElementById("mlm-eval-notice").textContent =
    `${versions.length} versão(ões). ${semAvaliacao} sem avaliação.`;
}

function mlmIsShown(tab) {
  return tab.classList.contains("active") && document.visibilityState === "visible";
}

// Um só pedido alimenta as duas abas — a resposta é a mesma para Models e
// para Evaluation, porque a avaliação é um campo por versão do mesmo
// registo (nunca um ml_training_report.json avulso).
async function mlmRefresh() {
  if (mlmLoading) return;
  mlmLoading = true;
  try {
    const report = await mlmRequest("/api/ml/models");
    renderPanelError("#ml-models-panel", "");
    renderPanelError("#ml-evaluation-panel", "");
    mlmRenderModels(report);
    mlmRenderEvaluation(report);
  } catch (err) {
    const texto = mlmErrorText(err.message);
    renderPanelError("#ml-models-panel", "Não foi possível carregar os modelos: " + texto);
    renderPanelError("#ml-evaluation-panel", "Não foi possível carregar as avaliações: " + texto);
    document.getElementById("mlm-models-body").innerHTML =
      `<tr><td colspan="5" class="empty-state">Sem dados — ${escapeHtml(texto)}</td></tr>`;
    document.getElementById("mlm-eval-body").innerHTML =
      `<tr><td colspan="3" class="empty-state">Sem dados — ${escapeHtml(texto)}</td></tr>`;
  } finally {
    mlmLoading = false;
  }
}

// Ao contrário da Attack Library (que carrega uma vez), aqui recarregamos
// SEMPRE que uma das abas passa de escondida a visível: um adopt pode ter
// corrido entretanto e o backend só passa a usar a versão nova depois de
// reiniciado.
function mlmOnTabChange() {
  const shown = mlmModelsTab ? mlmIsShown(mlmModelsTab) : false;
  if (shown && !mlmModelsWasShown) mlmRefresh();
  mlmModelsWasShown = shown;

  const shownEval = mlmEvalTab ? mlmIsShown(mlmEvalTab) : false;
  if (shownEval && !mlmEvalWasShown) mlmRefresh();
  mlmEvalWasShown = shownEval;
}

function mlmInit() {
  mlmModelsTab = document.getElementById("tab-ml-models");
  if (mlmModelsTab) {
    const observer = new MutationObserver(mlmOnTabChange);
    observer.observe(mlmModelsTab, { attributes: true, attributeFilter: ["class"] });
  }
  mlmEvalTab = document.getElementById("tab-ml-evaluation");
  if (mlmEvalTab) {
    const observer = new MutationObserver(mlmOnTabChange);
    observer.observe(mlmEvalTab, { attributes: true, attributeFilter: ["class"] });
  }
  document.addEventListener("visibilitychange", mlmOnTabChange);
  document.getElementById("mlm-models-reload").addEventListener("click", () => mlmRefresh());
  document.getElementById("mlm-eval-reload").addEventListener("click", () => mlmRefresh());
  // Deep link #ml-models / #ml-evaluation: o applyHash de app.js corre antes
  // deste script.
  mlmOnTabChange();
}

if (typeof document !== "undefined") { mlmInit(); }