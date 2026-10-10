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

// --- estados, datas e origem (texto simples ou HTML já escapado) -------------
//
// "ok" e "no_metadata" são os dois estados que não são problema: o primeiro
// diz que o SHA-256 bateu, o segundo que o legado está a ser usado sem
// verificação até ser adotado (REG-02). Qualquer outro status é um problema
// real e traduz-se pela mensagem de MLM_ERROR_TEXT — o código nunca aparece.

const MLM_OK_TEXT = "Íntegra (SHA-256 verificado)";
const MLM_NO_METADATA_TEXT =
  "Sem metadados nem hash — carrega sem verificação até ser adotado";

function mlmStatusText(entry) {
  const status = entry ? entry.status : null;
  if (status === "ok") return MLM_OK_TEXT;
  if (status === "no_metadata") return MLM_NO_METADATA_TEXT;
  return mlmErrorText(entry ? entry.error_code : null);
}

// Data ISO -> texto pt-PT. Uma data ilegível nunca é adivinhada nem vira
// "Invalid Date": devolve o texto escapado que estava no metadata.json, para
// o analista ver o que lá está. Sem data, "desconhecido".
function mlmFormatDate(iso) {
  if (iso === null || iso === undefined || iso === "") return "desconhecido";
  const data = new Date(iso);
  if (Number.isNaN(data.getTime())) return escapeHtml(String(iso));
  return data.toLocaleString("pt-PT");
}

// "adotado" é o badge de quem herdou do legado; "treinado" (Fase 3) é texto
// simples; o legado é neutro, nunca verde nem vermelho.
function mlmOriginText(entry) {
  if (entry && entry.kind === "legacy") return "legado";
  const meta = (entry && entry.metadata) || null;
  if (meta && meta.adopted === true) return "adotado";
  if (meta && meta.origin === "trained") return "treinado";
  return "desconhecido";
}

function mlmOriginHtml(entry) {
  const meta = (entry && entry.metadata) || null;
  const texto = escapeHtml(mlmOriginText(entry));
  if (entry && entry.kind === "legacy") {
    return `<span class="mlm-badge mlm-badge-legacy">${texto}</span>`;
  }
  if (meta && meta.adopted === true) {
    return `<span class="mlm-badge mlm-badge-adopted">${texto}</span>`;
  }
  return texto;
}

// A data de treino do legado é a mtime do ficheiro — não é a data em que o
// modelo foi treinado, por isso diz "(data do ficheiro)" em vez de fingir.
function mlmTrainedAtText(entry) {
  const meta = (entry && entry.metadata) || null;
  if (meta) {
    // "(estimada)" só faz sentido com uma data: "desconhecido (estimada)"
    // seria dizer ao mesmo tempo que não se sabe e que se sabe.
    if (meta.trained_at === null || meta.trained_at === undefined || meta.trained_at === "") {
      return "desconhecido";
    }
    const base = mlmFormatDate(meta.trained_at);
    return meta.trained_at_estimated === true ? `${base} (estimada)` : base;
  }
  const ficheiro = entry && entry.files ? entry.files["isolation_forest.pkl"] : null;
  if (ficheiro) {
    return `${mlmFormatDate(ficheiro.modified_at)} (data do ficheiro)`;
  }
  return "desconhecido";
}

function mlmBuildModelsRows(report) {
  const versions = (report && report.versions) || [];
  if (!versions.length) {
    return '<tr><td colspan="5" class="empty-state">Sem dados — ainda não há modelos registados.</td></tr>';
  }
  return versions.map((entry, indice) => {
    const ativa = entry.active ? '<span class="mlm-badge mlm-badge-active">ativa</span> ' : "";
    const estadoTexto = mlmStatusText(entry);
    // O badge de erro só entra quando há mesmo um erro. O legado tem
    // status "no_metadata" e error_code null porque o modelo está a ser
    // usado à vontade: pintá-lo de vermelho (e com a mensagem genérica, já
    // que não há código) diria ao analista que o modelo avariou.
    const estado = (entry.status === "ok" || entry.status === "no_metadata")
      ? escapeHtml(estadoTexto)
      : `<span class="mlm-badge mlm-badge-error">${escapeHtml(estadoTexto)}</span>`;
    const versao = entry.kind === "legacy"
      ? `<span class="mlm-badge mlm-badge-legacy">${escapeHtml(entry.label || "legado, sem metadados")}</span>`
      : escapeHtml(entry.id || entry.label || "");
    const avaliacao = entry.evaluation === null || entry.evaluation === undefined
      ? "Sem avaliação"
      : "Registada";
    return `<tr class="atk-row" data-index="${indice}" tabindex="0">
      <td>${versao}</td>
      <td>${ativa}${estado}</td>
      <td>${mlmOriginHtml(entry)}</td>
      <td>${mlmTrainedAtText(entry)}</td>
      <td>${avaliacao}</td>
    </tr>`;
  }).join("");
}

// Uma frase por condição, todas a dizer o que fazer. A diferença entre
// `active` (o que models/ACTIVE aponta) e `loaded` (o que o processo tem
// mesmo em memória) é a que explica um dashboard desatualizado depois de um
// adopt: sem ela, a aba affirmaria uma ativa que não é a usada nas deteções
// (D-02).
function mlmModelsNoticeText(report) {
  const versions = (report && report.versions) || [];
  const ativa = report && report.active ? report.active : "nenhuma";
  const carregado = report && report.loaded ? report.loaded : null;
  const frases = [`${versions.length} versão(ões) registada(s). Ativa: ${ativa}.`];

  if (report && report.active_error) {
    frases.push(`⚠ ${mlmErrorText(report.active_error)} Nenhuma versão está ativa e a deteção `
      + "de anomalias fica indisponível (503) até corrigires models/ACTIVE.");
  }
  if (report && report.active === "legacy") {
    frases.push("Ativo: modelo legado (sem metadados nem verificação SHA-256). "
      + "Para o registar como v1 corre 'python model_registry.py adopt' em scripts/.");
  }
  if (report && !report.active && !report.active_error && versions.length > 0) {
    frases.push("Nenhuma versão ativa. Se um adopt foi interrompido, volta a correr "
      + "'python model_registry.py adopt' em scripts/ para completar o models/ACTIVE.");
  }
  if (carregado && report && report.active && carregado !== report.active) {
    frases.push(`O backend está a usar «${carregado}» mas a versão ativa é «${report.active}»: `
      + "reinicia o backend (scripts/start-backend.ps1) para carregar a ativa.");
  }
  if (!carregado) {
    frases.push("O backend ainda não carregou nenhum modelo neste processo "
      + "(carrega no primeiro pedido de deteção).");
  }
  return frases.join(" ");
}

// ================== detalhe da versão selecionada ============================
//
// Tudo o que o metadata.json traz, desenhado a partir do relatório que a
// aba J tem em memória — a lista já traz os metadados, por isso selecionar
// uma versão não custa um pedido ao backend.
//
// Regra única: um valor que não existe é "desconhecido", nunca uma string
// vazia e nunca um valor adivinhado. E um erro de uma versão com problema
// aparece pela mensagem de MLM_ERROR_TEXT, nunca pelo código.

const MLM_ARTIFACT_NAMES = ["isolation_forest.pkl", "scaler.pkl"];

// A chave estável de uma entrada. A seleção segue a chave e não a posição:
// entre dois refrescamentos a lista pode reordenar-se, e o legado depois de
// um adopt desaparece (D-03) — com a posição, o detalhe passava a mostrar
// outra versão sem ninguém ter clicado em nada.
function mlmEntryKey(entry) {
  if (entry && entry.kind === "legacy") return "legacy";
  return (entry && entry.id) || "";
}

function mlmFindEntryIndex(report, key) {
  const versions = (report && report.versions) || [];
  if (!key) return -1;
  for (let i = 0; i < versions.length; i += 1) {
    if (mlmEntryKey(versions[i]) === key) return i;
  }
  return -1;
}

function mlmRowIndexFromEvent(event) {
  const alvo = event && event.target;
  const linha = alvo && typeof alvo.closest === "function"
    ? alvo.closest("tr[data-index]") : null;
  if (!linha || !linha.dataset) return -1;
  const indice = parseInt(linha.dataset.index, 10);
  return Number.isNaN(indice) ? -1 : indice;
}

function mlmIsSelectKey(event) {
  const key = event && event.key;
  // "Spacebar" é o nome antigo do Espaço em alguns browsers.
  return key === "Enter" || key === " " || key === "Spacebar";
}

// Delegado pelo keydown do tbody: Enter e Espaço selecionam a linha focada
// (sem deixar a página fazer scroll com o Espaço), o resto passa.
function mlmHandleRowKey(event, onSelect) {
  if (!mlmIsSelectKey(event)) return false;
  const indice = mlmRowIndexFromEvent(event);
  if (indice < 0) return false;
  event.preventDefault();
  onSelect(indice);
  return true;
}

function mlmLibraryVersionsText(libraryVersions) {
  if (!libraryVersions || typeof libraryVersions !== "object") return "desconhecido";
  const chaves = Object.keys(libraryVersions).sort();
  if (!chaves.length) return "desconhecido";
  return chaves
    .map((chave) => `${escapeHtml(chave)}=${escapeHtml(String(libraryVersions[chave]))}`)
    .join(", ");
}

function mlmArtifactsHtml(entry) {
  const meta = (entry && entry.metadata) || null;
  const registados = meta && meta.artifacts && typeof meta.artifacts === "object"
    ? meta.artifacts : null;
  const linhas = [];
  for (const nome of MLM_ARTIFACT_NAMES) {
    const artefacto = registados ? registados[nome] : null;
    if (artefacto) {
      const hash = typeof artefacto.sha256 === "string" && artefacto.sha256
        ? `<code>${escapeHtml(artefacto.sha256)}</code>`
        : "hash em falta no metadata.json";
      const tamanho = (artefacto.size_bytes === null || artefacto.size_bytes === undefined)
        ? "desconhecido" : `${mlmCell(artefacto.size_bytes)} bytes`;
      linhas.push(`<li><strong>${escapeHtml(nome)}</strong> — ${hash} — ${tamanho}</li>`);
      continue;
    }
    if (entry && entry.kind === "legacy") {
      const ficheiro = entry.files ? entry.files[nome] : null;
      if (!ficheiro) {
        linhas.push(`<li class="empty-state">${escapeHtml(nome)}: sem ficheiro registado.</li>`);
        continue;
      }
      const tamanho = (ficheiro.size_bytes === null || ficheiro.size_bytes === undefined)
        ? "desconhecido" : `${mlmCell(ficheiro.size_bytes)} bytes`;
      linhas.push(`<li><strong>${escapeHtml(nome)}</strong> — sem hash registado — ${tamanho}`
        + ` — ${mlmFormatDate(ficheiro.modified_at)}</li>`);
      continue;
    }
    return `<li class="empty-state">${escapeHtml(mlmErrorText(entry && entry.error_code))}</li>`;
  }
  return linhas.join("\n");
}

function mlmParamsHtml(parameters) {
  if (!parameters || typeof parameters !== "object") {
    return '<li class="empty-state">desconhecido</li>';
  }
  const chaves = Object.keys(parameters).sort();
  if (!chaves.length) return '<li class="empty-state">desconhecido</li>';
  return chaves
    .map((chave) => `<li>${escapeHtml(chave)} = ${escapeHtml(String(parameters[chave]))}</li>`)
    .join("\n");
}

function mlmDatasetHtml(dataset) {
  const d = dataset && typeof dataset === "object" ? dataset : {};
  const sintetico = (d.synthetic === null || d.synthetic === undefined)
    ? "desconhecido" : (d.synthetic ? "Sim" : "Não");
  return [
    `<li>Nome: ${mlmCell(d.name)}</li>`,
    `<li>Tamanho: ${mlmCell(d.size)}</li>`,
    `<li>Ataques: ${mlmCell(d.attacks)}</li>`,
    `<li>Sintético: ${sintetico}</li>`,
  ].join("\n");
}

// Devolve {title, metaHtml, artifactsHtml, paramsHtml, datasetHtml, evalText}.
// `title` e `evalText` são texto simples (vão por textContent); os *Html já
// vêm escapados.
function mlmBuildDetail(entry) {
  const meta = (entry && entry.metadata) || null;
  const criadoEm = meta ? mlmFormatDate(meta.created_at) : "desconhecido";
  const tipo = meta ? mlmCell(meta.model_type) : "desconhecido";
  const bibliotecas = mlmLibraryVersionsText(meta ? meta.library_versions : null);
  return {
    title: (entry && (entry.id || entry.label)) || "Versão",
    metaHtml: [
      `<span>Estado: <strong>${escapeHtml(mlmStatusText(entry))}</strong></span>`,
      `<span>Ativa: <strong>${entry && entry.active ? "Sim" : "Não"}</strong></span>`,
      `<span>Origem: <strong>${escapeHtml(mlmOriginText(entry))}</strong></span>`,
      `<span>Criado em: <strong>${criadoEm}</strong></span>`,
      `<span>Treinado em: <strong>${mlmTrainedAtText(entry)}</strong></span>`,
      `<span>Tipo de modelo: <strong>${tipo}</strong></span>`,
      `<span>Versões das bibliotecas: <strong>${bibliotecas}</strong></span>`,
    ].join("\n"),
    artifactsHtml: mlmArtifactsHtml(entry),
    paramsHtml: mlmParamsHtml(meta ? meta.parameters : null),
    datasetHtml: mlmDatasetHtml(meta ? meta.dataset : null),
    evalText: entry && entry.evaluation !== null && entry.evaluation !== undefined
      ? "Avaliação registada no metadata.json; a apresentação das métricas chega na Fase 2."
      : "Sem avaliação",
  };
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
let mlmLastReport = null;
let mlmSelectedKey = null;

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
  // A tabela acabou de ser redesenhada, o que apagou a linha marcada: volta
  // a marcá-la se a versão selecionada ainda existir.
  mlmReapplySelection();
}

// Todo o conteúdo do painel vem de mlmBuildDetail, que já escapou tudo. O
// title e o texto de avaliação são texto simples (textContent).
function mlmRenderDetail(entry) {
  const painel = document.getElementById("ml-models-detail-panel");
  if (!painel) return;
  const detalhe = mlmBuildDetail(entry);
  renderPanelError("#ml-models-detail-panel", "");
  painel.hidden = false;
  document.getElementById("mlm-detail-title").textContent = detalhe.title;
  document.getElementById("mlm-detail-meta").innerHTML = detalhe.metaHtml;
  document.getElementById("mlm-detail-artifacts").innerHTML = detalhe.artifactsHtml;
  document.getElementById("mlm-detail-params").innerHTML = detalhe.paramsHtml;
  document.getElementById("mlm-detail-dataset").innerHTML = detalhe.datasetHtml;
  document.getElementById("mlm-detail-eval").textContent = detalhe.evalText;
}

function mlmMarkSelectedRow(index) {
  const body = document.getElementById("mlm-models-body");
  if (!body) return;
  body.querySelectorAll("tr[data-index]").forEach((tr) => {
    tr.classList.toggle("selected", tr.dataset.index === String(index));
  });
}

function mlmHideDetail() {
  mlmSelectedKey = null;
  mlmMarkSelectedRow(-1);
  const painel = document.getElementById("ml-models-detail-panel");
  if (painel) painel.hidden = true;
}

// Não há novo pedido: os metadados já vieram com a lista.
function mlmSelectEntry(index) {
  const versions = (mlmLastReport && mlmLastReport.versions) || [];
  const entry = versions[index];
  if (!entry) {
    mlmHideDetail();
    return;
  }
  mlmSelectedKey = mlmEntryKey(entry);
  mlmMarkSelectedRow(index);
  mlmRenderDetail(entry);
}

// Depois de cada refrescamento a seleção é reposta a partir da CHAVE. Se a
// versão deixou de existir — o legado depois de um adopt (D-03) — o detalhe
// desaparece em vez de ficar a mostrar outra versão.
function mlmReapplySelection() {
  if (!mlmSelectedKey) return;
  const index = mlmFindEntryIndex(mlmLastReport, mlmSelectedKey);
  if (index < 0) {
    mlmHideDetail();
    return;
  }
  mlmMarkSelectedRow(index);
  mlmRenderDetail((mlmLastReport && mlmLastReport.versions)[index]);
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
    mlmLastReport = report;
    mlmRenderModels(report);
    mlmRenderEvaluation(report);
  } catch (err) {
    const texto = mlmErrorText(err.message);
    mlmLastReport = null;
    mlmHideDetail();
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
  // Linhas selecionáveis com rato e com teclado (Enter/Espaço), como na
  // Attack Library. O keydown delega em mlmHandleRowKey, que é puro.
  const corpo = document.getElementById("mlm-models-body");
  if (corpo) {
    corpo.addEventListener("click", (event) => {
      const index = mlmRowIndexFromEvent(event);
      if (index >= 0) mlmSelectEntry(index);
    });
    corpo.addEventListener("keydown", (event) => {
      mlmHandleRowKey(event, mlmSelectEntry);
    });
  }
  // Deep link #ml-models / #ml-evaluation: o applyHash de app.js corre antes
  // deste script.
  mlmOnTabChange();
}

if (typeof document !== "undefined") { mlmInit(); }