// Aba "📦 Models" (marco R9, registo de modelos; R10: treinar a partir do dashboard).
// Carregado depois de app.js e metrics.js: reutiliza os seus globais (API_BASE,
// API_KEY, htmlT/htmRender de html.js, renderPanelError) — não redeclarar nenhum aqui.
//
// A aba "📐 Evaluation" NÃO vive aqui desde a Fase 2: saiu para
// ml_evaluation.js, com o seu próprio prefixo `mle` e o seu próprio ciclo de
// dados (D-09). Os dois ficheiros partilham um só escopo global, por isso o
// teste node:vm carrega ambos no mesmo contexto — uma colisão entre eles seria
// um teste vermelho, não um bug em produção.
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

// Códigos de transporte (api.js): o texto fixo em PT vem de apiErrorMessage,
// nunca da exceção original.
const MLM_TRANSPORT_CODES = ["network_error", "timeout", "invalid_response", "http_404", "http_502", "http_503", "http_504"];

function mlmErrorText(code) {
  if (typeof code !== "string") return MLM_GENERIC_ERROR;
  if (Object.prototype.hasOwnProperty.call(MLM_ERROR_TEXT, code)) return MLM_ERROR_TEXT[code];
  if (MLM_TRANSPORT_CODES.indexOf(code) >= 0 && typeof ApiError === "function"
      && typeof apiErrorMessage === "function") {
    return apiErrorMessage(new ApiError(code, 0));
  }
  return MLM_GENERIC_ERROR;
}

// Converte o ApiError de api.js no código que o resto do ficheiro já usa
// (mesma chave de lookup que mlmCodeFromResponse): 403/422 sem slug ficam
// http_403/http_422; transporte e slugs passam tal e qual.
function mlmCodeFromApiError(err) {
  if (!err || err.name !== "ApiError") return "unexpected_error";
  if (err.code === "validation_error" || (err.code === "forbidden" && err.status)) {
    return "http_" + (err.status || 422);
  }
  return err.code;
}

function mlmCodeFromResponse(status, body) {
  if (status === 401) return "unauthorized";
  const detail = body ? body.detail : null;
  if (typeof detail === "string" && MLM_CODE_RE.test(detail)) return detail;
  return "http_" + status;
}

// ======================= treino (R10) — camada pura ===========================
//
// O corpo do pedido de treino: DUAS chaves e nada mais. Os parâmetros do
// modelo (contamination/random_state/n_estimators) são omissões do servidor —
// os tetos são uma protecção do backend (D-01.3), não um campo do formulário.
const MLM_TRAIN_DATASETS = ["latest_export", "sample_fixture"];
const MLM_TRAIN_ORIGINS = ["real", "synthetic", "unknown"];
const MLM_TRAIN_DATASET_OMISSAO = "latest_export";
const MLM_TRAIN_ORIGEM_OMISSAO = "unknown";

function mlmTrainBody(dataset, dataset_origin) {
  const dsFinal = MLM_TRAIN_DATASETS.includes(dataset) ? dataset : MLM_TRAIN_DATASET_OMISSAO;
  // O gerador sintético nunca pode ser declarado como dados reais.
  const origem = dsFinal === "sample_fixture"
    ? "synthetic"
    : (MLM_TRAIN_ORIGINS.includes(dataset_origin) ? dataset_origin : MLM_TRAIN_ORIGEM_OMISSAO);
  return { dataset: dsFinal, dataset_origin: origem };
}

// O estado do botão vive aqui para ser testável sem DOM: nenhum sítio
// escreve "A treinar…" por sua conta.
const MLM_TREINAR_LABEL = "Treinar";
const MLM_TREINANDO_LABEL = "A treinar…";

function mlmTrainButtonState(ocupado) {
  return ocupado
    ? { text: MLM_TREINANDO_LABEL, disabled: true }
    : { text: MLM_TREINAR_LABEL, disabled: false };
}

// Devolve {estado, texto} com estado em "ok" | "reiniciar" | "nao_ativa" | "incompleto".
// "reiniciar" é o caso que decide a UX de todo o R10: a vN foi criada e
// está ativa, mas a cache do modelo é por processo e o backend continua a
// medir com a anterior (D-01 invertida; ver CLAUDE.md, "a cache é por processo").
function mlmTrainResult(resposta) {
  if (!resposta || typeof resposta !== "object") {
    return { estado: "incompleto", texto: "O servidor respondeu sem dizer que versão foi criada — não há forma de dizer o que foi treinado. Vê o backend.log." };
  }
  const version = typeof resposta.version === "string" ? resposta.version : "desconhecida";
  const active = typeof resposta.active === "string" ? resposta.active : null;
  const loaded = typeof resposta.loaded === "string" ? resposta.loaded : null;

  if (!active) {
    return { estado: "incompleto", texto: "O servidor respondeu sem dizer que versão foi criada — não há forma de dizer o que foi treinado. Vê o backend.log." };
  }

  if (loaded && active && loaded !== active) {
    return {
      estado: "reiniciar",
      texto: `«${version}» foi criada e está ativa, mas o backend continua a usar «${loaded}»: as deteções ainda são da «${loaded}» até reiniciar o backend (scripts/start-backend.ps1).`
    };
  }
  if (active && loaded && loaded === active) {
    return {
      estado: "ok",
      texto: `«${version}» foi criada, está ativa e é a versão que o backend está a usar.`
    };
  }
  if (active && (!loaded || loaded !== active)) {
    return {
      estado: "nao_ativa",
      texto: `«${version}» foi criada e registada, mas a versão ativa continua a ser «${active}»: o treino não passa a ativar a versão nova.`
    };
  }
  return { estado: "incompleto", texto: "O servidor respondeu sem dizer que versão foi criada — não há forma de dizer o que foi treinado. Vê o backend.log." };
}

// Mensagens de erro do treino. Nem `training_in_progress` nem nenhum código novo
// entra em `MLM_ERROR_TEXT`: essa tabela é do registo (mlmStatusText usa-a para
// `entry.error_code`), e o treino é uma operação diferente com códigos diferentes.
const MLM_TRAIN_GENERIC_ERROR = "O treino não foi concluído. Olha o backend.log.";
const MLM_TRAIN_ERROR_TEXT = {
  training_in_progress: "Já há um treino a correr — o servidor só aceita um de cada vez (D-01.2). Espera que o primeiro termine e volta a carregar em «Treinar».",
  dataset_unavailable: "O conjunto de dados pedido não está disponível no servidor: o export do Indexer falhou ou não há eventos na janela. Confirma que o Wazuh Indexer está ligado e olha o backend.log.",
  training_failed: "O treino falhou a meio e nenhuma versão nova ficou registada. O motivo está no backend.log.",
  models_dir_unavailable: "Não foi possível escrever em scripts/models/ (permissões ou disco cheio). Corrige as permissões e olha o backend.log.",
};
const MLM_TRAIN_HTTP_TEXT = {
  http_400: "O pedido de treino foi recusado pelo servidor. Volta a carregar em «Treinar» sem alterar os campos.",
  http_404: "A rota de treino não foi encontrada no backend. Verifica se o backend do R10 está a correr.",
  http_409: "Já há um treino a correr — o servidor só aceita um de cada vez (D-01.2). Espera que o primeiro termine e volta a carregar em «Treinar».",
  http_422: "O servidor recusou o pedido — um dos parâmetros está fora dos valores aceites. Volta a carregar em «Treinar» sem alterar os campos.",
  http_500: "O backend deu um erro interno a treinar. Olha o backend.log.",
  http_503: "O registo de modelos recusou a operação (ACTIVE inválido, hash em falta ou metadata.json corrompido). Vê a aba 📦 Models e o backend.log.",
};

// Os códigos do registo continuam traduzidos pela tabela que já existe —
// nenhuma segunda cópia de "unauthorized" ou "registry_unavailable".
function mlmTrainErrorText(codigo) {
  if (typeof codigo !== "string") return MLM_TRAIN_GENERIC_ERROR;
  if (Object.prototype.hasOwnProperty.call(MLM_TRAIN_ERROR_TEXT, codigo)) return MLM_TRAIN_ERROR_TEXT[codigo];
  if (Object.prototype.hasOwnProperty.call(MLM_TRAIN_HTTP_TEXT, codigo)) return MLM_TRAIN_HTTP_TEXT[codigo];
  const doRegisto = mlmErrorText(codigo);
  return doRegisto === MLM_GENERIC_ERROR ? MLM_TRAIN_GENERIC_ERROR : doRegisto;
}

function mlmCell(value) {
  if (value === null || value === undefined || value === "") return "desconhecido";
  return String(value);
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
  if (Number.isNaN(data.getTime())) return String(iso);
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
  const texto = mlmOriginText(entry);
  if (entry && entry.kind === "legacy") {
    return htmlT`<span class="mlm-badge mlm-badge-legacy">${texto}</span>`;
  }
  if (meta && meta.adopted === true) {
    return htmlT`<span class="mlm-badge mlm-badge-adopted">${texto}</span>`;
  }
  return htmlT`${texto}`;
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
    return htmlT`<tr><td colspan="5" class="empty-state">Sem dados — ainda não há modelos registados.</td></tr>`;
  }
  return htmlT`${versions.map((entry, indice) => {
    const ativa = entry.active ? htmlT`<span class="mlm-badge mlm-badge-active">ativa</span> ` : "";
    const estadoTexto = mlmStatusText(entry);
    // O badge de erro só entra quando há mesmo um erro. O legado tem
    // status "no_metadata" e error_code null porque o modelo está a ser
    // usado à vontade: pintá-lo de vermelho (e com a mensagem genérica, já
    // que não há código) diria ao analista que o modelo avariou.
    const estado = (entry.status === "ok" || entry.status === "no_metadata")
      ? htmlT`${estadoTexto}`
      : htmlT`<span class="mlm-badge mlm-badge-error">${estadoTexto}</span>`;
    const versao = entry.kind === "legacy"
      ? htmlT`<span class="mlm-badge mlm-badge-legacy">${entry.label || "legado, sem metadados"}</span>`
      : htmlT`${entry.id || entry.label || ""}`;
    const avaliacao = entry.evaluation === null || entry.evaluation === undefined
      ? "Sem avaliação"
      : "Registada";
    return htmlT`<tr class="atk-row" data-index="${indice}" tabindex="0">
      <td>${versao}</td>
      <td>${ativa}${estado}</td>
      <td>${mlmOriginHtml(entry)}</td>
      <td>${mlmTrainedAtText(entry)}</td>
      <td>${avaliacao}</td>
    </tr>`;
  })}`;
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
    .map((chave) => `${chave}=${String(libraryVersions[chave])}`)
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
        ? htmlT`<code>${artefacto.sha256}</code>`
        : "hash em falta no metadata.json";
      const tamanho = (artefacto.size_bytes === null || artefacto.size_bytes === undefined)
        ? "desconhecido" : `${mlmCell(artefacto.size_bytes)} bytes`;
      linhas.push(htmlT`<li><strong>${nome}</strong> — ${hash} — ${tamanho}</li>`);
      continue;
    }
    if (entry && entry.kind === "legacy") {
      const ficheiro = entry.files ? entry.files[nome] : null;
      if (!ficheiro) {
        linhas.push(htmlT`<li class="empty-state">${nome}: sem ficheiro registado.</li>`);
        continue;
      }
      const tamanho = (ficheiro.size_bytes === null || ficheiro.size_bytes === undefined)
        ? "desconhecido" : `${mlmCell(ficheiro.size_bytes)} bytes`;
      linhas.push(htmlT`<li><strong>${nome}</strong> — sem hash registado — ${tamanho} — ${mlmFormatDate(ficheiro.modified_at)}</li>`);
      continue;
    }
    return htmlT`<li class="empty-state">${mlmErrorText(entry && entry.error_code)}</li>`;
  }
  return htmlT`${linhas.map((l, i) => htmlT`${i ? "\n" : ""}${l}`)}`;
}

function mlmParamsHtml(parameters) {
  if (!parameters || typeof parameters !== "object") {
    return htmlT`<li class="empty-state">desconhecido</li>`;
  }
  const chaves = Object.keys(parameters).sort();
  if (!chaves.length) return htmlT`<li class="empty-state">desconhecido</li>`;
  return htmlT`${chaves.map((chave, i) =>
    htmlT`${i ? "\n" : ""}<li>${chave} = ${String(parameters[chave])}</li>`)}`;
}

function mlmDatasetHtml(dataset) {
  const d = dataset && typeof dataset === "object" ? dataset : {};
  const sintetico = (d.synthetic === null || d.synthetic === undefined)
    ? "desconhecido" : (d.synthetic ? "Sim" : "Não");
  return htmlT`<li>Nome: ${mlmCell(d.name)}</li>
<li>Tamanho: ${mlmCell(d.size)}</li>
<li>Ataques: ${mlmCell(d.attacks)}</li>
<li>Sintético: ${sintetico}</li>`;
}

// Devolve {title, metaHtml, artifactsHtml, paramsHtml, datasetHtml, evalText}.
// `title` e `evalText` são texto simples (vão por textContent); os *Html são
// SafeHtml (htmlT), escapados na interpolação.
function mlmBuildDetail(entry) {
  const meta = (entry && entry.metadata) || null;
  const criadoEm = meta ? mlmFormatDate(meta.created_at) : "desconhecido";
  const tipo = meta ? mlmCell(meta.model_type) : "desconhecido";
  const bibliotecas = mlmLibraryVersionsText(meta ? meta.library_versions : null);
  return {
    title: (entry && (entry.id || entry.label)) || "Versão",
    metaHtml: htmlT`<span>Estado: <strong>${mlmStatusText(entry)}</strong></span>
<span>Ativa: <strong>${entry && entry.active ? "Sim" : "Não"}</strong></span>
<span>Origem: <strong>${mlmOriginText(entry)}</strong></span>
<span>Criado em: <strong>${criadoEm}</strong></span>
<span>Treinado em: <strong>${mlmTrainedAtText(entry)}</strong></span>
<span>Tipo de modelo: <strong>${tipo}</strong></span>
<span>Versões das bibliotecas: <strong>${bibliotecas}</strong></span>`,
    artifactsHtml: mlmArtifactsHtml(entry),
    paramsHtml: mlmParamsHtml(meta ? meta.parameters : null),
    datasetHtml: mlmDatasetHtml(meta ? meta.dataset : null),
    evalText: entry && entry.evaluation !== null && entry.evaluation !== undefined
      ? "Avaliação registada no metadata.json desta versão — as métricas estão na aba 📐 Evaluation."
      : "Sem avaliação",
  };
}

// ======================= camada DOM (só via mlmInit) ========================

let mlmModelsTab = null;
let mlmModelsWasShown = false;
let mlmLoading = false;
let mlmLastReport = null;
let mlmSelectedKey = null;
let mlmTraining = false;

// Único ponto de rede deste ficheiro (e de ml_evaluation.js): apiRequest faz o
// fetch, a chave e o timeout; aqui só se traduz o erro para o código de lookup.
async function mlmApiCall(path, options) {
  try {
    return await apiRequest(path, options);
  } catch (err) {
    throw new Error(mlmCodeFromApiError(err));
  }
}

async function mlmRequest(path) {
  return mlmApiCall(path);
}

// POST com o mesmo tratamento de erro de mlmRequest — o `detail` entra como CHAVE
// de lookup em mlmCodeFromResponse e o código nunca chega ao DOM (API-02).
// O treino demora: timeout próprio mais largo que os 15 s dos GET.
async function mlmPost(path, body) {
  return mlmApiCall(path, { method: "POST", body: body || {}, timeoutMs: 120000 });
}

// Estado (a carregar/erro/vazio) dentro de uma célula que ocupa a tabela toda;
// o <p> do state.js fica dentro do <td>, que é HTML válido num <tbody>.
function mlmShowTableState(tbody, colunas, tipo, conteudo) {
  if (!tbody) return;
  const tr = document.createElement("tr");
  const td = document.createElement("td");
  td.colSpan = colunas;
  tr.appendChild(td);
  tbody.replaceChildren(tr);
  if (tipo === "loading") sttShowLoading(td, conteudo);
  else if (tipo === "error") sttShowError(td, conteudo);
  else sttShowEmpty(td, conteudo);
}

function mlmSetTrainButton(ocupado) {
  const botao = document.getElementById("mlm-train-button");
  if (!botao) return;
  const estado = mlmTrainButtonState(ocupado);
  botao.disabled = estado.disabled;
  botao.textContent = estado.text;
}

function mlmRenderTrainResult(estado, texto, mensagem) {
  const alvo = document.getElementById("mlm-train-result");
  if (!alvo) return;
  alvo.className = "panel-note " + (estado === "erro" ? "mlm-train-erro" : "mlm-train-reiniciar");
  alvo.textContent = texto;   // texto simples: textContent já é seguro, não escapar antes
}

async function mlmDoTrain() {
  if (mlmTraining) return;                 // clique duplo não vira dois POST
  mlmTraining = true;
  mlmSetTrainButton(true);
  try {
    const resposta = await mlmPost("/api/ml/train", mlmTrainBody(mlmTrainDataset(), mlmTrainOrigin()));
    const resultado = mlmTrainResult(resposta);
    mlmRenderTrainResult(resultado.estado === "incompleto" ? "erro" : resultado.estado,
                        resultado.texto, "");
  } catch (err) {
    mlmRenderTrainResult("erro", "Não foi possível treinar: " + mlmTrainErrorText(err.message), "");
  } finally {
    mlmTraining = false;
    mlmSetTrainButton(false);
  }
  // UM ÚNICO refrescamento, no fim, qualquer que seja o desfecho (D-07):
  // a tabela tem de mostrar a vN nova — ou, se o treino falhou, tem de
  // continuar a mostrar o registo como estava, com o erro em cima.
  await mlmRefresh(true);
}

function mlmTrainDataset() {
  const select = document.getElementById("mlm-train-dataset");
  return select ? select.value : MLM_TRAIN_DATASET_OMISSAO;
}

function mlmTrainOrigin() {
  const select = document.getElementById("mlm-train-origin");
  return select ? select.value : MLM_TRAIN_ORIGEM_OMISSAO;
}

function mlmRenderModels(report) {
  htmRender(document.getElementById("mlm-models-body"), mlmBuildModelsRows(report));
  document.getElementById("mlm-models-notice").textContent = mlmModelsNoticeText(report);
  // A tabela acabou de ser redesenhada, o que apagou a linha marcada: volta
  // a marcá-la se a versão selecionada ainda existir.
  mlmReapplySelection();
}

// Todo o conteúdo do painel vem de mlmBuildDetail (htmlT, escapado). O
// title e o texto de avaliação são texto simples (textContent).
function mlmRenderDetail(entry) {
  const painel = document.getElementById("ml-models-detail-panel");
  if (!painel) return;
  const detalhe = mlmBuildDetail(entry);
  renderPanelError("#ml-models-detail-panel", "");
  painel.hidden = false;
  document.getElementById("mlm-detail-title").textContent = detalhe.title;
  htmRender(document.getElementById("mlm-detail-meta"), detalhe.metaHtml);
  htmRender(document.getElementById("mlm-detail-artifacts"), detalhe.artifactsHtml);
  htmRender(document.getElementById("mlm-detail-params"), detalhe.paramsHtml);
  htmRender(document.getElementById("mlm-detail-dataset"), detalhe.datasetHtml);
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

function mlmIsShown(tab) {
  return tab.classList.contains("active") && document.visibilityState === "visible";
}

// Um só pedido alimenta a aba Models. A Evaluation tem o seu próprio pedido,
// em ml_evaluation.js (D-09).
async function mlmRefresh(forcar) {
  if (mlmLoading && forcar !== true) return;
  mlmLoading = true;
  if (!mlmLastReport) mlmShowTableState(document.getElementById("mlm-models-body"), 5, "loading", "A carregar os modelos…");
  try {
    const report = await mlmRequest("/api/ml/models");
    renderPanelError("#ml-models-panel", "");
    mlmLastReport = report;
    mlmRenderModels(report);
  } catch (err) {
    const texto = mlmErrorText(err.message);
    mlmLastReport = null;
    mlmHideDetail();
    renderPanelError("#ml-models-panel", "Não foi possível carregar os modelos: " + texto);
    mlmShowTableState(document.getElementById("mlm-models-body"), 5, "error", texto);
  } finally {
    mlmLoading = false;
  }
}

// Ao contrário da Attack Library (que carrega uma vez), aqui recarregamos
// SEMPRE que a aba passa de escondida a visível: um adopt pode ter
// corrido entretanto e o backend só passa a usar a versão nova depois de
// reiniciado.
function mlmOnTabChange() {
  const shown = mlmModelsTab ? mlmIsShown(mlmModelsTab) : false;
  if (shown && !mlmModelsWasShown) mlmRefresh();
  mlmModelsWasShown = shown;
}

// Dataset sintético => origem fixa em "synthetic" e select desativado;
// com export recente o utilizador volta a poder declarar a origem.
function mlmSyncTrainOrigin() {
  const dsSelect = document.getElementById("mlm-train-dataset");
  const origem = document.getElementById("mlm-train-origin");
  if (!dsSelect || !origem) return;
  if (dsSelect.value === "sample_fixture") {
    origem.value = "synthetic";
    origem.disabled = true;
  } else {
    origem.disabled = false;
  }
}

function mlmInit() {
  mlmModelsTab = document.getElementById("tab-ml-models");
  if (mlmModelsTab) {
    const observer = new MutationObserver(mlmOnTabChange);
    observer.observe(mlmModelsTab, { attributes: true, attributeFilter: ["class"] });
  }
  document.addEventListener("visibilitychange", mlmOnTabChange);
  document.getElementById("mlm-models-reload").addEventListener("click", () => mlmRefresh());
  const treinar = document.getElementById("mlm-train-button");
  if (treinar) treinar.addEventListener("click", () => mlmDoTrain());
  const dsSelect = document.getElementById("mlm-train-dataset");
  if (dsSelect) {
    dsSelect.addEventListener("change", mlmSyncTrainOrigin);
    mlmSyncTrainOrigin();
  }
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