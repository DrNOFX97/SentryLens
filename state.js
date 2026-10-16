// state.js — estados de painel partilhados (W2.2): a carregar, vazio, erro.
// Script clássico, prefixo `stt`. Constrói o DOM com textContent (nunca
// innerHTML), por isso o texto recebido nunca é interpretado como HTML.
// Sem dados é «—» / «Sem dados», nunca 0.

function sttBuild(el, className, text, role) {
  if (!el) return null;
  const p = document.createElement("p");
  p.className = className;
  if (role) p.setAttribute("role", role);
  p.textContent = text;
  el.replaceChildren(p);
  return p;
}

function sttShowLoading(el, text) {
  const p = sttBuild(el, "loading-state", text || "A carregar…", "status");
  if (p) p.setAttribute("aria-live", "polite");
  return p;
}

function sttShowEmpty(el, text) {
  return sttBuild(el, "empty-state", text || "Sem dados");
}

// err: ApiError (usa a mensagem fixa), string (mostrada como texto) ou outro
// valor (mensagem genérica). role="alert" para os leitores de ecrã.
function sttShowError(el, err) {
  let text;
  if (typeof err === "string" && err) text = err;
  else if (typeof apiErrorMessage === "function") text = apiErrorMessage(err);
  else text = "Erro inesperado — tenta de novo.";
  return sttBuild(el, "error-state", text, "alert");
}
