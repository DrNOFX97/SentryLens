"use strict";
// router.js (W3.1) — ciclo de vida das abas: só carrega e faz polling quando a
// aba está ativa E o separador do browser está visível. Script clássico,
// prefixo `rt`, sem DOM no topo (testável em node:vm com timers falsos).
//
// API pública:
//   rtCreateRouter({ doc, now, setIntervalFn, clearIntervalFn, onError })
//     -> { registerTab, activate, deactivate, getActiveId, isRunning,
//          handleVisibilityChange }
//   rtRegisterTab({ id, load, refreshMs, onHide })   (router por omissão)
//   rtActivate(id) / rtDeactivate()                  (router por omissão)
//   rtRouter                                          (router por omissão)
//
// Regras:
//   - activate(id): esconde a aba anterior (onHide), e se o documento estiver
//     visível corre load() já e arranca o intervalo refreshMs.
//   - Documento escondido: nenhum load, nenhum intervalo (0 pedidos).
//   - Voltar a ficar visível: refresh imediato só se passaram >= refreshMs
//     desde o último load (ou nunca carregou); depois retoma o intervalo.
//   - Ao esconder (aba trocada ou documento escondido) o intervalo pára e
//     onHide() é chamado uma vez por transição.
//   - Um load ainda pendente (Promise) não é sobreposto por outro.

function rtCreateRouter(opts) {
  const o = opts || {};
  const doc = o.doc || (typeof document !== "undefined" ? document : null);
  const nowFn = o.now || (() => Date.now());
  const setIv = o.setIntervalFn || ((fn, ms) => setInterval(fn, ms));
  const clearIv = o.clearIntervalFn || ((id) => clearInterval(id));
  const onError = o.onError || ((err) => {
    if (typeof console !== "undefined") console.error("router: load falhou", err);
  });

  const tabs = new Map();
  let activeId = null;

  function visible() {
    return !doc || doc.visibilityState === "visible";
  }

  function stopTimer(tab) {
    if (tab.timer !== null) {
      clearIv(tab.timer);
      tab.timer = null;
    }
  }

  function runLoad(tab) {
    if (tab.inFlight) return;
    tab.lastLoadAt = nowFn();
    let result;
    try {
      result = tab.load();
    } catch (err) {
      onError(err);
      return;
    }
    if (result && typeof result.then === "function") {
      tab.inFlight = true;
      const done = () => { tab.inFlight = false; };
      result.then(done, (err) => { done(); onError(err); });
    }
  }

  function startTimer(tab) {
    if (tab.timer !== null || !(tab.refreshMs > 0)) return;
    tab.timer = setIv(() => {
      // Guarda redundante: nunca corre fora de aba ativa + visível.
      if (activeId === tab.id && visible()) runLoad(tab);
    }, tab.refreshMs);
  }

  function hide(tab) {
    stopTimer(tab);
    if (tab.shown) {
      tab.shown = false;
      if (tab.onHide) {
        try { tab.onHide(); } catch (err) { onError(err); }
      }
    }
  }

  // Põe a aba ativa a correr (se visível). `force` = load incondicional.
  function show(tab, force) {
    if (!visible()) return;
    const stale = tab.lastLoadAt === null ||
      !(tab.refreshMs > 0) ||
      nowFn() - tab.lastLoadAt >= tab.refreshMs;
    tab.shown = true;
    if (force || stale) runLoad(tab);
    startTimer(tab);
  }

  function registerTab(spec) {
    if (!spec || typeof spec.id !== "string" || !spec.id) {
      throw new Error("registerTab: id obrigatório");
    }
    if (typeof spec.load !== "function") {
      throw new Error("registerTab: load tem de ser função");
    }
    if (tabs.has(spec.id)) {
      throw new Error("registerTab: id repetido: " + spec.id);
    }
    const tab = {
      id: spec.id,
      load: spec.load,
      refreshMs: Number(spec.refreshMs) > 0 ? Number(spec.refreshMs) : 0,
      onHide: typeof spec.onHide === "function" ? spec.onHide : null,
      timer: null,
      lastLoadAt: null,
      inFlight: false,
      shown: false,
    };
    tabs.set(tab.id, tab);
    return {
      id: tab.id,
      refresh: () => { if (activeId === tab.id && visible()) runLoad(tab); },
    };
  }

  function activate(id) {
    const next = tabs.get(id) || null;
    if (activeId !== null && activeId !== id) {
      const prev = tabs.get(activeId);
      if (prev) hide(prev);
    }
    activeId = next ? id : null;
    // Ativação explícita carrega sempre (a aba acabou de ser aberta).
    if (next) show(next, true);
  }

  function deactivate() {
    if (activeId === null) return;
    const prev = tabs.get(activeId);
    activeId = null;
    if (prev) hide(prev);
  }

  function handleVisibilityChange() {
    const tab = activeId !== null ? tabs.get(activeId) : null;
    if (!tab) return;
    if (visible()) show(tab, false);
    else hide(tab);
  }

  if (doc && typeof doc.addEventListener === "function") {
    doc.addEventListener("visibilitychange", handleVisibilityChange);
  }

  return {
    registerTab,
    activate,
    deactivate,
    handleVisibilityChange,
    getActiveId: () => activeId,
    isRunning: (id) => { const t = tabs.get(id); return !!t && t.timer !== null; },
  };
}

const rtRouter = rtCreateRouter();
function rtRegisterTab(spec) { return rtRouter.registerTab(spec); }
function rtActivate(id) { rtRouter.activate(id); }
function rtDeactivate() { rtRouter.deactivate(); }
