// kpi.js — cartão de KPI partilhado (W7.3, E6). Script clássico, prefixo `kpi`.
// Constrói o DOM com textContent (nunca innerHTML). Sem valor é «—» neutro:
// sem classe de nível, nunca 0. Usa a classe .card já existente em style.css
// (h3 = etiqueta, .value = valor), com .critical/.high/.medium/.low.

const KPI_LEVELS = ["critical", "high", "medium", "low"];

function kpiHasValue(v) {
  if (typeof v === "number") return Number.isFinite(v);
  return typeof v === "string" && v.trim() !== "";
}

// Modelo puro: {label, value, sub, cls, empty}. `value` é texto já formatado
// (ex.: fmtPct(...)) ou número (formatado por fmtNumber, se existir). `unit`
// só se junta quando há valor. `level` fora de KPI_LEVELS é ignorado e, sem
// valor, o nível é sempre ignorado (um «—» nunca fica vermelho nem verde).
function kpiModel(opts) {
  const o = opts || {};
  const empty = !kpiHasValue(o.value);
  let value = "—";
  if (!empty) {
    value = typeof o.value === "number" && typeof fmtNumber === "function"
      ? fmtNumber(o.value, { decimals: Number.isInteger(o.value) ? 0 : 1 })
      : String(o.value);
    if (typeof o.unit === "string" && o.unit) value += " " + o.unit;
  }
  const level = !empty && KPI_LEVELS.includes(o.level) ? o.level : "";
  return {
    label: o.label === null || o.label === undefined ? "" : String(o.label),
    value,
    sub: o.sub === null || o.sub === undefined ? "" : String(o.sub),
    cls: "card" + (level ? " " + level : "") + (empty ? " kpi-empty" : ""),
    empty,
  };
}

// Renderiza o cartão dentro de `el` (el passa a ser o próprio .card).
function kpiRender(el, opts) {
  if (!el) return null;
  const m = kpiModel(opts);
  const h = document.createElement("h3");
  h.textContent = m.label;
  const v = document.createElement("div");
  v.className = "value";
  v.textContent = m.value;
  const kids = [h, v];
  if (m.sub) {
    const s = document.createElement("small");
    s.className = "kpi-sub";
    s.textContent = m.sub;
    kids.push(s);
  }
  el.className = m.cls;
  el.replaceChildren(...kids);
  return el;
}
