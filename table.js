// table.js — tabela partilhada (W7.2, E5). Script clássico, prefixo `tbl`.
// Depende de state.js (sttShowEmpty/sttShowError). O DOM é construído com
// textContent; uma célula só aceita HTML se o `render` devolver htmlRaw()/htmlT``
// (SafeHtml de html.js). NENHUM handler inline: um único listener delegado de
// click e de keydown por contentor, que vai buscar a linha pelo data-id.
//
// tblRender(el, {
//   columns: [{key, label, sortable?, sortValue?(row), render?(row), align?}],
//   rows: [...], empty?: string, error?: ApiError|string,
//   sortable?: boolean (default true; cada coluna pode pôr sortable:false),
//   rowId?(row) (default row.id), onSelect?(row, id),
//   total?: número (M de «a mostrar N de M»), limit?: número máx. de linhas,
//   sortKey?, sortDir?: "asc"|"desc" (ordenação inicial), caption?: string
// })

const TBL_STATE = new WeakMap();

function tblIsMissing(v) {
  return v === null || v === undefined || v === "" || (typeof v === "number" && !Number.isFinite(v));
}

// Comparação com «sem valor» sempre no fim, números por valor, resto por pt.
function tblCompare(a, b, dir) {
  const ma = tblIsMissing(a);
  const mb = tblIsMissing(b);
  if (ma || mb) return ma && mb ? 0 : ma ? 1 : -1; // vazios no fim em qualquer direção
  let c;
  if (typeof a === "number" && typeof b === "number") c = a - b;
  else c = String(a).localeCompare(String(b), "pt", { numeric: true, sensitivity: "base" });
  return dir === "desc" ? -c : c;
}

// Ordena sem mutar a entrada; estável (índice original como desempate).
function tblSortRows(rows, column, dir) {
  if (!column) return rows.slice();
  const get = typeof column.sortValue === "function" ? column.sortValue : (r) => r[column.key];
  return rows
    .map((row, i) => ({ row, i, v: get(row) }))
    .sort((x, y) => tblCompare(x.v, y.v, dir) || x.i - y.i)
    .map((x) => x.row);
}

// Texto «A mostrar N de M». M nunca é inventado: sem `total`, é o nº de linhas.
function tblCountText(shown, total) {
  return `A mostrar ${shown} de ${total}`;
}

function tblRowId(st, row, index) {
  const raw = typeof st.opts.rowId === "function" ? st.opts.rowId(row) : row && row.id;
  return tblIsMissing(raw) ? String(index) : String(raw);
}

function tblColumnSortable(st, col) {
  return st.opts.sortable !== false && col.sortable !== false;
}

function tblFillCell(td, col, row) {
  const v = typeof col.render === "function" ? col.render(row) : row[col.key];
  if (htmIsSafe(v)) htmRender(td, v);
  else td.textContent = tblIsMissing(v) ? "—" : String(v);
}

function tblBuild(el, st) {
  const opts = st.opts;
  const columns = opts.columns || [];
  const all = Array.isArray(opts.rows) ? opts.rows : [];
  const sortCol = columns.find((c) => c.key === st.sortKey);
  const sorted = tblSortRows(all, sortCol, st.sortDir);
  const limit = Number.isInteger(opts.limit) && opts.limit >= 0 ? opts.limit : sorted.length;
  const shownRows = sorted.slice(0, limit);
  const total = Number.isFinite(opts.total) ? opts.total : all.length;

  st.rowsById = new Map();
  const table = document.createElement("table");
  table.className = "data-table";
  if (opts.caption) {
    const cap = document.createElement("caption");
    cap.textContent = opts.caption;
    table.appendChild(cap);
  }

  const thead = document.createElement("thead");
  const hr = document.createElement("tr");
  for (const col of columns) {
    const th = document.createElement("th");
    th.setAttribute("scope", "col");
    th.textContent = col.label === undefined ? String(col.key) : String(col.label);
    if (col.align) th.className = "align-" + col.align;
    if (tblColumnSortable(st, col)) {
      th.setAttribute("data-sort-key", String(col.key));
      th.setAttribute("tabindex", "0");
      th.setAttribute("aria-sort",
        col.key === st.sortKey ? (st.sortDir === "desc" ? "descending" : "ascending") : "none");
    }
    hr.appendChild(th);
  }
  thead.appendChild(hr);

  const tbody = document.createElement("tbody");
  shownRows.forEach((row, i) => {
    const id = tblRowId(st, row, i);
    st.rowsById.set(id, row);
    const tr = document.createElement("tr");
    tr.setAttribute("data-id", id);
    if (typeof opts.onSelect === "function") {
      tr.setAttribute("tabindex", "0");
      tr.setAttribute("role", "button");
      if (id === st.selectedId) tr.setAttribute("aria-selected", "true");
    }
    for (const col of columns) {
      const td = document.createElement("td");
      if (col.align) td.className = "align-" + col.align;
      tblFillCell(td, col, row);
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  });

  table.appendChild(thead);
  table.appendChild(tbody);
  const count = document.createElement("p");
  count.className = "table-count";
  count.setAttribute("aria-live", "polite");
  count.textContent = tblCountText(shownRows.length, total);
  el.replaceChildren(table, count);
}

function tblToggleSort(el, st, key) {
  if (st.sortKey === key) st.sortDir = st.sortDir === "asc" ? "desc" : "asc";
  else { st.sortKey = key; st.sortDir = "asc"; }
  tblBuild(el, st);
}

function tblSelect(el, st, tr) {
  const id = tr.getAttribute("data-id");
  if (id === null || !st.rowsById.has(id) || typeof st.opts.onSelect !== "function") return;
  st.selectedId = id;
  for (const other of el.querySelectorAll("tr[data-id]")) {
    if (other.getAttribute("data-id") === id) other.setAttribute("aria-selected", "true");
    else other.removeAttribute("aria-selected");
  }
  st.opts.onSelect(st.rowsById.get(id), id);
}

// Resolve o alvo de um evento (cabeçalho ordenável ou linha) e atua.
function tblHandle(el, st, target) {
  if (!target || typeof target.closest !== "function") return false;
  const th = target.closest("th[data-sort-key]");
  if (th && el.contains(th)) { tblToggleSort(el, st, th.getAttribute("data-sort-key")); return true; }
  const tr = target.closest("tr[data-id]");
  if (tr && el.contains(tr)) { tblSelect(el, st, tr); return true; }
  return false;
}

function tblBind(el, st) {
  if (st.bound) return;
  st.bound = true;
  el.addEventListener("click", (ev) => { tblHandle(el, st, ev.target); });
  el.addEventListener("keydown", (ev) => {
    if (ev.key !== "Enter" && ev.key !== " " && ev.key !== "Spacebar") return;
    if (tblHandle(el, st, ev.target) && typeof ev.preventDefault === "function") ev.preventDefault();
  });
}

function tblRender(el, opts) {
  if (!el) return null;
  const o = opts || {};
  let st = TBL_STATE.get(el);
  if (!st) { st = { bound: false, selectedId: null, rowsById: new Map() }; TBL_STATE.set(el, st); }
  st.opts = o;
  // Ordenação do utilizador sobrevive a novos dados; a inicial só vale à primeira.
  if (st.sortKey === undefined) {
    st.sortKey = o.sortKey || null;
    st.sortDir = o.sortDir === "desc" ? "desc" : "asc";
  }
  tblBind(el, st);

  if (o.error !== undefined && o.error !== null && o.error !== false) {
    st.rowsById = new Map();
    sttShowError(el, o.error);
    return el;
  }
  if (!Array.isArray(o.rows) || o.rows.length === 0) {
    st.rowsById = new Map();
    sttShowEmpty(el, o.empty);
    return el;
  }
  tblBuild(el, st);
  return el;
}
